// appidd: App Identification for SJB-OS (step 1: visibility).
//
// nftables queues the first packets of each TCP/UDP connection to NFQUEUE
// (queue numbers 0..QUEUES-1, with bypass, so traffic flows when appidd is
// down). appidd runs nDPI on them and, once nDPI is done (or after
// MAX_PKTS packets), writes the application into the connection's conntrack
// mark in the verdict itself:
//
//   bits  0-11  application (nDPI protocol ID; 0 = unknown)
//   bit     12  classification done: nftables stops queueing the flow
//   bits 16-31  rule ID + 1, set by the ruleset on logged allow rules
//
// The verdict carries CTA_MARK with CTA_MARK_MASK, so only bits 0-10 and 12
// change (bit 11, the session-log flag, belongs to the ruleset)
// (the kernel computes new = (old & ~CTA_MARK_MASK) ^ CTA_MARK).
// Every packet is accepted: appidd never drops traffic.
//
// It also listens for conntrack DESTROY events to count bytes per
// application and per source host (written to STATS_PATH every 10 s) and
// to log the end of
// each connection a logged rule allowed, one journal line each:
//   ngfw-session rule=N app=NAME cat=CATEGORY proto=tcp src=.. sport=..
//     dst=.. dport=.. bytes=.. packets=.. dur=SECONDS
//
// `appidd --catalog` prints nDPI's application list as JSON.
//
// Single-threaded: one poll loop over the two netlink sockets.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <ndpi/ndpi_api.h>

#define QUEUES 2
#define MAX_PKTS 32           // give up after this many packets
#define MAX_FLOWS 65536       // flow table cap
#define IDLE_SECS 120         // flows unseen this long are dropped
#define APP_MASK 0x07ffu
#define SESSION_BIT 0x0800u // the rule asked for a session-end log line
#define DONE_BIT 0x1000u
#define RULE_SHIFT 16
#define STATS_PATH "/run/appidd/stats.json"
#define NBUCKETS 16384

static struct ndpi_detection_module_struct *ndpi;
static int debug; // APPIDD_DEBUG=1: one line per inspected packet
static volatile sig_atomic_t stop;

// ---- flow table (conntrack ID -> nDPI state) -------------------------------

struct flow {
	uint32_t ctid;
	struct ndpi_flow_struct *nf;
	uint16_t pkts;
	uint16_t app; // app ID last written to the ct mark (provisional)
	time_t last;
	struct flow *next;
};

static struct flow *buckets[NBUCKETS];
static unsigned nflows;

static struct flow **slot(uint32_t ctid)
{
	struct flow **p = &buckets[ctid % NBUCKETS];
	while (*p && (*p)->ctid != ctid)
		p = &(*p)->next;
	return p;
}

static void flow_free(struct flow *f)
{
	ndpi_free_flow(f->nf);
	free(f);
	nflows--;
}

static void flow_drop(uint32_t ctid)
{
	struct flow **p = slot(ctid);
	if (*p) {
		struct flow *f = *p;
		*p = f->next;
		flow_free(f);
	}
}

static void flows_expire(time_t now)
{
	for (int i = 0; i < NBUCKETS; i++) {
		struct flow **p = &buckets[i];
		while (*p) {
			if (now - (*p)->last > IDLE_SECS) {
				struct flow *f = *p;
				*p = f->next;
				flow_free(f);
			} else {
				p = &(*p)->next;
			}
		}
	}
}

static struct flow *flow_get(uint32_t ctid, time_t now)
{
	struct flow **p = slot(ctid);
	if (*p)
		return *p;
	if (nflows >= MAX_FLOWS) {
		flows_expire(now);
		if (nflows >= MAX_FLOWS)
			return NULL; // full: leave the flow unclassified
	}
	struct flow *f = calloc(1, sizeof *f);
	if (!f)
		return NULL;
	f->nf = ndpi_flow_malloc(ndpi_detection_get_sizeof_ndpi_flow_struct());
	if (!f->nf) {
		free(f);
		return NULL;
	}
	memset(f->nf, 0, ndpi_detection_get_sizeof_ndpi_flow_struct());
	f->ctid = ctid;
	*p = f;
	nflows++;
	return f;
}

// ---- per-application statistics ---------------------------------------------

struct appstat {
	uint64_t flows, bytes;
	time_t last;
};
static struct appstat *stats; // indexed by app ID (0..APP_MASK)

// ---- per-host statistics -----------------------------------------------------

// Bytes and connections per source address (the connection's originator),
// for forwarded connections only. Open addressing; when full, the host seen
// longest ago gives up its slot.
#define MAX_HOSTS 4096
struct hoststat {
	uint32_t ip; // network order; 0 = free
	uint64_t flows, bytes;
	time_t last;
};
static struct hoststat hosts[MAX_HOSTS];

static void host_add(uint32_t ip, uint64_t bytes, time_t now)
{
	if (!ip)
		return;
	unsigned h = (ntohl(ip) * 2654435761u) % MAX_HOSTS;
	for (unsigned i = 0; i < MAX_HOSTS; i++) {
		struct hoststat *e = &hosts[(h + i) % MAX_HOSTS];
		if (e->ip == ip || !e->ip) {
			e->ip = ip;
			e->flows++;
			e->bytes += bytes;
			e->last = now;
			return;
		}
	}
	// Full: reuse the stalest entry. Its counts restart from this
	// connection (the reader treats counters that went down as new).
	struct hoststat *old = &hosts[0];
	for (unsigned i = 1; i < MAX_HOSTS; i++)
		if (hosts[i].last < old->last)
			old = &hosts[i];
	*old = (struct hoststat){.ip = ip, .flows = 1, .bytes = bytes, .last = now};
}

static uint16_t app_of(ndpi_protocol p)
{
	uint16_t id = p.proto.app_protocol;
	if (id == NDPI_PROTOCOL_UNKNOWN)
		id = p.proto.master_protocol;
	return id & APP_MASK;
}

static const char *app_name(uint16_t id)
{
	if (id == 0)
		return "unknown";
	const char *n = ndpi_get_proto_name(ndpi, id);
	return n ? n : "unknown";
}

static const char *app_category(uint16_t id)
{
	ndpi_protocol p;
	memset(&p, 0, sizeof p);
	p.proto.app_protocol = id;
	p.category = NDPI_PROTOCOL_CATEGORY_UNSPECIFIED;
	const char *c = ndpi_category_get_name(ndpi, ndpi_get_proto_category(ndpi, p));
	return c ? c : "";
}

// json_str writes s as a JSON string (nDPI names are plain ASCII, but be safe).
static void json_str(FILE *f, const char *s)
{
	fputc('"', f);
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c == '"' || c == '\\')
			fprintf(f, "\\%c", c);
		else if (c < 0x20)
			fprintf(f, "\\u%04x", c);
		else
			fputc(c, f);
	}
	fputc('"', f);
}

static void stats_write(time_t now)
{
	char tmp[] = STATS_PATH ".XXXXXX";
	int fd = mkstemp(tmp);
	if (fd < 0)
		return;
	FILE *f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		unlink(tmp);
		return;
	}
	fprintf(f, "{\"updated\": %ld, \"active_flows\": %u, \"apps\": [", (long)now, nflows);
	int first = 1;
	for (unsigned id = 0; id <= APP_MASK; id++) {
		if (!stats[id].flows)
			continue;
		fprintf(f, "%s\n  {\"id\": %u, \"name\": ", first ? "" : ",", id);
		json_str(f, app_name(id));
		fprintf(f, ", \"category\": ");
		json_str(f, app_category(id));
		fprintf(f, ", \"flows\": %llu, \"bytes\": %llu, \"last_seen\": %ld}",
			(unsigned long long)stats[id].flows, (unsigned long long)stats[id].bytes, (long)stats[id].last);
		first = 0;
	}
	fprintf(f, "\n], \"hosts\": [");
	first = 1;
	for (unsigned i = 0; i < MAX_HOSTS; i++) {
		if (!hosts[i].ip)
			continue;
		char a[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &hosts[i].ip, a, sizeof a);
		fprintf(f, "%s\n  {\"ip\": \"%s\", \"flows\": %llu, \"bytes\": %llu}", first ? "" : ",", a,
			(unsigned long long)hosts[i].flows, (unsigned long long)hosts[i].bytes);
		first = 0;
	}
	fprintf(f, "\n]}\n");
	fchmod(fd, 0644);
	if (fclose(f) == 0)
		rename(tmp, STATS_PATH);
	else
		unlink(tmp);
}

// ---- NFQUEUE -----------------------------------------------------------------

static struct mnl_socket *qnl;
static unsigned qportid;

static void send_verdict(uint16_t qnum, uint32_t pktid, int setmark, uint32_t mark)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, qnum);
	nfq_nlmsg_verdict_put(nlh, pktid, NF_ACCEPT);
	if (setmark) {
		// CTA_MARK_MASK names the bits to change: the kernel computes
		// new = (old & ~mask) ^ mark, so the rule bits are kept.
		struct nlattr *nest = mnl_attr_nest_start(nlh, NFQA_CT);
		mnl_attr_put_u32(nlh, CTA_MARK, htonl(mark & (APP_MASK | DONE_BIT)));
		mnl_attr_put_u32(nlh, CTA_MARK_MASK, htonl(APP_MASK | DONE_BIT));
		mnl_attr_nest_end(nlh, nest);
	}
	if (mnl_socket_sendto(qnl, nlh, nlh->nlmsg_len) < 0)
		perror("appidd: verdict");
}

static int queue_cb(const struct nlmsghdr *nlh, void *data)
{
	(void)data;
	struct nlattr *attr[NFQA_MAX + 1] = {0};
	if (nfq_nlmsg_parse(nlh, attr) < 0 || !attr[NFQA_PACKET_HDR])
		return MNL_CB_OK;
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	uint16_t qnum = ntohs(nfg->res_id);
	struct nfqnl_msg_packet_hdr *ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
	uint32_t pktid = ntohl(ph->packet_id);

	uint32_t ctid = 0, ctmark = 0;
	if (attr[NFQA_CT]) {
		struct nf_conntrack *ct = nfct_new();
		if (ct) {
			if (nfct_payload_parse(mnl_attr_get_payload(attr[NFQA_CT]),
					       mnl_attr_get_payload_len(attr[NFQA_CT]), AF_INET, ct) >= 0) {
				ctid = nfct_get_attr_u32(ct, ATTR_ID);
				ctmark = nfct_get_attr_u32(ct, ATTR_MARK);
			}
			nfct_destroy(ct);
		}
	}
	// Packets already queued when the flow was finished: nothing to do.
	if (!ctid || !attr[NFQA_PAYLOAD] || (ctmark & DONE_BIT)) {
		send_verdict(qnum, pktid, 0, 0);
		return MNL_CB_OK;
	}

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct flow *f = flow_get(ctid, ts.tv_sec);
	if (!f) {
		send_verdict(qnum, pktid, 0, 0);
		return MNL_CB_OK;
	}
	f->last = ts.tv_sec;
	f->pkts++;
	uint64_t ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
	ndpi_protocol p = ndpi_detection_process_packet(ndpi, f->nf,
		mnl_attr_get_payload(attr[NFQA_PAYLOAD]), mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]), ms, NULL);

	int done = p.state == NDPI_STATE_CLASSIFIED || p.state == NDPI_STATE_MONITORING;
	if (debug)
		fprintf(stderr, "appidd: ct %u pkt %u master %u app %u state %d\n", ctid, f->pkts,
			p.proto.master_protocol, p.proto.app_protocol, (int)p.state);
	if (!done && f->pkts >= MAX_PKTS) {
		p = ndpi_detection_giveup(ndpi, f->nf);
		done = 1;
	}
	uint16_t app = app_of(p);
	if (done) {
		send_verdict(qnum, pktid, 1, app | DONE_BIT);
		flow_drop(ctid); // no more packets come for it
	} else if (app && app != f->app) {
		// A provisional answer (e.g. TLS server name before the
		// certificate): record it now, keep inspecting.
		send_verdict(qnum, pktid, 1, app);
		f->app = app;
	} else {
		send_verdict(qnum, pktid, 0, 0);
	}
	return MNL_CB_OK;
}

static int queue_setup(void)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	qnl = mnl_socket_open(NETLINK_NETFILTER);
	if (!qnl || mnl_socket_bind(qnl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("appidd: nfqueue socket");
		return -1;
	}
	qportid = mnl_socket_get_portid(qnl);
	for (uint16_t q = 0; q < QUEUES; q++) {
		struct nlmsghdr *nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, q);
		nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
		if (mnl_socket_sendto(qnl, nlh, nlh->nlmsg_len) < 0) {
			perror("appidd: bind queue");
			return -1;
		}
		nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, q);
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 2048); // headers + first payload bytes are enough
		mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_CONNTRACK | NFQA_CFG_F_FAIL_OPEN));
		mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_CONNTRACK | NFQA_CFG_F_FAIL_OPEN));
		if (mnl_socket_sendto(qnl, nlh, nlh->nlmsg_len) < 0) {
			perror("appidd: configure queue");
			return -1;
		}
	}
	int one = 1;
	mnl_socket_setsockopt(qnl, NETLINK_NO_ENOBUFS, &one, sizeof one);
	return 0;
}

// ---- conntrack DESTROY events ----------------------------------------------

static struct mnl_socket *cnl;

static int ct_cb(const struct nlmsghdr *nlh, void *data)
{
	(void)data;
	struct nf_conntrack *ct = nfct_new();
	if (!ct)
		return MNL_CB_OK;
	nfct_nlmsg_parse(nlh, ct);
	uint32_t ctid = nfct_get_attr_u32(ct, ATTR_ID);
	uint32_t mark = nfct_get_attr_u32(ct, ATTR_MARK);
	uint16_t app = mark & APP_MASK;
	int known = (mark & DONE_BIT) != 0;
	struct flow **fp = slot(ctid);
	if (*fp && !known) {
		// Ended before nDPI finished: take its best answer so far.
		ndpi_protocol p = ndpi_detection_giveup(ndpi, (*fp)->nf);
		if (app_of(p))
			app = app_of(p);
		known = 1;
	}
	flow_drop(ctid);

	uint8_t l4 = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
	if (l4 != IPPROTO_TCP && l4 != IPPROTO_UDP) {
		nfct_destroy(ct);
		return MNL_CB_OK;
	}
	uint64_t bytes = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES) + nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES);
	uint64_t pkts = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS) + nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_PACKETS);
	time_t now = time(NULL);
	if (known || app) {
		stats[app].flows++;
		stats[app].bytes += bytes;
		stats[app].last = now;
		host_add(nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC), bytes, now);
	}
	uint32_t rule = mark >> RULE_SHIFT;
	if (rule && (mark & SESSION_BIT)) {
		char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
		uint32_t s = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC), d = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
		inet_ntop(AF_INET, &s, src, sizeof src);
		inet_ntop(AF_INET, &d, dst, sizeof dst);
		double dur = 0;
		if (nfct_attr_is_set(ct, ATTR_TIMESTAMP_START) && nfct_attr_is_set(ct, ATTR_TIMESTAMP_STOP))
			dur = (nfct_get_attr_u64(ct, ATTR_TIMESTAMP_STOP) - nfct_get_attr_u64(ct, ATTR_TIMESTAMP_START)) / 1e9;
		printf("ngfw-session rule=%u app=%s cat=%s proto=%s src=%s sport=%u dst=%s dport=%u bytes=%llu packets=%llu dur=%.1f\n",
		       rule - 1, app_name(app), app ? app_category(app) : "",
		       l4 == IPPROTO_TCP ? "tcp" : "udp", src, ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)), dst,
		       ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)), (unsigned long long)bytes, (unsigned long long)pkts, dur);
		fflush(stdout);
	}
	nfct_destroy(ct);
	return MNL_CB_OK;
}

static int ct_setup(void)
{
	cnl = mnl_socket_open(NETLINK_NETFILTER);
	if (!cnl || mnl_socket_bind(cnl, NF_NETLINK_CONNTRACK_DESTROY, MNL_SOCKET_AUTOPID) < 0) {
		perror("appidd: conntrack events");
		return -1;
	}
	int rcv = 4 << 20;
	setsockopt(mnl_socket_get_fd(cnl), SOL_SOCKET, SO_RCVBUFFORCE, &rcv, sizeof rcv);
	int one = 1;
	mnl_socket_setsockopt(cnl, NETLINK_NO_ENOBUFS, &one, sizeof one);
	return 0;
}

// stats_load picks up the totals the previous appidd wrote, so a restart
// (an upgrade, a crash, systemctl restart) doesn't lose what was counted
// since its last write; ngfwd samples the totals as running counters. Only
// a reboot (which clears /run) starts them from zero, and ngfwd treats
// counters that went down as new. Reads appidd's own format, one object a
// line.
static void stats_load(void)
{
	FILE *f = fopen(STATS_PATH, "r");
	if (!f)
		return;
	char line[1024];
	unsigned apps = 0, nhosts = 0;
	while (fgets(line, sizeof line, f)) {
		unsigned id;
		unsigned long long flows, bytes;
		long last;
		char ip[INET_ADDRSTRLEN];
		const char *p;
		if (sscanf(line, " {\"id\": %u,", &id) == 1 && id <= APP_MASK && (p = strstr(line, "\"flows\":")) &&
		    sscanf(p, "\"flows\": %llu, \"bytes\": %llu, \"last_seen\": %ld", &flows, &bytes, &last) == 3) {
			stats[id] = (struct appstat){.flows = flows, .bytes = bytes, .last = last};
			apps++;
		} else if (sscanf(line, " {\"ip\": \"%15[0-9.]\", \"flows\": %llu, \"bytes\": %llu}", ip, &flows, &bytes) == 3) {
			uint32_t a;
			if (inet_pton(AF_INET, ip, &a) != 1 || !a)
				continue;
			unsigned h = (ntohl(a) * 2654435761u) % MAX_HOSTS;
			for (unsigned i = 0; i < MAX_HOSTS; i++) {
				struct hoststat *e = &hosts[(h + i) % MAX_HOSTS];
				if (!e->ip) {
					*e = (struct hoststat){.ip = a, .flows = flows, .bytes = bytes, .last = time(NULL)};
					nhosts++;
					break;
				}
			}
		}
	}
	fclose(f);
	if (apps || nhosts)
		fprintf(stderr, "appidd: carried on from %s: %u applications, %u hosts\n", STATS_PATH, apps, nhosts);
}

// ---- main --------------------------------------------------------------------

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static int catalog(void)
{
	unsigned n = ndpi_get_num_protocols(ndpi);
	printf("[");
	int first = 1;
	for (unsigned id = 1; id < n && id <= APP_MASK; id++) {
		const char *name = ndpi_get_proto_name(ndpi, id);
		if (!name || !*name || !strcmp(name, "Unknown"))
			continue;
		printf("%s\n  {\"id\": %u, \"name\": ", first ? "" : ",", id);
		json_str(stdout, name);
		printf(", \"category\": ");
		json_str(stdout, app_category(id));
		printf("}");
		first = 0;
	}
	printf("\n]\n");
	return 0;
}

int main(int argc, char **argv)
{
	ndpi = ndpi_init_detection_module(NULL, NDPI_LICENSE_NOT_FOR_PROFIT_LGPL);
	if (!ndpi || ndpi_finalize_initialization(ndpi) != 0) {
		fprintf(stderr, "appidd: nDPI initialisation failed\n");
		return 1;
	}
	if (argc > 1 && !strcmp(argv[1], "--catalog"))
		return catalog();
	if (argc > 1) {
		fprintf(stderr, "usage: appidd [--catalog]\n");
		return 2;
	}
	debug = getenv("APPIDD_DEBUG") != NULL;
	stats = calloc(APP_MASK + 1, sizeof *stats);
	if (!stats || queue_setup() < 0 || ct_setup() < 0)
		return 1;
	mkdir("/run/appidd", 0755);
	stats_load();
	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);
	fprintf(stderr, "appidd: nDPI %s, %u applications, queues 0-%d. Checking papers at the border.\n",
		ndpi_revision(), ndpi_get_num_protocols(ndpi), QUEUES - 1);

	static char buf[0xffff + 8192];
	struct pollfd pfd[2] = {{.fd = mnl_socket_get_fd(qnl), .events = POLLIN},
				{.fd = mnl_socket_get_fd(cnl), .events = POLLIN}};
	time_t last_write = 0;
	while (!stop) {
		int r = poll(pfd, 2, 1000);
		if (r < 0 && errno != EINTR)
			break;
		if (pfd[0].revents & POLLIN) {
			ssize_t n = mnl_socket_recvfrom(qnl, buf, sizeof buf);
			if (n > 0)
				mnl_cb_run(buf, n, 0, qportid, queue_cb, NULL);
		}
		if (pfd[1].revents & POLLIN) {
			ssize_t n = mnl_socket_recvfrom(cnl, buf, sizeof buf);
			if (n > 0)
				mnl_cb_run(buf, n, 0, 0, ct_cb, NULL);
		}
		time_t now = time(NULL);
		if (now - last_write >= 10) {
			flows_expire(now);
			stats_write(now);
			last_write = now;
		}
	}
	stats_write(time(NULL));
	ndpi_exit_detection_module(ndpi);
	return 0;
}
