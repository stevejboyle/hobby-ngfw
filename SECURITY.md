# Security

SJB-OS is a demonstration, not a supported product: run it in a lab, not in
front of anything that matters. Security reports are still welcome.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: the **Security** tab of this
repository, then **Report a vulnerability**. Please don't open a public issue.
Include the version (`show version`), what you found and how to reproduce it.

There is no bounty and no response-time commitment; fixes ship, when they
do, as signed upgrade bundles on the releases page.

## What to expect from the appliance

- No vendor access: no root key or password ships. Root has only what the
  operator sets at deploy time (`root_ssh_key`, `root_password`).
- Upgrade bundles are signed (Ed25519); appliances hold only the public key
  and refuse anything it didn't sign.
- Operators get a captive CLI, never a Unix shell; the management interface
  is separate from forwarded traffic.
- Known limits: a self-signed certificate, one admin account, password SSH
  for `admin` unless you set `admin_ssh_key`, and no independent audit.
