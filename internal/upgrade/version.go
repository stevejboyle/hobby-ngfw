package upgrade

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is MAJOR.MINOR.PATCH with an optional suffix:
//
//   - -rNN is a SJB-OS revision build that comes after the release:
//     0.6.1 is 0.6.1-r00, and 0.6.1 < 0.6.1-r01 < ... < 0.6.1-r10 (numeric).
//   - any other -tag is a pre-release that comes before it, as in semver:
//     0.6.1-rc1 < 0.6.1.
//
// Build metadata (+...) is accepted and ignored for ordering.
type Version struct {
	Major, Minor, Patch int
	Rev                 int    // -rNN; 0 for a plain release
	Pre                 string // pre-release tag (not -rNN)
	raw                 string
}

func (v Version) String() string { return v.raw }

// ParseVersion parses a version string.
func ParseVersion(s string) (Version, error) {
	v := Version{raw: s}
	core := s
	if i := strings.IndexByte(core, '+'); i >= 0 {
		core = core[:i]
	}
	if i := strings.IndexByte(core, '-'); i >= 0 {
		v.Pre = core[i+1:]
		core = core[:i]
		if v.Pre == "" {
			return v, fmt.Errorf("version %q: empty pre-release", s)
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("version %q: want MAJOR.MINOR.PATCH", s)
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, fmt.Errorf("version %q: %q is not a number", s, p)
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	if len(v.Pre) > 1 && v.Pre[0] == 'r' {
		if n, err := strconv.Atoi(v.Pre[1:]); err == nil && n >= 0 && strings.Trim(v.Pre[1:], "0123456789") == "" {
			v.Rev, v.Pre = n, ""
		}
	}
	return v, nil
}

// Compare returns -1, 0 or 1. A pre-release sorts before its release, and
// -rNN revisions after it, by number.
func (v Version) Compare(o Version) int {
	for _, d := range []int{v.Major - o.Major, v.Minor - o.Minor, v.Patch - o.Patch} {
		if d < 0 {
			return -1
		}
		if d > 0 {
			return 1
		}
	}
	// Same MAJOR.MINOR.PATCH: pre-releases first, then the release (r00),
	// then revisions.
	if (v.Pre == "") != (o.Pre == "") {
		if v.Pre != "" {
			return -1
		}
		return 1
	}
	switch {
	case v.Pre != "": // both pre-releases of the same version
		return strings.Compare(v.Pre, o.Pre)
	case v.Rev < o.Rev:
		return -1
	case v.Rev > o.Rev:
		return 1
	}
	return 0
}

// CheckVersion decides whether a bundle may be installed over current.
// allowSame permits reinstalling the running version (repair).
func CheckVersion(m Manifest, current string, allowSame bool) error {
	cur, err := ParseVersion(current)
	if err != nil {
		return fmt.Errorf("installed version: %w", err)
	}
	nv, err := ParseVersion(m.Version)
	if err != nil {
		return err
	}
	switch c := nv.Compare(cur); {
	case c < 0:
		return fmt.Errorf("%s is older than the installed %s; use `fwctl upgrade rollback` to go back", m.Version, current)
	case c == 0 && !allowSame:
		return fmt.Errorf("%s is already installed (use -reinstall to apply it again)", current)
	}
	if m.MinFromVersion != "" {
		min, err := ParseVersion(m.MinFromVersion)
		if err != nil {
			return err
		}
		if cur.Compare(min) < 0 {
			return fmt.Errorf("%s needs %s or later installed first (have %s)", m.Version, m.MinFromVersion, current)
		}
	}
	return nil
}
