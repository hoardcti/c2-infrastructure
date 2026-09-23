package aggregator

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/doodad-labs/command-server-watch/internal/payload"
)

// resultKey returns a comparable key used to deduplicate result entries.
//
// Two results are considered duplicates when they share the same source
// and the same set of flags (order- and duplicate-independent).
func resultKey(r payload.Result) string {
	flags := slices.Clone(r.Flags)
	slices.Sort(flags)
	flags = slices.Compact(flags)

	// NUL cannot appear in a source name or flag, so it is a safe separator
	return r.Source + "\x00" + strings.Join(flags, "\x00")
}

// validIP reports whether ip is a valid IPv4 or IPv6 address. Zoned IPv6
// addresses (fe80::1%eth0) are rejected because the zone cannot safely be
// used as part of a file path.
func validIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)

	return nil == err && "" == addr.Zone()
}
