// validate-catalogs runs the same filesource.Load() the backend uses on each
// reload tick, against a catalogs directory on disk. Exits non-zero on any
// parse / schema / semantic error (duplicate keys, unknown status, invalid
// regex / CIDR, out-of-range ASN, etc.).
//
// Intended for CI on PRs touching catalogs/*. Catches the class of mistakes
// where a YAML file is committable but the backend would silently fail to
// reload (e.g. duplicate map keys — yaml.v3 strict mode flags those, but no
// editor or `git diff` will).
package main

import (
	"fmt"
	"os"

	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/filesource"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <catalogs-dir>\n", os.Args[0])
		os.Exit(2)
	}
	dir := os.Args[1]
	slow, err := filesource.New(dir).Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalogs invalid: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("catalogs ok (version=%s, tls_fp=%d, ip_block=%d, ua=%d, ip_wl=%d, asn=%d, tls_fp_cat=%d, browser_prof=%d)\n",
		slow.Version,
		len(slow.TLSFPBlocklist),
		len(slow.IPBlocklist),
		len(slow.UABlacklist),
		len(slow.IPWhitelist),
		len(slow.ASNDatacenters),
		len(slow.TLSFPCatalog),
		len(slow.TLSFPBrowserProfiles),
	)
}
