// Copyright (C) 2016, 2023 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"bufio"
	"fmt"
	"golang.org/x/net/idna"
	"io"
	"net"
	"software.sslmate.com/src/certspotter"
	"strings"
)

type WatchItem struct {
	domain       []string
	acceptSuffix bool
	ipaddr       net.IP // non-nil for IP address watch items; nil for DNS name watch items
}

type WatchList []WatchItem

func ParseWatchItem(str string) (WatchItem, error) {
	fields := strings.Fields(str)
	if len(fields) == 0 {
		return WatchItem{}, fmt.Errorf("empty domain")
	}
	domain := fields[0]

	for _, field := range fields[1:] {
		switch {
		case strings.HasPrefix(field, "valid_at:"):
			// Ignore for backwards compatibility
		default:
			return WatchItem{}, fmt.Errorf("unknown parameter %q", field)
		}
	}

	if domain == "." {
		// "." as in root zone -> matches everything
		return WatchItem{
			domain:       []string{},
			acceptSuffix: true,
		}, nil
	}

	if strings.HasPrefix(domain, "ip:") {
		// Explicit IP address watch item.  The "ip:" prefix is required so that
		// bare IP literals in the watch list remain an unambiguous, fail-closed
		// configuration error instead of silently matching as a DNS name.
		ipaddr := net.ParseIP(domain[len("ip:"):])
		if ipaddr == nil {
			return WatchItem{}, fmt.Errorf("invalid IP address %q", domain)
		}
		return WatchItem{
			ipaddr: canonicalWatchIP(ipaddr),
		}, nil
	}

	if ipaddr := net.ParseIP(domain); ipaddr != nil {
		// A bare IP literal is ambiguous: it could be intended as an IP address
		// or as a (syntactically invalid) DNS name.  Fail closed rather than
		// guessing, so an IP-only certificate can never be silently missed.
		return WatchItem{}, fmt.Errorf("watch item %q looks like an IP address; use %q to watch an IP address", domain, "ip:"+ipaddr.String())
	}

	acceptSuffix := false
	if strings.HasPrefix(domain, ".") {
		acceptSuffix = true
		domain = domain[1:]
	}

	if domain == "" {
		return WatchItem{}, fmt.Errorf("empty domain")
	}

	asciiDomain, err := idna.ToASCII(strings.ToLower(strings.TrimRight(domain, ".")))
	if err != nil {
		return WatchItem{}, fmt.Errorf("invalid domain %q (%w)", domain, err)
	}
	return WatchItem{
		domain:       strings.Split(asciiDomain, "."),
		acceptSuffix: acceptSuffix,
	}, nil
}

func ReadWatchList(reader io.Reader) (WatchList, error) {
	items := make(WatchList, 0, 50)
	scanner := bufio.NewScanner(reader)
	lineNo := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		item, err := ParseWatchItem(line)
		if err != nil {
			return nil, fmt.Errorf("%w on line %d", err, lineNo)
		}
		items = append(items, item)
	}
	return items, scanner.Err()
}

func (item WatchItem) String() string {
	if item.ipaddr != nil {
		return "ip:" + item.ipaddr.String()
	}
	if item.acceptSuffix {
		return "." + strings.Join(item.domain, ".")
	} else {
		return strings.Join(item.domain, ".")
	}
}

func canonicalWatchIP(ipaddr net.IP) net.IP {
	// Store every watched address in the same canonical 16-byte form used for
	// certificate identifiers, so mapped and unmapped encodings of the same
	// address share a single identity.
	return ipaddr.To16()
}

func (item WatchItem) matchesIPAddr(ipaddr net.IP) bool {
	return item.ipaddr != nil && item.ipaddr.Equal(ipaddr)
}

func (item WatchItem) matchesDNSName(dnsName []string) bool {
	watchDomain := item.domain
	for len(dnsName) > 0 && len(watchDomain) > 0 {
		certLabel := dnsName[len(dnsName)-1]
		watchLabel := watchDomain[len(watchDomain)-1]

		if !dnsLabelMatches(certLabel, watchLabel) {
			return false
		}

		dnsName = dnsName[:len(dnsName)-1]
		watchDomain = watchDomain[:len(watchDomain)-1]
	}
	return len(watchDomain) == 0 && (item.acceptSuffix || len(dnsName) == 0)
}

func dnsLabelMatches(certLabel string, watchLabel string) bool {
	// For fail-safe behavior, if a label was unparsable, it matches everything.
	// Similarly, redacted labels match everything, since the label _might_ be
	// for a name we're interested in.

	return certLabel == "*" ||
		certLabel == "?" ||
		certLabel == certspotter.UnparsableDNSLabelPlaceholder ||
		certspotter.MatchesWildcard(watchLabel, certLabel)
}

func (list WatchList) Matches(identifiers *certspotter.Identifiers) (bool, WatchItem) {
	dnsNames := make([][]string, len(identifiers.DNSNames))
	for i, dnsName := range identifiers.DNSNames {
		dnsNames[i] = strings.Split(dnsName, ".")
	}
	for _, item := range list {
		if item.ipaddr != nil {
			for _, ipaddr := range identifiers.IPAddrs {
				if item.matchesIPAddr(ipaddr) {
					return true, item
				}
			}
			continue
		}
		for _, dnsName := range dnsNames {
			if item.matchesDNSName(dnsName) {
				return true, item
			}
		}
	}
	return false, WatchItem{}
}
