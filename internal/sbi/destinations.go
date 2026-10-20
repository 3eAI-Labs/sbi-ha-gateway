// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package sbi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ErrDestinationNotAllowed is returned for an outbound call whose destination the
// Destinations policy refuses. It is permanent: retrying the same URI cannot succeed.
var ErrDestinationNotAllowed = errors.New("outbound destination not allowed")

// Destinations decides which hosts the gateway's outbound calls — notification callbacks,
// SMSF calls — may reach. The URIs come from NATS messages, so this
// limits what a compromised or mistaken application can make the gateway call.
//
// The check runs when the connection is made, on the address actually dialled: a host name
// is resolved once, every address is checked, and the connection goes to a checked address,
// so DNS cannot point an allowed name somewhere else in between. TLS still verifies the
// name in the URI.
//
// A name is resolved only when an address could allow it: it matches a name rule, or the
// policy has CIDR or address rules, or allows any. With name rules alone an unlisted name is
// refused unresolved, so a URI cannot make the gateway query DNS for any name it carries.
type Destinations struct {
	allowAny bool
	hosts    map[string]bool // exact names
	suffixes []string        // ".example.com": that domain's subdomains
	prefixes []netip.Prefix  // CIDR blocks and single addresses

	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error) // nil: net.DefaultResolver
}

// ParseDestinations reads OUTBOUND_ALLOWED_DESTINATIONS: comma-separated host names
// ("smsf1.5gc.example"), domain suffixes (".5gc.example" or "*.5gc.example"), CIDR blocks
// ("10.20.0.0/16") and addresses. allowAny (OUTBOUND_ALLOW_ANY) allows every destination
// but the always-denied ones. Empty and !allowAny: nothing is allowed.
func ParseDestinations(list string, allowAny bool) (*Destinations, error) {
	d := &Destinations{allowAny: allowAny, hosts: map[string]bool{}}
	for _, entry := range strings.Split(list, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		switch {
		case entry == "":
		case strings.Contains(entry, "/"):
			p, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("OUTBOUND_ALLOWED_DESTINATIONS: %q: %w", entry, err)
			}
			d.prefixes = append(d.prefixes, p.Masked())
		case isAddr(entry):
			a, _ := netip.ParseAddr(entry)
			d.prefixes = append(d.prefixes, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		case strings.HasPrefix(entry, "*.") || strings.HasPrefix(entry, "."):
			suffix := "." + strings.TrimLeft(entry, "*.")
			if !validName(suffix[1:]) {
				return nil, fmt.Errorf("OUTBOUND_ALLOWED_DESTINATIONS: %q is not a domain", entry)
			}
			d.suffixes = append(d.suffixes, suffix)
		default:
			if !validName(entry) {
				return nil, fmt.Errorf("OUTBOUND_ALLOWED_DESTINATIONS: %q is not a host name, domain, CIDR or address", entry)
			}
			d.hosts[entry] = true
		}
	}
	return d, nil
}

// Restricted reports whether the policy limits destinations (a list, not allow-any).
func (d *Destinations) Restricted() bool { return !d.allowAny }

func isAddr(s string) bool { _, err := netip.ParseAddr(s); return err == nil }

func validName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// nameAllowed reports whether host matches a name rule.
func (d *Destinations) nameAllowed(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if d.hosts[host] {
		return true
	}
	for _, s := range d.suffixes {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}

// listed reports whether a is inside a CIDR or address rule.
func (d *Destinations) listed(a netip.Addr) bool {
	for _, p := range d.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// addrAllowed reports whether the gateway may connect to a, reached through a name that did
// (byName) or did not match a name rule. Loopback, link-local (cloud metadata among them),
// unspecified and multicast addresses are refused unless a CIDR or address rule lists them.
func (d *Destinations) addrAllowed(a netip.Addr, byName bool) bool {
	a = a.Unmap()
	if d.listed(a) {
		return true
	}
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	return d.allowAny || byName
}

// DialContext wraps dial so that it connects only to an allowed destination; addr is the
// "host:port" the HTTP transport dials.
func (d *Destinations) DialContext(dial func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if a, err := netip.ParseAddr(host); err == nil {
			if !d.addrAllowed(a, false) {
				return nil, fmt.Errorf("%w: %s", ErrDestinationNotAllowed, host)
			}
			return dial(ctx, network, addr)
		}
		// A name that matches no name rule may still resolve into a listed CIDR block: the
		// decision is on each resolved address. Without such a block, or allow-any, nothing
		// could allow it, and it is not resolved.
		byName := d.nameAllowed(host)
		if !byName && !d.allowAny && len(d.prefixes) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrDestinationNotAllowed, host)
		}
		lookup := d.lookup
		if lookup == nil {
			lookup = net.DefaultResolver.LookupNetIP
		}
		ips, err := lookup(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		last := fmt.Errorf("%w: %s resolves to no allowed address", ErrDestinationNotAllowed, host)
		for _, ip := range ips {
			if !d.addrAllowed(ip, byName) {
				continue
			}
			conn, err := dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
}
