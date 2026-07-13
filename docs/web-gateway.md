# FreeSense Web Gateway 2.0

FreeSense Web Gateway is an outbound web security gateway built around the
FreeBSD Squid 7 port. It replaces the retired Squid/SquidGuard wrappers with a
native FreeSense configuration model, policy compiler, PF integration and
transactional activation path.

## Safety model

- The package is disabled after installation.
- HTTPS defaults to CONNECT tunnelling without decryption.
- WAN and gateway-facing interfaces cannot be selected as clients.
- Transparent redirects exist only while the gateway is enabled and healthy,
  unless an administrator explicitly chooses fail-closed enforcement.
- Every change is staged, parsed by Squid, activated atomically and rolled back
  if the daemon cannot start.
- TLS inspection requires an internal CA with its private key plus an explicit
  legal/privacy acknowledgement.
- Upstream certificate validation is never globally disabled.

## Listener and HTTPS modes

Explicit proxy, transparent HTTP and transparent HTTPS listeners can be mixed
per internal interface for IPv4 and IPv6. PF bypasses firewall-owned, private,
management and administrator-exempt traffic to prevent interception loops.
UDP/443 can optionally be blocked so HTTP/3 clients retry over TCP.

HTTPS offers three modes:

1. **Tunnel only** — end-to-end CONNECT tunnels; hostname/SNI/IP policy only.
2. **Selective inspection** — inspect listed destinations and splice the rest.
3. **Full inspection** — inspect by default while honoring built-in and custom
   bypass lists for pinned, mTLS, update, authentication and PKI services.

The inspection CA is selected from Certificate Manager and registered as being
in use by the package. Deploy its public certificate to managed clients before
turning inspection on.

## Policy and identity

The native compiler produces Squid ACL files for allow/block destinations,
regular expressions, threat feeds, TLS bump/splice decisions, authentication,
ICAP adaptation and delay pools. The UI includes a decision simulator and warns
when an HTTPS rule needs inspection to see a URL path or response body.

Explicit clients may authenticate with enabled, non-expired accounts from the local FreeSense user database,
LDAP/AD, RADIUS or Kerberos/Negotiate. Transparent listeners intentionally do
not challenge browsers. NTLM/SMB fallback is not supported.

## Feeds and malware scanning

HTTPS domain/hosts feeds are staged, bounded, normalized, deduplicated and
atomically activated. A failed download or compile keeps the last-known-good
database. An hourly FreeSense-managed scheduler checks the configured 1-720
hour interval. FreeSense does not silently bundle third-party feeds.

External ICAP supports request and response modification with explicit bypass
or fail-closed policy. The optional `FreeSense-pkg-WebGateway-AV` companion adds
ClamAV, c-icap and squidclamav for local scanning of HTTP and inspected HTTPS.

## Cache, upstreams and operations

Cache profiles, delay-pool shaping and authenticated parent proxies are managed
under **Cache & Upstreams**. Inbound publishing remains the responsibility of
HAProxy and is linked from the Web Gateway overview.

Diagnostics verifies the pinned Squid major, required helpers, generated
configuration and safety invariants. Status includes an emergency disable that
removes interception rules before stopping the service.

## Build invariant

The FreeSense poudriere configuration forces Squid options required for PF
transparent proxying, TLS certificate generation, ICAP, authentication, delay
pools and quotas. CI must reject Squid 8 until its missing Squid 7 certificate
generation workflow has a tested replacement.
