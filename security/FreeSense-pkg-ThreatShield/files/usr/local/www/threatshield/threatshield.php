<?php
/*
 * threatshield.php
 * FreeSense Threat Shield - General Settings, DNS Engine & Advanced Protection
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield
##|*DESCR=Configure FreeSense Threat Shield DNS, caching, rate limiting, and threat protection
##|*MATCH=threatshield/threatshield.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

$input_errors = [];
$savemsg = null;
$ts_config = threatshield_config();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save'])) {
	$pconfig = $_POST;

	// Core & Network
	$ts_config['enable'] = isset($pconfig['enable']) ? 'on' : 'off';
	$ts_config['listen_port'] = (int)($pconfig['listen_port'] ?? 53);
	$ts_config['dns_coordination_mode'] = in_array($pconfig['dns_coordination_mode'] ?? '', ['primary', 'proxy', 'standalone'], true) ? $pconfig['dns_coordination_mode'] : 'primary';
	$ts_config['upstream_mode'] = in_array($pconfig['upstream_mode'] ?? '', ['parallel', 'fastest_addr', 'load_balance'], true) ? $pconfig['upstream_mode'] : 'parallel';
	$ts_config['upstreams'] = trim($pconfig['upstreams'] ?? '');
	$ts_config['bootstrap_dns'] = trim($pconfig['bootstrap_dns'] ?? '');
	$ts_config['fallback_dns'] = trim($pconfig['fallback_dns'] ?? '');

	// Cache & Performance
	$ts_config['cache_size'] = max(1, (int)($pconfig['cache_size'] ?? 4));
	$ts_config['cache_ttl_min'] = max(0, (int)($pconfig['cache_ttl_min'] ?? 0));
	$ts_config['cache_ttl_max'] = max(0, (int)($pconfig['cache_ttl_max'] ?? 0));
	$ts_config['cache_optimistic'] = isset($pconfig['cache_optimistic']) ? 'on' : 'off';

	// Security & Protection
	$ts_config['enable_dnssec'] = isset($pconfig['enable_dnssec']) ? 'on' : 'off';
	$ts_config['safebrowsing_enabled'] = isset($pconfig['safebrowsing_enabled']) ? 'on' : 'off';
	$ts_config['enable_safesearch'] = isset($pconfig['enable_safesearch']) ? 'on' : 'off';
	$ts_config['enable_parental'] = isset($pconfig['enable_parental']) ? 'on' : 'off';
	$ts_config['blocking_mode'] = in_array($pconfig['blocking_mode'] ?? '', ['default', 'refused', 'nxdomain', 'null_ip', 'custom_ip'], true) ? $pconfig['blocking_mode'] : 'default';
	$ts_config['blocking_ipv4'] = trim($pconfig['blocking_ipv4'] ?? '');
	$ts_config['blocking_ipv6'] = trim($pconfig['blocking_ipv6'] ?? '');
	$ts_config['block_doh_canary'] = isset($pconfig['block_doh_canary']) ? 'on' : 'off';
	$ts_config['block_icloud_private_relay'] = isset($pconfig['block_icloud_private_relay']) ? 'on' : 'off';
	$ts_config['catch_rogue_dns'] = isset($pconfig['catch_rogue_dns']) ? 'on' : 'off';

	// ECS & Rate Limiting
	$ts_config['edns_client_subnet'] = isset($pconfig['edns_client_subnet']) ? 'on' : 'off';
	$ts_config['ratelimit'] = max(0, (int)($pconfig['ratelimit'] ?? 0));
	$ts_config['rate_limit_subnet_len_ipv4'] = max(1, min(32, (int)($pconfig['rate_limit_subnet_len_ipv4'] ?? 24)));
	$ts_config['rate_limit_subnet_len_ipv6'] = max(1, min(128, (int)($pconfig['rate_limit_subnet_len_ipv6'] ?? 56)));
	$ts_config['rate_limit_whitelist'] = trim($pconfig['rate_limit_whitelist'] ?? '');

	// Query Log & Privacy
	$ts_config['querylog_enabled'] = isset($pconfig['querylog_enabled']) ? 'on' : 'off';
	$ts_config['querylog_retention'] = (int)($pconfig['querylog_retention'] ?? 90);
	$ts_config['anonymize_client_ip'] = isset($pconfig['anonymize_client_ip']) ? 'on' : 'off';
	$ts_config['ignored_domains'] = trim($pconfig['ignored_domains'] ?? '');

	$input_errors = array_merge($input_errors, threatshield_validate_config($ts_config));

	if (empty($input_errors)) {
		config_set_path(THREATSHIELD_CONFIG_PATH, threatshield_config_for_storage($ts_config));
		write_config(gettext('Updated FreeSense Threat Shield settings.'));
		threatshield_sync_config();
		$savemsg = gettext('Threat Shield settings saved and applied successfully.');
	}
}

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('General Settings')];
$pglinks = ['', '@self', '@self'];

include('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('general');
?>

<div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3">
	<div>
		<h2 class="h3 mb-1"><i class="fa-solid fa-shield-halved text-primary me-2"></i><?=gettext('General Settings & DNS Engine')?></h2>
		<p class="text-muted mb-0"><?=gettext('Comprehensive configuration for DNS listening, upstream encryption, caching, anti-evasion, and privacy controls.')?></p>
	</div>
	<div class="d-flex gap-2">
		<a class="btn btn-outline-primary" href="/threatshield/threatshield_status.php"><i class="fa-solid fa-chart-pie me-2"></i><?=gettext('Live Dashboard')?></a>
		<a class="btn btn-outline-secondary" href="/threatshield/threatshield_querylog.php"><i class="fa-solid fa-list-check me-2"></i><?=gettext('Query Inspector')?></a>
	</div>
</div>

<form method="post" action="threatshield.php">
	<!-- 1. Core DNS Configuration -->
	<div class="card mb-3 shadow-sm">
		<div class="card-header bg-light">
			<h2 class="h5 mb-0"><i class="fa-solid fa-power-off text-primary me-2"></i><?=gettext('1. Core Engine & Port Coordination')?></h2>
		</div>
		<div class="card-body">
			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="enable" id="enable" <?=$ts_config['enable'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="enable">
					<?=gettext('Enable FreeSense Threat Shield')?>
				</label>
				<div class="form-text"><?=gettext('Activates the high-performance DNS filtering daemon, encrypted upstream resolution, and network-level threat defenses.')?></div>
			</div>

			<div class="mb-3">
				<label for="dns_coordination_mode" class="form-label fw-semibold"><?=gettext('DNS Port Coordination Mode')?></label>
				<select class="form-select" name="dns_coordination_mode" id="dns_coordination_mode">
					<option value="primary" <?=$ts_config['dns_coordination_mode'] === 'primary' ? 'selected' : ''?>>
						<?=gettext('Primary DNS (Recommended): Threat Shield binds to Port 53 on all interfaces; Unbound is automatically shifted to 127.0.0.1:5335 to provide local DHCP reverse PTR and domain overrides')?>
					</option>
					<option value="proxy" <?=$ts_config['dns_coordination_mode'] === 'proxy' ? 'selected' : ''?>>
						<?=gettext('Proxy Mode: Unbound remains listening on Port 53 and forwards non-local queries to Threat Shield running on 127.0.0.1:5354')?>
					</option>
					<option value="standalone" <?=$ts_config['dns_coordination_mode'] === 'standalone' ? 'selected' : ''?>>
						<?=gettext('Standalone Mode: Threat Shield manages all resolution on Port 53 directly (Unbound is disabled)')?>
					</option>
				</select>
				<div class="form-text"><?=gettext('Primary mode ensures seamless DHCP hostname resolution while giving you full ad/malware filtering and wire-speed performance.')?></div>
			</div>

			<div class="row g-3">
				<div class="col-md-6">
					<label for="listen_port" class="form-label fw-semibold"><?=gettext('DNS Listening Port')?></label>
					<input type="number" class="form-control" name="listen_port" id="listen_port" value="<?=htmlspecialchars((string)$ts_config['listen_port'])?>">
					<div class="form-text"><?=gettext('Standard DNS operates on port 53. Change this only if running custom proxy topologies.')?></div>
				</div>
				<div class="col-md-6">
					<label for="upstream_mode" class="form-label fw-semibold"><?=gettext('Upstream Query Strategy')?></label>
					<select class="form-select" name="upstream_mode" id="upstream_mode">
						<option value="parallel" <?=$ts_config['upstream_mode'] === 'parallel' ? 'selected' : ''?>><?=gettext('Parallel Queries (Recommended: Sends query to all upstreams simultaneously, adopts the fastest response)')?></option>
						<option value="fastest_addr" <?=$ts_config['upstream_mode'] === 'fastest_addr' ? 'selected' : ''?>><?=gettext('Fastest IP (Periodically benchmarks upstreams and routes all queries to the fastest responding server)')?></option>
						<option value="load_balance" <?=$ts_config['upstream_mode'] === 'load_balance' ? 'selected' : ''?>><?=gettext('Load Balancing (Sequential round-robin distribution across all configured upstreams)')?></option>
					</select>
					<div class="form-text"><?=gettext('Parallel query mode eliminates ISP latency jitter and provides instantaneous failover if an upstream is slow.')?></div>
				</div>
			</div>
		</div>
	</div>

	<!-- 2. Upstream DNS Configuration -->
	<div class="card mb-3 shadow-sm">
		<div class="card-header bg-light">
			<h2 class="h5 mb-0"><i class="fa-solid fa-lock text-primary me-2"></i><?=gettext('2. Encrypted Upstream DNS Resolvers')?></h2>
		</div>
		<div class="card-body">
			<div class="mb-3">
				<label for="upstreams" class="form-label fw-semibold"><?=gettext('Upstream DNS Resolvers (One entry per line)')?></label>
				<textarea class="form-control font-monospace" name="upstreams" id="upstreams" rows="4"><?=htmlspecialchars((string)$ts_config['upstreams'])?></textarea>
				<div class="form-text">
					<?=gettext('Supports encrypted and secure DNS protocols:')?>
					<ul class="mb-0 mt-1">
						<li><code>https://dns.quad9.net/dns-query</code> &mdash; <?=gettext('DNS-over-HTTPS (DoH)')?></li>
						<li><code>tls://1.1.1.1</code> &mdash; <?=gettext('DNS-over-TLS (DoT)')?></li>
						<li><code>quic://dns.adguard-dns.com</code> &mdash; <?=gettext('DNS-over-QUIC (DoQ)')?></li>
						<li><code>9.9.9.9</code> &mdash; <?=gettext('Standard Plain UDP/TCP DNS')?></li>
					</ul>
				</div>
			</div>

			<div class="row g-3">
				<div class="col-md-6">
					<label for="bootstrap_dns" class="form-label fw-semibold"><?=gettext('Bootstrap DNS IP Addresses')?></label>
					<textarea class="form-control font-monospace" name="bootstrap_dns" id="bootstrap_dns" rows="2"><?=htmlspecialchars((string)$ts_config['bootstrap_dns'])?></textarea>
					<div class="form-text"><?=gettext('Plain IP addresses used strictly to resolve hostnames in DoH/DoT URLs before encryption initiates.')?></div>
				</div>
				<div class="col-md-6">
					<label for="fallback_dns" class="form-label fw-semibold"><?=gettext('Fallback DNS Resolvers')?></label>
					<textarea class="form-control font-monospace" name="fallback_dns" id="fallback_dns" rows="2"><?=htmlspecialchars((string)$ts_config['fallback_dns'])?></textarea>
					<div class="form-text"><?=gettext('Emergency backup resolvers queried only when all primary encrypted upstreams are completely unreachable.')?></div>
				</div>
			</div>
		</div>
	</div>

	<!-- 3. Cache & Performance -->
	<div class="card mb-3 shadow-sm">
		<div class="card-header bg-light">
			<h2 class="h5 mb-0"><i class="fa-solid fa-gauge-high text-primary me-2"></i><?=gettext('3. DNS Cache & Query Performance')?></h2>
		</div>
		<div class="card-body">
			<div class="row g-3 mb-3">
				<div class="col-md-4">
					<label for="cache_size" class="form-label fw-semibold"><?=gettext('DNS Cache Size (in MB)')?></label>
					<input type="number" min="1" max="1024" class="form-control" name="cache_size" id="cache_size" value="<?=htmlspecialchars((string)$ts_config['cache_size'])?>">
					<div class="form-text"><?=gettext('RAM allocated for in-memory DNS caching (default 4 MB caches ~150,000 domains).')?></div>
				</div>
				<div class="col-md-4">
					<label for="cache_ttl_min" class="form-label fw-semibold"><?=gettext('Minimum TTL Override (Seconds)')?></label>
					<input type="number" min="0" max="86400" class="form-control" name="cache_ttl_min" id="cache_ttl_min" value="<?=htmlspecialchars((string)$ts_config['cache_ttl_min'])?>">
					<div class="form-text"><?=gettext('Forces records to stay cached for at least this duration, reducing query volume to external upstreams (0 = respect upstream TTL).')?></div>
				</div>
				<div class="col-md-4">
					<label for="cache_ttl_max" class="form-label fw-semibold"><?=gettext('Maximum TTL Cap (Seconds)')?></label>
					<input type="number" min="0" max="604800" class="form-control" name="cache_ttl_max" id="cache_ttl_max" value="<?=htmlspecialchars((string)$ts_config['cache_ttl_max'])?>">
					<div class="form-text"><?=gettext('Caps maximum record cache lifetime to prevent stale DNS records when upstream servers change (0 = no cap).')?></div>
				</div>
			</div>

			<div class="form-check form-switch mb-0">
				<input class="form-check-input" type="checkbox" name="cache_optimistic" id="cache_optimistic" <?=$ts_config['cache_optimistic'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="cache_optimistic">
					<?=gettext('Enable Optimistic Caching')?>
				</label>
				<div class="form-text"><?=gettext('Responds immediately with expired cached responses while asynchronously refreshing the record in the background. Yields sub-1ms query latency for frequent requests.')?></div>
			</div>
		</div>
	</div>

	<!-- 4. Security & Anti-Evasion Controls -->
	<div class="card mb-3 shadow-sm">
		<div class="card-header bg-light">
			<h2 class="h5 mb-0"><i class="fa-solid fa-shield-virus text-primary me-2"></i><?=gettext('4. Threat Protection & Anti-Evasion Controls')?></h2>
		</div>
		<div class="card-body">
			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="enable_dnssec" id="enable_dnssec" <?=$ts_config['enable_dnssec'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="enable_dnssec"><?=gettext('DNSSEC Cryptographic Validation')?></label>
				<div class="form-text"><?=gettext('Validates digital signatures on DNS records from authoritative zones to protect against cache poisoning, spoofing, and BGP hijacks.')?></div>
			</div>

			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="safebrowsing_enabled" id="safebrowsing_enabled" <?=$ts_config['safebrowsing_enabled'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="safebrowsing_enabled"><?=gettext('SafeBrowsing Threat Heuristics')?></label>
				<div class="form-text"><?=gettext('Blocks domains identified in live malware, ransomware, command-and-control (C2), and phishing intelligence databases.')?></div>
			</div>

			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="enable_safesearch" id="enable_safesearch" <?=$ts_config['enable_safesearch'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="enable_safesearch"><?=gettext('Enforce SafeSearch')?></label>
				<div class="form-text"><?=gettext('Forces strict SafeSearch filtering on search engines (Google, Bing, DuckDuckGo, Brave, YouTube) at the DNS level.')?></div>
			</div>

			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="enable_parental" id="enable_parental" <?=$ts_config['enable_parental'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="enable_parental"><?=gettext('Parental Control')?></label>
				<div class="form-text"><?=gettext('Blocks adult content, pornography, and gambling domains across the network.')?></div>
			</div>

			<hr class="my-3">

			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="block_doh_canary" id="block_doh_canary" <?=$ts_config['block_doh_canary'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="block_doh_canary"><?=gettext('Block Browser DoH Bypass Canary (Firefox / Chrome / Edge)')?></label>
				<div class="form-text"><?=gettext('Signals browsers via the official canary domain (use-application-dns.net) to disable automatic external encrypted DNS, ensuring all local browser queries respect firewall filtering.')?></div>
			</div>

			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="block_icloud_private_relay" id="block_icloud_private_relay" <?=$ts_config['block_icloud_private_relay'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="block_icloud_private_relay"><?=gettext('Block Apple iCloud Private Relay')?></label>
				<div class="form-text"><?=gettext('Blocks Apple Private Relay domains (mask.icloud.com) to prevent Apple iOS/macOS clients on the LAN from routing around your firewall policies.')?></div>
			</div>

			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="catch_rogue_dns" id="catch_rogue_dns" <?=$ts_config['catch_rogue_dns'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="catch_rogue_dns"><?=gettext('Transparent Rogue DNS Redirection (PF NAT Intercept)')?></label>
				<div class="form-text"><?=gettext('Intercepts and redirects hardcoded client DNS queries (such as Smart TVs querying 8.8.8.8) into Threat Shield.')?></div>
			</div>

			<div class="mb-3">
				<label for="blocking_mode" class="form-label fw-semibold"><?=gettext('DNS Blocking Response Mode')?></label>
				<select class="form-select" name="blocking_mode" id="blocking_mode" onchange="toggleCustomIpFields(this.value)">
					<option value="default" <?=$ts_config['blocking_mode'] === 'default' ? 'selected' : ''?>><?=gettext('Default (Respond with 0.0.0.0 for IPv4 and :: for IPv6)')?></option>
					<option value="nxdomain" <?=$ts_config['blocking_mode'] === 'nxdomain' ? 'selected' : ''?>><?=gettext('NXDOMAIN (Respond with "Non-Existent Domain" status)')?></option>
					<option value="refused" <?=$ts_config['blocking_mode'] === 'refused' ? 'selected' : ''?>><?=gettext('REFUSED (Respond with "Query Refused" status)')?></option>
					<option value="null_ip" <?=$ts_config['blocking_mode'] === 'null_ip' ? 'selected' : ''?>><?=gettext('Null IP (Respond with 0.0.0.0 / ::)')?></option>
					<option value="custom_ip" <?=$ts_config['blocking_mode'] === 'custom_ip' ? 'selected' : ''?>><?=gettext('Custom Sinkhole IP (Redirect blocked traffic to custom IP page)')?></option>
				</select>
			</div>

			<div id="custom_ip_fields" class="row g-3 <?=$ts_config['blocking_mode'] === 'custom_ip' ? '' : 'd-none'?>">
				<div class="col-md-6">
					<label for="blocking_ipv4" class="form-label fw-semibold"><?=gettext('Custom IPv4 Sinkhole')?></label>
					<input type="text" class="form-control font-monospace" name="blocking_ipv4" id="blocking_ipv4" value="<?=htmlspecialchars((string)$ts_config['blocking_ipv4'])?>" placeholder="e.g. 192.168.1.200">
				</div>
				<div class="col-md-6">
					<label for="blocking_ipv6" class="form-label fw-semibold"><?=gettext('Custom IPv6 Sinkhole')?></label>
					<input type="text" class="form-control font-monospace" name="blocking_ipv6" id="blocking_ipv6" value="<?=htmlspecialchars((string)$ts_config['blocking_ipv6'])?>" placeholder="e.g. 2001:db8::1">
				</div>
			</div>
		</div>
	</div>

	<!-- 5. EDNS Client Subnet & Rate Limiting -->
	<div class="card mb-3 shadow-sm">
		<div class="card-header bg-light">
			<h2 class="h5 mb-0"><i class="fa-solid fa-network-wired text-primary me-2"></i><?=gettext('5. EDNS Client Subnet (ECS) & Rate Limiting')?></h2>
		</div>
		<div class="card-body">
			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="edns_client_subnet" id="edns_client_subnet" <?=$ts_config['edns_client_subnet'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="edns_client_subnet"><?=gettext('Enable EDNS Client Subnet (ECS)')?></label>
				<div class="form-text"><?=gettext('Sends truncated client subnet information to upstream authoritative resolvers to allow CDNs (e.g. Akamai, Cloudflare) to route to the closest geographic server. Disable for maximum privacy.')?></div>
			</div>

			<div class="row g-3">
				<div class="col-md-4">
					<label for="ratelimit" class="form-label fw-semibold"><?=gettext('Rate Limit (Queries / Sec)')?></label>
					<input type="number" min="0" max="10000" class="form-control" name="ratelimit" id="ratelimit" value="<?=htmlspecialchars((string)$ts_config['ratelimit'])?>">
					<div class="form-text"><?=gettext('Maximum queries per second allowed per client IP (0 = disabled). Protects against local DoS loops.')?></div>
				</div>
				<div class="col-md-4">
					<label for="rate_limit_subnet_len_ipv4" class="form-label fw-semibold"><?=gettext('IPv4 Subnet Prefix Length')?></label>
					<input type="number" min="1" max="32" class="form-control" name="rate_limit_subnet_len_ipv4" id="rate_limit_subnet_len_ipv4" value="<?=htmlspecialchars((string)$ts_config['rate_limit_subnet_len_ipv4'])?>">
					<div class="form-text"><?=gettext('Subnet mask length for IPv4 rate limiting (default /24).')?></div>
				</div>
				<div class="col-md-4">
					<label for="rate_limit_subnet_len_ipv6" class="form-label fw-semibold"><?=gettext('IPv6 Subnet Prefix Length')?></label>
					<input type="number" min="1" max="128" class="form-control" name="rate_limit_subnet_len_ipv6" id="rate_limit_subnet_len_ipv6" value="<?=htmlspecialchars((string)$ts_config['rate_limit_subnet_len_ipv6'])?>">
					<div class="form-text"><?=gettext('Subnet mask length for IPv6 rate limiting (default /56).')?></div>
				</div>
			</div>
		</div>
	</div>

	<!-- 6. Query Logging & Privacy Compliance -->
	<div class="card mb-4 shadow-sm">
		<div class="card-header bg-light">
			<h2 class="h5 mb-0"><i class="fa-solid fa-database text-primary me-2"></i><?=gettext('6. Query Logging & Privacy Compliance')?></h2>
		</div>
		<div class="card-body">
			<div class="form-check form-switch mb-3">
				<input class="form-check-input" type="checkbox" name="querylog_enabled" id="querylog_enabled" <?=$ts_config['querylog_enabled'] === 'on' ? 'checked' : ''?>>
				<label class="form-check-label fw-semibold" for="querylog_enabled"><?=gettext('Enable Query Logging')?></label>
				<div class="form-text"><?=gettext('Logs DNS requests for real-time live inspection, threat auditing, and analytics.')?></div>
			</div>

			<div class="row g-3 mb-3">
				<div class="col-md-6">
					<label for="querylog_retention" class="form-label fw-semibold"><?=gettext('Query Log Retention Period')?></label>
					<select class="form-select" name="querylog_retention" id="querylog_retention">
						<option value="6" <?=$ts_config['querylog_retention'] === 6 ? 'selected' : ''?>><?=gettext('6 Hours')?></option>
						<option value="24" <?=$ts_config['querylog_retention'] === 24 ? 'selected' : ''?>><?=gettext('24 Hours (1 Day)')?></option>
						<option value="168" <?=$ts_config['querylog_retention'] === 168 ? 'selected' : ''?>><?=gettext('7 Days (1 Week)')?></option>
						<option value="720" <?=$ts_config['querylog_retention'] === 720 ? 'selected' : ''?>><?=gettext('30 Days (1 Month)')?></option>
						<option value="2160" <?=$ts_config['querylog_retention'] === 2160 ? 'selected' : ''?>><?=gettext('90 Days (3 Months - Recommended)')?></option>
					</select>
				</div>
				<div class="col-md-6">
					<div class="form-check form-switch mt-4">
						<input class="form-check-input" type="checkbox" name="anonymize_client_ip" id="anonymize_client_ip" <?=$ts_config['anonymize_client_ip'] === 'on' ? 'checked' : ''?>>
						<label class="form-check-label fw-semibold" for="anonymize_client_ip"><?=gettext('Anonymize Client IP Addresses (GDPR Compliance)')?></label>
						<div class="form-text"><?=gettext('Masks the last octet of client IP addresses (e.g. 192.168.1.0) in query logs and reports.')?></div>
					</div>
				</div>
			</div>

			<div class="mb-0">
				<label for="ignored_domains" class="form-label fw-semibold"><?=gettext('Ignored Domains (Exclude from Query Log)')?></label>
				<textarea class="form-control font-monospace" name="ignored_domains" id="ignored_domains" rows="2" placeholder="healthcheck.internal&#10;*.monitoring.lan"><?=htmlspecialchars((string)$ts_config['ignored_domains'])?></textarea>
				<div class="form-text"><?=gettext('Enter domain names (one per line) to exclude from query logging, useful for filtering out high-frequency internal monitoring chatter.')?></div>
			</div>
		</div>
	</div>

	<div class="d-flex gap-2 mb-4">
		<button type="submit" name="save" class="btn btn-primary px-4"><i class="fa-solid fa-floppy-disk me-2"></i><?=gettext('Save & Apply Settings')?></button>
		<a href="threatshield.php" class="btn btn-outline-secondary"><?=gettext('Cancel')?></a>
	</div>
</form>

<script>
function toggleCustomIpFields(mode) {
	const container = document.getElementById('custom_ip_fields');
	if (container) {
		if (mode === 'custom_ip') {
			container.classList.remove('d-none');
		} else {
			container.classList.add('d-none');
		}
	}
}
</script>

<?php include('foot.inc'); ?>
