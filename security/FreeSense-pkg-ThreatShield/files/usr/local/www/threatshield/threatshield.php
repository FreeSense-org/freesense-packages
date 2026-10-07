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
$assigned_interfaces = threatshield_assigned_interfaces();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save'])) {
	$pconfig = $_POST;

	// Core & Network
	$ts_config['enable'] = isset($pconfig['enable']) ? 'on' : 'off';
	$ts_config['listen_port'] = (int)($pconfig['listen_port'] ?? 53);
	$ts_config['http_port'] = (int)($pconfig['http_port'] ?? 3000);
	$ts_config['dns_coordination_mode'] = in_array($pconfig['dns_coordination_mode'] ?? '', ['primary', 'proxy', 'standalone'], true) ? $pconfig['dns_coordination_mode'] : 'primary';
	$ts_config['interfaces'] = array_values(array_intersect(array_map('strval', (array)($pconfig['interfaces'] ?? ['all'])), array_merge(['all'], array_keys($assigned_interfaces))));
	if (in_array('all', $ts_config['interfaces'], true) || empty($ts_config['interfaces'])) $ts_config['interfaces'] = ['all'];
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
	$ts_config['dns_intercept_interfaces'] = array_values(array_intersect(array_map('strval', (array)($pconfig['dns_intercept_interfaces'] ?? [])), array_keys($assigned_interfaces)));

	// ECS & Rate Limiting
	$ts_config['edns_client_subnet'] = isset($pconfig['edns_client_subnet']) ? 'on' : 'off';
	$ts_config['ratelimit'] = max(0, (int)($pconfig['ratelimit'] ?? 0));
	$ts_config['rate_limit_subnet_len_ipv4'] = max(1, min(32, (int)($pconfig['rate_limit_subnet_len_ipv4'] ?? 24)));
	$ts_config['rate_limit_subnet_len_ipv6'] = max(1, min(128, (int)($pconfig['rate_limit_subnet_len_ipv6'] ?? 56)));
	$ts_config['rate_limit_whitelist'] = trim($pconfig['rate_limit_whitelist'] ?? '');

	// Query Log & Privacy
	$ts_config['querylog_enabled'] = isset($pconfig['querylog_enabled']) ? 'on' : 'off';
	$ts_config['querylog_retention'] = (string)($pconfig['querylog_retention'] ?? '2160');
	$ts_config['anonymize_client_ip'] = isset($pconfig['anonymize_client_ip']) ? 'on' : 'off';
	$ts_config['ignored_domains'] = trim($pconfig['ignored_domains'] ?? '');

	$input_errors = array_merge($input_errors, threatshield_validate_config($ts_config));

	if (empty($input_errors) && threatshield_save_and_apply($ts_config, gettext('Updated FreeSense Threat Shield settings.'), $input_errors)) {
		$savemsg = gettext('Threat Shield settings saved and applied successfully.');
	}
}

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Settings')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];

include('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('general');

$on = function ($key) use ($ts_config) {
	return ($ts_config[$key] ?? 'off') === 'on';
};
/* checkboxes post "on" like the plain HTML checkboxes did */
$switch = function ($name, $title, $description) use ($on) {
	return new Form_Checkbox($name, $title, $description, $on($name), 'on');
};
/* one checkbox per interface, posted as name[] = interface key */
$iface_group = function ($title, $name, array $selected, $with_all = false) use ($assigned_interfaces) {
	$group = new Form_MultiCheckboxGroup($title);
	$choices = $with_all ? ['all' => gettext('All assigned addresses')] + $assigned_interfaces : $assigned_interfaces;
	foreach ($choices as $key => $label) {
		$box = new Form_MultiCheckbox($name . '[]', null, $label, in_array((string)$key, $selected, true), (string)$key);
		$box->setAttribute('id', $name . '_' . $key);
		$group->add($box);
	}
	return $group;
};
$state = COLLAPSIBLE | (!empty($input_errors) ? SEC_OPEN : SEC_CLOSED);

$form = new Form();

$section = new Form_Section('General');
$section->addInput($switch('enable', 'Enable', 'Enable Threat Shield DNS filtering'))
	->setHelp('Runs the DNS filtering engine with encrypted upstreams, blocklists and the GeoIP policy.');
$section->addInput(new Form_Select('dns_coordination_mode', 'DNS mode', $ts_config['dns_coordination_mode'], [
	'primary' => gettext('Primary DNS (recommended): Threat Shield on port 53, DNS Resolver moves to 127.0.0.1:5335'),
	'proxy' => gettext('Proxy: DNS Resolver stays on port 53 and forwards to Threat Shield on 127.0.0.1:5354'),
	'standalone' => gettext('Standalone: Threat Shield answers on port 53, DNS Resolver is turned off'),
]))->setHelp('Primary and proxy mode keep local DHCP host names and domain overrides of the DNS Resolver working.');
$section->addInput(new Form_Input('listen_port', 'DNS port', 'number', (string)$ts_config['listen_port'], ['min' => 1, 'max' => 65535]))
	->setHelp('Port 53 is standard DNS. Change it only for custom proxy setups; primary mode requires 53.');
$section->add($iface_group('Listen on', 'interfaces', array_map('strval', threatshield_normalize_list($ts_config['interfaces']))))
	->setHelp('Pick interfaces to avoid exposing DNS on every address. Proxy mode always listens on loopback only.');
$section->addInput(new Form_Input('http_port', 'Management API port', 'number', (string)$ts_config['http_port'], ['min' => 1, 'max' => 65535]))
	->setHelp('Bound to loopback only; used by this page and the feed updater.');
$form->add($section);

$section = new Form_Section('Upstream DNS');
$section->addInput(new Form_Select('upstream_mode', 'Query strategy', $ts_config['upstream_mode'], [
	'parallel' => gettext('Parallel: ask all upstreams, use the fastest answer (recommended)'),
	'fastest_addr' => gettext('Fastest IP: benchmark upstreams and use the fastest one'),
	'load_balance' => gettext('Load balancing: spread queries across all upstreams'),
]));
$section->addInput(new Form_Textarea('upstreams', 'Upstream servers', (string)$ts_config['upstreams']))
	->setRows(4)->addClass('fs-mono')
	->setHelp('One per line. Encrypted forms: <code>https://dns.quad9.net/dns-query</code> (DoH), <code>tls://1.1.1.1</code> (DoT), ' .
	    '<code>quic://dns.adguard-dns.com</code> (DoQ); a plain IP such as <code>9.9.9.9</code> uses UDP/TCP.');
$section->addInput(new Form_Textarea('bootstrap_dns', 'Bootstrap DNS', (string)$ts_config['bootstrap_dns']))
	->setRows(2)->addClass('fs-mono')
	->setHelp('Plain IP addresses used only to resolve the host names in DoH/DoT/DoQ upstreams.');
$section->addInput(new Form_Textarea('fallback_dns', 'Fallback DNS', (string)$ts_config['fallback_dns']))
	->setRows(2)->addClass('fs-mono')
	->setHelp('Used only when no upstream server answers.');
$form->add($section);

$section = new Form_Section('Filtering');
$section->addInput($switch('enable_dnssec', 'DNSSEC', 'Validate DNSSEC signatures'))
	->setHelp('Protects against spoofed and poisoned DNS answers.');
$section->addInput($switch('safebrowsing_enabled', 'Safe browsing', 'Block malware, phishing and command-and-control domains'));
$section->addInput($switch('enable_safesearch', 'SafeSearch', 'Enforce SafeSearch on search engines and YouTube'));
$section->addInput($switch('enable_parental', 'Parental control', 'Block adult content and gambling domains'));
$section->addInput(new Form_Select('blocking_mode', 'Blocked answer', $ts_config['blocking_mode'], [
	'default' => gettext('Default (0.0.0.0 and ::)'),
	'nxdomain' => gettext('NXDOMAIN (domain does not exist)'),
	'refused' => gettext('REFUSED (query refused)'),
	'null_ip' => gettext('Null IP (0.0.0.0 and ::)'),
	'custom_ip' => gettext('Custom sinkhole IP'),
]))->setHelp('What clients receive for a blocked domain.');
$group = new Form_Group('Sinkhole addresses');
$group->add(new Form_Input('blocking_ipv4', 'IPv4 sinkhole', 'text', (string)$ts_config['blocking_ipv4']))
	->addClass('fs-mono')->setPlaceholder('192.168.1.200')->setHelp('IPv4 address (required)');
$group->add(new Form_Input('blocking_ipv6', 'IPv6 sinkhole', 'text', (string)$ts_config['blocking_ipv6']))
	->addClass('fs-mono')->setPlaceholder('2001:db8::1')->setHelp('IPv6 address (optional)');
$section->add($group);
$form->add($section);

$section = new Form_Section('Anti-evasion');
$section->addInput($switch('block_doh_canary', 'Browser DoH', 'Tell browsers not to use their own DNS-over-HTTPS'))
	->setHelp('Answers the canary domain use-application-dns.net, so Firefox, Chrome and Edge keep using filtered DNS.');
$section->addInput($switch('block_icloud_private_relay', 'iCloud Private Relay', 'Block Apple iCloud Private Relay'))
	->setHelp('Stops Apple devices from routing around the firewall policy through mask.icloud.com.');
$section->addInput($switch('catch_rogue_dns', 'DNS redirection', 'Redirect hard-coded DNS servers to Threat Shield'))
	->setHelp('A NAT rule sends DNS queries to other servers (for example a TV asking 8.8.8.8) to Threat Shield.');
$section->add($iface_group('Redirect on', 'dns_intercept_interfaces', array_map('strval', threatshield_normalize_list($ts_config['dns_intercept_interfaces']))))
	->setHelp('DNS is only redirected on the interfaces selected here.');
$form->add($section);

$section = new Form_Section('Query log');
$section->addInput($switch('querylog_enabled', 'Query log', 'Log DNS queries'))
	->setHelp('Needed for the query log and the top lists on the overview.');
$section->addInput(new Form_Select('querylog_retention', 'Keep log for', (string)$ts_config['querylog_retention'], [
	'6' => gettext('6 hours'),
	'24' => gettext('1 day'),
	'168' => gettext('7 days'),
	'720' => gettext('30 days'),
	'2160' => gettext('90 days (recommended)'),
]));
$section->addInput($switch('anonymize_client_ip', 'Anonymize clients', 'Hide the last part of client IP addresses'))
	->setHelp('For example 192.168.1.0 instead of 192.168.1.23, in the log and the statistics.');
$section->addInput(new Form_Textarea('ignored_domains', 'Ignored domains', (string)$ts_config['ignored_domains']))
	->setRows(2)->addClass('fs-mono')->setAttribute('placeholder', "healthcheck.internal\n*.monitoring.lan")
	->setHelp('One per line; these queries are not logged (for example frequent monitoring checks).');
$form->add($section);

$section = new Form_Section('Cache', 'ts-cache', $state);
$section->addInput(new Form_Input('cache_size', 'Cache size (MB)', 'number', (string)$ts_config['cache_size'], ['min' => 1, 'max' => 1024]))
	->setHelp('Memory for cached answers; 4 MB holds about 150,000 records.');
$group = new Form_Group('TTL limits (s)');
$group->add(new Form_Input('cache_ttl_min', 'Minimum TTL', 'number', (string)$ts_config['cache_ttl_min'], ['min' => 0, 'max' => 86400]))
	->setHelp('Minimum TTL (0 = as received)');
$group->add(new Form_Input('cache_ttl_max', 'Maximum TTL', 'number', (string)$ts_config['cache_ttl_max'], ['min' => 0, 'max' => 604800]))
	->setHelp('Maximum TTL (0 = no cap)');
$section->add($group);
$section->addInput($switch('cache_optimistic', 'Optimistic cache', 'Answer from expired cache entries while refreshing them'))
	->setHelp('Keeps frequent lookups instant; the record is refreshed in the background.');
$form->add($section);

$section = new Form_Section('Rate limiting and client subnet', 'ts-ratelimit', $state);
$section->addInput(new Form_Input('ratelimit', 'Rate limit (queries/s)', 'number', (string)$ts_config['ratelimit'], ['min' => 0, 'max' => 10000]))
	->setHelp('Per client subnet; 0 turns rate limiting off.');
$group = new Form_Group('Subnet prefix length');
$group->add(new Form_Input('rate_limit_subnet_len_ipv4', 'IPv4 prefix', 'number', (string)$ts_config['rate_limit_subnet_len_ipv4'], ['min' => 1, 'max' => 32]))
	->setHelp('IPv4 (default 24)');
$group->add(new Form_Input('rate_limit_subnet_len_ipv6', 'IPv6 prefix', 'number', (string)$ts_config['rate_limit_subnet_len_ipv6'], ['min' => 1, 'max' => 128]))
	->setHelp('IPv6 (default 56)');
$section->add($group);
$section->addInput(new Form_Textarea('rate_limit_whitelist', 'Not rate limited', (string)$ts_config['rate_limit_whitelist']))
	->setRows(2)->addClass('fs-mono')->setAttribute('placeholder', "192.0.2.10\n2001:db8::10")
	->setHelp('One IPv4 or IPv6 address per line.');
$section->addInput($switch('edns_client_subnet', 'Client subnet (ECS)', 'Send EDNS client subnet to upstream servers'))
	->setHelp('Helps CDNs pick a nearby server but reveals part of the client address. Leave off for privacy.');
$form->add($section);

print($form);
?>

<script>
//<![CDATA[
events.push(function () {
	/* the sinkhole addresses only apply to the custom IP answer */
	function sinkhole() {
		hideInput('blocking_ipv4', $('#blocking_mode').val() !== 'custom_ip');
	}
	$('#blocking_mode').on('change', sinkhole);
	sinkhole();

	/* "All assigned addresses" and single interfaces exclude each other */
	var all = document.getElementById('interfaces_all');
	var each = document.querySelectorAll('input[name="interfaces[]"]:not(#interfaces_all)');
	if (all) {
		all.addEventListener('change', function () {
			if (all.checked) each.forEach(function (box) { box.checked = false; });
		});
		each.forEach(function (box) {
			box.addEventListener('change', function () {
				if (box.checked) all.checked = false;
			});
		});
	}
});
//]]>
</script>

<?php include('foot.inc'); ?>
