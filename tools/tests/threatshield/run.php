<?php
/*
 * Threat Shield unit tests: php tools/tests/threatshield/run.php
 * Runs against the stand-ins in stubs/; set UPDATE_GOLDEN=1 to rewrite the
 * expected output files after an intended change.
 */
require __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__, 3) . '/security/FreeSense-pkg-ThreatShield/files/usr/local/pkg/threatshield/threatshield_ui.inc';

$failures = 0;
$count = 0;
function check(string $name, bool $ok, string $detail = ''): void {
	global $failures, $count;
	$count++;
	if (!$ok) {
		$failures++;
		fwrite(STDERR, "FAIL: {$name}" . (($detail !== '') ? "\n      {$detail}" : '') . "\n");
	}
}
function same(string $name, $expected, $actual): void {
	check($name, $expected === $actual, 'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
}
function golden(string $name, string $actual): void {
	$file = __DIR__ . '/golden/' . $name;
	if (getenv('UPDATE_GOLDEN')) {
		@mkdir(dirname($file), 0755, true);
		file_put_contents($file, $actual);
	}
	$expected = is_file($file) ? (string)file_get_contents($file) : '';
	check("golden {$name}", $expected === $actual, 'output differs from ' . $file . ' (run with UPDATE_GOLDEN=1 after an intended change)');
}

/* ---------------------------------------------------------- addresses */
same('normalize host', '192.0.2.7/32', threatshield_cidr_normalize('192.0.2.7'));
same('normalize clears host bits', '192.0.2.0/24', threatshield_cidr_normalize('192.0.2.77/24'));
same('normalize v6', '2001:db8::/32', threatshield_cidr_normalize('2001:db8:1::5/32'));
same('reject junk', null, threatshield_cidr_normalize('300.1.1.1'));
same('reject long prefix', null, threatshield_cidr_normalize('192.0.2.0/33'));
check('contains', threatshield_cidr_contains('192.0.2.0/24', '192.0.2.200'));
check('not contains', !threatshield_cidr_contains('192.0.2.0/25', '192.0.2.200'));
check('family mismatch', !threatshield_cidr_contains('0.0.0.0/0', '2001:db8::1'));
check('overlap', threatshield_cidr_overlaps('10.0.0.0/8', '10.1.0.0/16') && threatshield_cidr_overlaps('10.1.0.0/16', '10.0.0.0/8'));

$list = "; Spamhaus DROP\n198.51.100.0/24 ; SBL1\n# comment\n203.0.113.5\n203.0.113.5/32\n2001:db8:bad::/48 ; v6\nnot-an-ip\n10.0.0.0/8\n";
same('parse list', ['198.51.100.0/24', '203.0.113.5/32', '2001:db8:bad::/48', '10.0.0.0/8'], threatshield_parse_ip_list($list));
same('parse v4 only', ['198.51.100.0/24', '203.0.113.5/32', '10.0.0.0/8'], threatshield_parse_ip_list($list, 4));

$lines = threatshield_build_table_lines(
	['198.51.100.0/24', '203.0.113.5', '10.0.0.0/8', '0.0.0.0/0', '192.0.2.0/24'],
	['198.51.100.7', '192.0.2.0/23'],
	threatshield_protected_ranges());
same('table: private, default route and contained exclusion dropped; hole punched',
    ['198.51.100.0/24', '203.0.113.5/32', '!198.51.100.7/32'], $lines);
same('table: always entries', ['203.0.113.0/24', '10.0.0.0/8'], threatshield_build_table_lines(['203.0.113.0/24'], [], [], ['10.0.0.0/8']));

/* ------------------------------------------------------------ domains */
same('domain plain', 'example.com', threatshield_normalize_domain('Example.COM.'));
same('domain url', 'shop.example.com', threatshield_normalize_domain('https://shop.example.com/cart?x=1'));
same('domain rule', 'ads.example.com', threatshield_normalize_domain('@@||ads.example.com^$important'));
same('domain wildcard', 'example.net', threatshield_normalize_domain('*.example.net'));
same('domain invalid', null, threatshield_normalize_domain('bad domain'));
$allow = [['domain' => 'example.com', 'subdomains' => 'on'], ['domain' => 'exact.example.org', 'subdomains' => 'off']];
same('allowlist parent match', 0, threatshield_allowlist_find($allow, 'cdn.example.com'));
same('allowlist exact only', null, threatshield_allowlist_find($allow, 'a.exact.example.org'));
same('allowlist rules', ['@@||example.com^$important', '@@|exact.example.org^$important'], threatshield_allowlist_rules($allow));

$cfg = ['allowlist' => []];
$m = null;
check('allowlist add', threatshield_allowlist_add($cfg, 'https://www.example.com/x', true, 'manual', '', $m));
check('allowlist dedupe', !threatshield_allowlist_add($cfg, 'www.example.com', true, 'querylog', '', $m));
check('allowlist covered by parent', threatshield_allowlist_add($cfg, 'example.com', true, 'manual', '', $m) && !threatshield_allowlist_add($cfg, 'a.example.com', false, 'manual', '', $m));
$cfg = ['ip_allowlist' => []];
check('ip allow add', threatshield_ip_allowlist_add($cfg, '198.51.100.0/24', 'manual', '', $m));
check('ip allow covered', !threatshield_ip_allowlist_add($cfg, '198.51.100.9', 'manual', '', $m));

/* ---------------------------------------------------------- migration */
$GLOBALS['ts_test_config']['installedpackages']['threatshield'] = require __DIR__ . '/fixtures/config_legacy.php';
$raw = $GLOBALS['ts_test_config']['installedpackages']['threatshield'];
$once = threatshield_migrate_config($raw, 1760000000);
$twice = threatshield_migrate_config($once, 1760000000);
same('migration is idempotent', $once, $twice);
same('migration moves simple allows', ['bank.example', 'exact.example'], array_column($once['allowlist'], 'domain'));
same('migration keeps the comment', 'bank login breaks', $once['allowlist'][0]['comment']);
same('migration exact match', 'off', $once['allowlist'][1]['subdomains']);
same('migration keeps complex rules', "||tracker.example^\n@@||regex.example^\$client=192.0.2.5", $once['custom_rules']);
same('migration feed ids', substr(md5('https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt'), 0, 8), $once['feeds'][0]['id']);
same('migration recognises presets', 'adguard_dns', $once['feeds'][0]['preset']);
same('migration custom level', 'custom', $once['feed_level']);
same('migration keeps new blocks off', 'off', $once['block_dns6_bypass']);
same('migration geoip policy', 'allow_selected', $once['geoip_policies'][0]['action']);
$merged = threatshield_config();
same('merge: defaults present', '1', $merged['dnsbl_quorum']);
same('merge: lists replace defaults', 2, count($merged['feeds']));
threatshield_persist_migration();
same('persist keeps the unbound snapshot', 'on', $GLOBALS['ts_test_config']['installedpackages']['threatshield']['_unbound_state']['managed']);
same('persist marks version', '2', $GLOBALS['ts_test_config']['installedpackages']['threatshield']['config_version']);
same('storage roundtrip', threatshield_config_for_storage(threatshield_config()), threatshield_config_for_storage(threatshield_merge_defaults(threatshield_config_for_storage(threatshield_config()))));
check('storage wraps nested lists', isset(threatshield_config_for_storage(['allowlist' => [['domain' => 'a.example']]])['allowlist']['item'][0]['domain']));

/* ------------------------------------------------------- catalog/levels */
$feeds = threatshield_apply_feed_level([['id' => 'x', 'url' => 'https://lists.example.org/a.txt', 'enabled' => 'on', 'preset' => '']], 'light');
same('level keeps custom feed', 'on', $feeds[0]['enabled']);
same('level adds light presets', ['adguard_dns', 'hagezi_light', 'phishing_army'], array_values(array_filter(array_map(fn($f) => $f['enabled'] === 'on' ? $f['preset'] : null, array_slice($feeds, 1)))));
$feeds = threatshield_apply_feed_level($feeds, 'aggressive');
same('level switches presets off', 'off', $feeds[1]['enabled']);
check('services catalog keeps 1.0 ids', empty(array_diff(['tiktok','discord','youtube','facebook','instagram','roblox','steam','netflix','twitter','twitch','reddit','epic_games','snapchat','telegram'], threatshield_services_catalog())));

/* -------------------------------------------------------------- DNSBL */
same('qname v4', '7.100.51.198.zen.spamhaus.org', threatshield_dnsbl_qname('198.51.100.7', 'zen.spamhaus.org'));
same('qname key', '2.0.0.127.abc123.zen.dq.spamhaus.net', threatshield_dnsbl_qname('127.0.0.2', '{key}.zen.dq.spamhaus.net', 'abc123'));
same('qname v6', 'b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.dnsbl.example',
    threatshield_dnsbl_qname('4321:0:1:2:3:4:567:89ab', 'dnsbl.example'));
check('match range', threatshield_dnsbl_match(['127.0.0.4'], '127.0.0.2-127.0.0.9'));
check('PBL excluded', !threatshield_dnsbl_match(['127.0.0.10'], '127.0.0.2-127.0.0.9'));
check('error code never listed', !threatshield_dnsbl_match(['127.255.255.254'], 'any'));
check('valid match spec', threatshield_dnsbl_valid_match('127.0.0.2, 127.0.0.4-127.0.0.6') && !threatshield_dnsbl_valid_match('127.0.0.x'));
$z = fn($rcode, $answers = [], $error = null, $match = 'any') => ['rcode' => $rcode, 'answers' => $answers, 'error' => $error, 'match' => $match];
same('verdict listed', 'listed', threatshield_dnsbl_verdict(['a' => $z(0, ['127.0.0.2']), 'b' => $z(3)], 1)['verdict']);
same('verdict clean', 'clean', threatshield_dnsbl_verdict(['a' => $z(3), 'b' => $z(3)], 1)['verdict']);
same('verdict quorum not reached', 'clean', threatshield_dnsbl_verdict(['a' => $z(0, ['127.0.0.2']), 'b' => $z(3)], 2)['verdict']);
same('verdict quorum undecided', 'fail', threatshield_dnsbl_verdict(['a' => $z(0, ['127.0.0.2']), 'b' => $z(null, [], 'timeout')], 2)['verdict']);
same('verdict timeout', 'fail', threatshield_dnsbl_verdict(['a' => $z(null, [], 'timeout')], 1)['verdict']);
same('verdict refused resolver', 'fail', threatshield_dnsbl_verdict(['a' => $z(0, ['127.255.255.254'])], 1)['verdict']);
same('verdict one zone down, other clean', 'clean', threatshield_dnsbl_verdict(['a' => $z(3), 'b' => $z(2)], 2)['verdict']);

same('pflog line (FreeBSD 16 tcpdump)', '192.168.27.1',
    threatshield_dnsbl_pflog_source('13:12:32.022402 rule 1..16/0(match): block in on em0: 192.168.27.1.51036 > 192.168.27.141.2222: tcp 0'));
same('pflog match line, IPv6', '2001:db8::7', threatshield_dnsbl_pflog_source('rule 2/0(match): match in on vtnet0: 2001:db8::7.40000 > 2001:db8::1.443: tcp 0'));
same('pflog outbound ignored', null, threatshield_dnsbl_pflog_source('rule 3/0(match): block out on em0: 192.0.2.1.5000 > 198.51.100.7.22: tcp 0'));
$q = threatshield_dns_build_query('2.0.0.127.zen.spamhaus.org', 0x1234);
same('query header', 0x1234, unpack('n', substr($q, 0, 2))[1]);
$answer = pack('nnnnnn', 0x1234, 0x8180, 1, 2, 0, 0) . substr($q, 12)
    . "\xC0\x0C" . pack('nnNn', 1, 1, 60, 4) . inet_pton('127.0.0.2')
    . "\xC0\x0C" . pack('nnNn', 1, 1, 60, 4) . inet_pton('127.0.0.4');
same('parse response', ['id' => 0x1234, 'rcode' => 0, 'answers' => ['127.0.0.2', '127.0.0.4']], threatshield_dns_parse_response($answer));
same('parse nxdomain', 3, threatshield_dns_parse_response(pack('nnnnnn', 7, 0x8183, 1, 0, 0, 0) . substr($q, 12))['rcode']);
same('parse garbage', null, threatshield_dns_parse_response('xx'));

/* ---------------------------------------------------------- schedules */
same('duration', '8h30m', threatshield_hhmm_duration('08:30'));
same('duration midnight', '0s', threatshield_hhmm_duration('00:00'));
same('schedule yaml skips bad days', "  time_zone: \"Local\"\n  mon:\n    start: 9h\n    end: 17h",
    threatshield_schedule_yaml(true, 'Local', [['day' => 'mon', 'start' => '09:00', 'end' => '17:00'], ['day' => 'tue', 'start' => '18:00', 'end' => '08:00']], '  '));

/* ---------------------------------------------------------- validation */
$full = ts_test_load('config_full.php');
same('full fixture validates', [], threatshield_validate_config($full));
$bad = $full;
$bad['inbound_policies'][0]['owned'] = 'off';
check('flood needs ownership', (bool)preg_grep('/flood limits/', threatshield_validate_config($bad)));
$bad = $full;
$bad['inbound_policies'][1]['interfaces'] = ['lan'];
check('inbound policy only on WAN', (bool)preg_grep('/gateway/', threatshield_validate_config($bad)));
$bad = $full;
$bad['geoip_policies'][0]['action'] = 'allow_selected';
$bad['geoip_policies'][0]['interfaces'] = ['lan'];
check('allow-only GeoIP not on LAN', (bool)preg_grep('/lock out/', threatshield_validate_config($bad)));
$bad = $full;
$bad['dns_coordination_mode'] = 'proxy';
check('DNSBL in proxy mode needs a resolver', (bool)preg_grep('/recursive resolver/', threatshield_validate_config($bad)));
$bad = $full;
$bad['dns_redirect_exclude'] = 'printer.lan';
check('redirect exceptions are addresses', (bool)preg_grep('/redirection exceptions/', threatshield_validate_config($bad)));

/* ------------------------------------------------------- XML storage */
/* Base xmlparse.inc always parses these tags as lists (listtags() and
 * listtags_pkg(), FreeSense 1.1): a stored field with one of these names
 * comes back as an array after config.xml is read again. */
$listtags = ['acls', 'additional_files_needed', 'alias', 'aliasurl', 'allowedhostname', 'allowedip', 'apilistener', 'apitoken', 'authserver', 'backuptarget', 'bridged', 'build_port_path', 'ca', 'cacert', 'cert', 'checkipservice', 'class', 'clone', 'columnitem', 'config', 'container', 'crl', 'depends_on_package', 'disk', 'dnsserver', 'dnsupdate', 'domainoverrides', 'dyndns', 'earlyshellcmd', 'element', 'encryption-algorithm-option', 'field', 'fieldname', 'file', 'gateway_group', 'gateway_item', 'gif', 'gre', 'group', 'hash-algorithm-option', 'hosts', 'ifgroupentry', 'igmpentry', 'interface_array', 'key', 'l7rules', 'lagg', 'laggroup', 'lbaction', 'lbpool', 'lbprotocol', 'member', 'menu', 'mobilegroup', 'mobilekey', 'monitor_type', 'mount', 'npt', 'ntpserver', 'onetoone', 'openvpn-client', 'openvpn-csc', 'openvpn-server', 'option', 'package', 'pages', 'passthrumac', 'phase1', 'phase2', 'pipe', 'pkgrepo', 'pool', 'ppp', 'pppoe', 'priv', 'proxyarpnet', 'qinqentry', 'queue', 'radnsserver', 'roll', 'route', 'row', 'rowhelperfield', 'rrddatafile', 'rule', 'schedule', 'servernat', 'servers', 'serversdisabled', 'service', 'shellcmd', 'sshkeyfile', 'staticmap', 'step', 'subqueue', 'switch', 'swport', 'tab', 'template', 'timerange', 'tunnel', 'user', 'vip', 'virtual_server', 'vlan', 'vlangroup', 'voucherdbfile', 'vxlan', 'wgpeer', 'widget', 'winsserver', 'wolentry', 'xmldatafile'];
$stored_keys = [];
$walk = function ($v) use (&$walk, &$stored_keys) {
	if (!is_array($v)) return;
	foreach ($v as $k => $x) {
		if (is_string($k)) $stored_keys[$k] = true;
		$walk($x);
	}
};
$walk(threatshield_config_for_storage(threatshield_merge_defaults(ts_test_load('config_full.php'))));
same('no stored field is an XML list tag', [], array_values(array_intersect(array_keys($stored_keys), $listtags)));

/* ---------------------------------------------------------- pf rules */
$GLOBALS['ts_test_config']['installedpackages']['threatshield'] = require __DIR__ . '/fixtures/config_full.php';
$cfg = threatshield_config();
same('hook ignores filter', '', threatshield_pf_early_rules(['enable' => 'off'] + $cfg, ts_test_ctx()));
same('legacy rules type answers nothing', '', threatshield_generate_rules('rules'));
same('filter type answers nothing', '', threatshield_generate_rules('filter'));
$nat = threatshield_pf_nat_rules($cfg, ts_test_ctx());
golden('nat.txt', $nat);
check('rdr to loopback', strpos($nat, 'rdr pass on vtnet1 inet proto { tcp udp } from any to any port 53 -> 127.0.0.1 port 53') !== false);
check('firewall exempt from rdr', strpos($nat, 'no rdr on vtnet1 inet proto { tcp udp } from any to (vtnet1) port 53') !== false);
same('rdr held back while unhealthy', "# Threat Shield: DNS redirection skipped, the DNS listener is not answering\n", threatshield_pf_nat_rules($cfg, ts_test_ctx(['healthy' => false])));
$proxy = $cfg;
$proxy['dns_coordination_mode'] = 'proxy';
check('proxy rdr target', strpos(threatshield_pf_nat_rules($proxy, ts_test_ctx()), '-> 127.0.0.1 port 5354') !== false);

$early = threatshield_pf_early_rules($cfg, ts_test_ctx());
golden('pfearly.txt', $early);
foreach (explode("\n", trim($early)) as $line) {
	if (preg_match('/label "([^"]*)"/', $line, $mm)) check("label length {$mm[1]}", strlen($mm[1]) <= 63);
	if (preg_match('/^table <([^>]+)>/', $line, $mm)) check("table name length {$mm[1]}", strlen($mm[1]) <= 31);
}
check('DoT blocked inbound on LAN only', strpos($early, 'block in log quick on vtnet1 proto { tcp udp } from ! <threatshield_dns_excl> to ! (self) port 853') !== false
    && strpos($early, 'on vtnet0 proto { tcp udp } from ! <threatshield_dns_excl> to ! (self) port 853') === false);
check('no outbound DoH block', !preg_match('/block out[^\n]*threatshield_doh/', $early));
check('GeoIP IPv4 only by default', strpos($early, 'block in log quick on vtnet0 inet proto tcp from <freesense_geoip_default>') !== false);
check('greylist logs to pflog1', strpos($early, 'block drop in log (to pflog1) quick on vtnet0 proto tcp from ! <threatshield_dnsbl_known_f> to (self) port { 22 } flags S/SA') !== false);
check('deny-on-failure uses known', strpos($early, 'from ! <threatshield_dnsbl_known> to $Servers port { 51820 }') !== false);
check('fail-open is a match rule', strpos($early, 'match in log (to pflog1) on vtnet0 proto tcp from ! <threatshield_dnsbl_known_f> to 192.0.2.80 port { 443 }') !== false);
check('owned pass with limits', strpos($early, 'keep state (max-src-conn 10, max-src-conn-rate 15/5, max-src-states 50, overload <threatshield_flood> flush global)') !== false);
check('reply-to on the WAN gateway', strpos($early, 'pass in quick on vtnet0 reply-to (vtnet0 203.0.113.1) inet proto tcp') !== false);
check('allowlist pass only for owned ports', substr_count($early, 'from <threatshield_ip_allow>') === 1);
$down = threatshield_pf_early_rules($cfg, ts_test_ctx(['dnsbl_up' => false]));
check('daemon down: allow-on-failure gate removed', strpos($down, 'ThreatShield ssh DNSBL pending') === false && strpos($down, 'ThreatShield ssh DNSBL listed') !== false);
check('daemon down: deny-on-failure gate kept', strpos($down, 'ThreatShield vpn DNSBL pending') !== false);
$created = [];
threatshield_pf_early_rules($cfg, ts_test_ctx(['ensure' => function ($f) use (&$created) { $created[] = $f; }]));
check('every table file is ensured', in_array('/var/db/threatshield/geoip/default.cidrs', $created, true) && in_array('/var/db/threatshield/dnsbl/known_f.txt', $created, true));

/* ---------------------------------------------------------------- YAML */
$yaml = threatshield_generate_yaml($cfg, ['bind_hosts' => ['127.0.0.1', '192.0.2.1'], 'domain' => 'home.arpa', 'pause' => ['active' => false, 'until' => 0]]);
golden('adguard.yaml', $yaml);
check('allowlist first in user rules', strpos($yaml, "user_rules:\n  - \"@@||example.com^\$important\"") !== false);
check('allow lists become whitelist_filters', (bool)preg_match('/whitelist_filters:\n  - enabled: true\n    url: "[^"]+"\n    name: "Referral allowlist"/', $yaml));
check('client services are an object', strpos($yaml, "      blocked_services:\n        schedule:\n          time_zone: \"Local\"\n          fri:") !== false);
check('no list after an empty-list marker', !preg_match('/: \[\]\n\s+- /', $yaml));
check('rate limit key AdGuard reads', strpos($yaml, '  ratelimit: 0') !== false && strpos($yaml, 'rate_limit:') === false);
check('DNSSEC key AdGuard reads', strpos($yaml, '  enable_dnssec: true') !== false);
$paused = threatshield_generate_yaml($cfg, ['bind_hosts' => ['127.0.0.1'], 'domain' => 'home.arpa', 'pause' => ['active' => true, 'until' => 1893456000]]);
check('pause survives regeneration', strpos($paused, "protection_enabled: false\n  protection_disabled_until: \"2030-01-01T00:00:00Z\"") !== false);
$ids = threatshield_filter_ids([['id' => 'a', 'url' => 'u1'], ['id' => 'b', 'url' => 'u2']]);
same('filter ids are stable', $ids, threatshield_filter_ids([['id' => 'a', 'url' => 'u1'], ['id' => 'b', 'url' => 'u2']]));

/* ------------------------------------------- local zones sent to Unbound */
$ts_saved_unbound = $GLOBALS['ts_test_config']['unbound'] ?? null;
$ts_saved_dhcpd = $GLOBALS['ts_test_config']['dhcpd'] ?? null;
$GLOBALS['ts_test_config']['unbound'] = [
	'hosts' => [
		['host' => 'nas', 'domain' => 'Corp.Example.net.', 'ip' => '10.0.0.5', 'aliases' => ['item' => [['host' => 'files', 'domain' => 'alias.lab']]]],
		['host' => 'single', 'domain' => 'solo.lab', 'ip' => '10.0.0.6', 'aliases' => ''],
	],
	'domainoverrides' => ['item' => [['domain' => 'ad.corp.local', 'ip' => '10.0.0.2']]],
];
$GLOBALS['ts_test_config']['dhcpd'] = ['lan' => ['domain' => 'lan.zone'], 'opt1' => ['domain' => 'bad domain!'], 'opt2' => ['domain' => 'x"] 1.1.1.1 ["']];
$zones = threatshield_local_zones('Home.Arpa.');
same('local zones: system, host, alias, override and DHCP domains, sorted, bad names dropped',
    ['ad.corp.local', 'alias.lab', 'corp.example.net', 'home.arpa', 'lan.zone', 'solo.lab'], $zones);
$zyaml = threatshield_generate_yaml($cfg, ['bind_hosts' => ['127.0.0.1'], 'domain' => 'home.arpa', 'pause' => ['active' => false, 'until' => 0]]);
foreach ($zones as $zone) {
	check("YAML sends {$zone} to Unbound", strpos($zyaml, "    - \"[/{$zone}/]127.0.0.1:5335\"") !== false);
}
check('YAML still sends the reverse zones to Unbound', strpos($zyaml, '"[/in-addr.arpa/]127.0.0.1:5335"') !== false && strpos($zyaml, '"[/ip6.arpa/]127.0.0.1:5335"') !== false);
same('zones read back from the YAML match the config', $zones, threatshield_yaml_local_zones($zyaml));
same('zones are also read from the single-quoted file AdGuard Home rewrites', $zones,
    threatshield_yaml_local_zones(str_replace('"', "'", $zyaml)));
check('a name with YAML or DNS metacharacters never reaches the YAML', strpos($zyaml, 'bad domain') === false && strpos($zyaml, '5335"') !== false && strpos($zyaml, 'x"]') === false && strpos($zyaml, 'x\\"]') === false);
$GLOBALS['ts_test_config']['unbound'] = [];
$GLOBALS['ts_test_config']['dhcpd'] = [];
same('with no overrides only the system domain is sent', ['home.arpa'], threatshield_local_zones('home.arpa'));
if ($ts_saved_unbound === null) unset($GLOBALS['ts_test_config']['unbound']); else $GLOBALS['ts_test_config']['unbound'] = $ts_saved_unbound;
if ($ts_saved_dhcpd === null) unset($GLOBALS['ts_test_config']['dhcpd']); else $GLOBALS['ts_test_config']['dhcpd'] = $ts_saved_dhcpd;

/* --------------------------------------------- list download progress */
@unlink(THREATSHIELD_PROGRESS_FILE);
unset($GLOBALS['threatshield_progress']);
$alive = fn(int $pid): bool => true;
$dead = fn(int $pid): bool => false;
same('no progress file: nothing to show', ['active' => false, 'finished' => false], threatshield_progress_state());
same('no progress file: the banner stays hidden', 'hidden', threatshield_progress_view(threatshield_progress_state())['kind']);
threatshield_progress_begin(0);
check('nothing to download: no progress file is written', !is_file(THREATSHIELD_PROGRESS_FILE));
threatshield_progress_begin(4);
threatshield_progress_step('feeds', 'Example list');
$st = threatshield_progress_state(null, $alive);
check('a run in progress is reported', $st['active'] && !$st['finished'] && $st['phase'] === 'feeds' && $st['label'] === 'Example list'
    && $st['done'] === 0 && $st['total'] === 4 && $st['percent'] === 0 && !$st['stalled']);
threatshield_progress_item(true);
threatshield_progress_item(false);
$st = threatshield_progress_state(null, $alive);
check('finished downloads are counted, failures too', $st['done'] === 2 && $st['failed'] === 1 && $st['percent'] === 50);
$view = threatshield_progress_view($st);
check('the banner shows the phase and the current list', $view['kind'] === 'running' && $view['title'] === 'Downloading DNS blocklists'
    && $view['detail'] === 'Example list' && $view['done'] === 2 && $view['total'] === 4 && $view['percent'] === 50);
$late = threatshield_progress_state(time() + THREATSHIELD_PROGRESS_STALL_SECONDS + 15, $alive);
check('no sign of life for a while is flagged as stalled', $late['stalled'] && $late['idle'] > THREATSHIELD_PROGRESS_STALL_SECONDS);
$waiting = threatshield_progress_view($late);
check('a stalled download says what it waits for', $waiting['kind'] === 'waiting' && strpos($waiting['detail'], 'Example list') !== false);
threatshield_progress_step('loading');
$late = threatshield_progress_state(time() + 120, $alive);
same('a slow reload into AdGuard Home is not called a stalled download', 'running', threatshield_progress_view($late)['kind']);
$gone = threatshield_progress_state(null, $dead);
check('an updater that died is reported as interrupted', $gone['interrupted'] && !$gone['active'] && $gone['finished']);
same('the interrupted run has its own banner', 'interrupted', threatshield_progress_view($gone)['kind']);

$GLOBALS['ts_test_calls'] = [];
check('a second download is not started while one runs', threatshield_update_start_background() === false && empty($GLOBALS['ts_test_calls']));
threatshield_progress_item(true);
threatshield_progress_item(true);
threatshield_progress_item(true);
check('the count never passes the total', threatshield_progress_state(null, $alive)['done'] === 4);
threatshield_progress_finish();
$st = threatshield_progress_state(null, $alive);
check('a finished run is a result, not a run', !$st['active'] && $st['finished'] && $st['percent'] === 100 && $st['failed'] === 1);
$view = threatshield_progress_view($st);
check('a result with failures is a warning with the counts', $view['kind'] === 'warn' && strpos($view['title'], '1 of 4') !== false);
threatshield_progress_begin(2);
threatshield_progress_item(true);
threatshield_progress_item(true);
threatshield_progress_finish();
$view = threatshield_progress_view(threatshield_progress_state(null, $alive));
check('a clean result says how many lists were downloaded', $view['kind'] === 'done' && strpos($view['title'], '2') !== false);
same('the result goes away after a minute', 'hidden',
    threatshield_progress_view(threatshield_progress_state(time() + THREATSHIELD_PROGRESS_RESULT_SECONDS + 5, $alive))['kind']);
$GLOBALS['ts_test_calls'] = [];
check('a new download starts in the background once none runs', threatshield_update_start_background() === true
    && $GLOBALS['ts_test_calls'] === [['mwexec_bg', THREATSHIELD_UPDATER . ' all force']]);
@unlink(THREATSHIELD_PROGRESS_FILE);
unset($GLOBALS['threatshield_progress']);

$naps = 0;
check('the updater waits for DNS and goes on once names resolve', threatshield_wait_for_dns(30, function () use (&$naps) { return $naps >= 2; }, function () use (&$naps) { $naps++; }) === true && $naps === 2);
check('the updater does not wait for ever when DNS stays down', threatshield_wait_for_dns(0, fn() => false, fn() => null) === false);
check('no waiting when DNS already answers', threatshield_wait_for_dns(30, fn() => true, function () { throw new RuntimeException('slept'); }) === true);

/* ------------------------------------------------------------------ HA */
$GLOBALS['ts_test_config']['installedpackages']['threatshield'] = threatshield_config_for_storage($cfg + ['ha_sync' => 'on']);
$GLOBALS['ts_test_config']['installedpackages']['threatshield']['ha_sync'] = 'on';
same('ha send', ['installedpackages/threatshield'], threatshield_plugin_xmlrpc_send());
$peer = $GLOBALS['ts_test_config']['installedpackages']['threatshield'];
$peer['_unbound_state'] = ['managed' => 'on', 'port' => '9999'];
$peer['custom_rules'] = '||peer.example^';
$GLOBALS['ts_test_config']['installedpackages']['threatshield']['_unbound_state'] = ['managed' => 'on', 'port' => '53'];
$r = threatshield_plugin_xmlrpc_recv(['installedpackages' => ['threatshield' => $peer]]);
same('ha recv changes', true, $r['xmlrpc_recv_result'] ?? null);
same('ha recv keeps the local unbound snapshot', '53', $r['installedpackages/threatshield']['_unbound_state']['port'] ?? null);
same('ha recv takes the peer rules', '||peer.example^', $r['installedpackages/threatshield']['custom_rules'] ?? null);
$peer['ha_sync'] = 'off';
same('ha recv ignores peers without sync', [], threatshield_plugin_xmlrpc_recv(['installedpackages' => ['threatshield' => $peer]]));

/* ------------------------------------------------------------ threat map */
require __DIR__ . '/map_tests.php';

echo ($failures === 0) ? "Threat Shield unit tests passed: {$count} checks.\n" : "Threat Shield unit tests: {$failures} of {$count} checks failed.\n";
exit($failures === 0 ? 0 : 1);
