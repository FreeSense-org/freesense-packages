<?php
/* Threat map tests; included by run.php (check(), same(), golden() come from there). */

/* ------------------------------------------------------------- filterlog */
$now = strtotime('2026-10-14 13:30:00');
$v4 = 'Oct 14 13:12:32 fw filterlog[62173]: 5,,,4100012345,vtnet0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.7,203.0.113.2,51234,22,0,S,123456,,64240,,mss';
$e = threatshield_map_parse_filterlog($v4, $now);
same('filterlog v4 action', 'block', $e['action'] ?? null);
same('filterlog v4 addresses', ['198.51.100.7', '203.0.113.2', 22, 'tcp', '4100012345'], [$e['src'], $e['dst'], $e['dport'], $e['proto'], $e['tracker']]);
same('filterlog v4 time', strtotime('2026-10-14 13:12:32'), $e['t']);
$v6 = 'Oct 14 13:25:45 FreeSense filterlog[62173]: 2,27,,1000000004,em0,match,block,out,6,0x00,0x00000,1,UDP,17,60,2001:db8::5,2001:db8:ffff::1,546,547,60';
$e = threatshield_map_parse_filterlog($v6, $now);
same('filterlog v6', ['2001:db8::5', '2001:db8:ffff::1', 'udp', 546, 547, 'out'], [$e['src'], $e['dst'], $e['proto'], $e['sport'], $e['dport'], $e['dir']]);
$rfc5424 = '<134>1 2026-10-14T13:12:32.123456+00:00 fw filterlog 62173 - - 7,,,4100000001,vtnet1,match,pass,in,4,0x0,,64,1,0,none,17,udp,60,192.0.2.10,198.51.100.53,40000,53,40';
$e = threatshield_map_parse_filterlog($rfc5424, $now);
same('filterlog RFC 5424 pass', ['pass', 53, strtotime('2026-10-14T13:12:32+00:00')], [$e['action'], $e['dport'], $e['t']]);
$icmp = 'Oct 14 13:00:00 fw filterlog[1]: 9,,,0,vtnet0,match,block,in,4,0x0,,64,1,0,none,1,icmp,84,198.51.100.9,203.0.113.2,request,1234,1';
$e = threatshield_map_parse_filterlog($icmp, $now);
same('filterlog icmp has no ports', ['icmp', 0, 0], [$e['proto'], $e['sport'], $e['dport']]);
$trunc = 'Oct 14 13:00:00 fw filterlog[1]: 9,,,0,vtnet0,match,block,in,4,error=truncated-ip,0x0,,64,1,0,none,6,tcp,40,198.51.100.9,203.0.113.2,1,2';
same('filterlog truncated-ip', '198.51.100.9', threatshield_map_parse_filterlog($trunc, $now)['src'] ?? null);
same('filterlog reject is a block', 'block', threatshield_map_parse_filterlog(str_replace(',block,', ',reject,', $v4), $now)['action'] ?? null);
same('filterlog garbage', null, threatshield_map_parse_filterlog('Oct 14 13:00:00 fw sshd[1]: hello', $now));
same('filterlog scrub ignored', null, threatshield_map_parse_filterlog(str_replace(',block,', ',scrub,', $v4), $now));
$dec = threatshield_map_parse_filterlog(str_replace('Oct 14', 'Dec 31', $v4), strtotime('2027-01-01 00:10:00'));
same('filterlog December line read in January', '2026-12-31', date('Y-m-d', $dec['t']));

/* ------------------------------------------------------------- rule index */
$pf = "@24 pass in quick on lo0 inet6 all flags S/SA keep state label \"descr=pass IPv6 loopback\" ridentifier 1000000001\n"
    . "  [ Evaluations: 1 ]\n"
    . "@40 block drop in log quick on vtnet0 inet from <freesense_geoip_default> to any label \"ThreatShield GeoIP default inbound\" ridentifier 4101234567\n"
    . "@41 block drop in log quick on vtnet0 all label \"id:1234\"\n";
$idx = threatshield_map_parse_pf_rules($pf);
same('rule index trackers', ['1000000001' => 'pass IPv6 loopback', '4101234567' => 'ThreatShield GeoIP default inbound'], $idx['t']);
same('rule index numbers', 'Block rule', $idx['n'][41]);

/* ------------------------------------------------------------- classify */
same('classify geoip', ['kind' => 'geoip', 'policy' => 'default', 'ts' => true], threatshield_map_classify('ThreatShield GeoIP default inbound', 'block'));
same('classify ip list', 'iplist', threatshield_map_classify('ThreatShield IP list shdrop outbound', 'block')['kind']);
same('classify dnsbl', ['dnsbl', 'ssh'], array_values(array_slice(threatshield_map_classify('ThreatShield ssh DNSBL listed', 'block'), 0, 2)));
same('classify bypass', 'DoT/DoQ', threatshield_map_classify('ThreatShield anti-bypass DoT/DoQ', 'block')['policy']);
same('classify flood', 'flood', threatshield_map_classify('ThreatShield flood offender', 'block')['kind']);
same('classify owned pass', 'ts_pass', threatshield_map_classify('ThreatShield ssh pass', 'pass')['kind']);
same('classify user rule', 'fw_pass', threatshield_map_classify('Allow web', 'pass')['kind']);
same('classify default deny', 'fw_block', threatshield_map_classify('Default deny rule IPv4', 'block')['kind']);

/* ------------------------------------------------------------- orient */
$local = ['192.0.2.0/24', '203.0.113.2/32', 'fe80::/10'];
same('orient inbound', ['remote' => '198.51.100.7', 'local' => '203.0.113.2', 'flow' => 'in'], threatshield_map_orient('198.51.100.7', '203.0.113.2', 'in', $local));
same('orient outbound', 'out', threatshield_map_orient('192.0.2.10', '198.51.100.53', 'out', $local)['flow']);
same('orient internal', null, threatshield_map_orient('192.0.2.10', '203.0.113.2', 'in', $local)['remote']);
same('orient transit uses direction', '198.51.100.99', threatshield_map_orient('198.51.100.7', '198.51.100.99', 'out', $local)['remote']);

/* ------------------------------------------------------------- read_new */
$log = $GLOBALS['ts_test_tmp'] . '/filter.log';
file_put_contents($log, "partial line\nline one\nline two\n");
[$lines, $st] = threatshield_map_read_new($log, [], 4096, 15);
same('read_new first run starts near the end, drops a partial line', ['line two'], $lines);
file_put_contents($log, "line three\nhalf", FILE_APPEND);
[$lines, $st] = threatshield_map_read_new($log, $st);
same('read_new returns whole lines only', ['line three'], $lines);
file_put_contents($log, " done\n", FILE_APPEND);
[$lines, $st] = threatshield_map_read_new($log, $st);
same('read_new completes the line', ['half done'], $lines);
file_put_contents($log, "after rotation\n");
[$lines, $st] = threatshield_map_read_new($log, $st);
same('read_new after rotation', ['after rotation'], $lines);
file_put_contents($log, str_repeat("flood line\n", 400), FILE_APPEND);
[$lines, $st, $skipped] = threatshield_map_read_new($log, $st, 1 << 20, 100, 1000);
check('read_new skips a flood backlog', $skipped > 0 && count($lines) < 15);

/* ------------------------------------------------------------- DNS events */
$entries = [
	['time' => '2026-10-14T13:00:03.123456789+00:00', 'client' => '192.0.2.20', 'question' => ['name' => 'ads.example.net', 'type' => 'A'], 'reason' => 'FilteredBlackList',
	 'rules' => [['text' => '||ads.example.net^', 'filter_list_id' => 7]]],
	['time' => '2026-10-14T13:00:02Z', 'client' => '192.0.2.21', 'question' => ['name' => 'www.example.org', 'type' => 'A'], 'reason' => 'NotFilteredNotFound',
	 'answer' => [['type' => 'CNAME', 'value' => 'example.org'], ['type' => 'A', 'value' => '198.51.100.80']]],
	['time' => '2026-10-14T13:00:01Z', 'client' => '192.0.2.21', 'question' => ['name' => 'old.example.org', 'type' => 'A'], 'reason' => 'NotFilteredNotFound',
	 'answer' => [['type' => 'A', 'value' => '198.51.100.81']]],
];
[$dns, $newest, $names] = threatshield_map_querylog_events($entries, strtotime('2026-10-14T13:00:01Z'), ['old.example.org|192.0.2.21']);
same('querylog events skip what was seen', ['dns_allow', 'dns_block'], array_column($dns, 'a'));
same('querylog allowed answer address', '198.51.100.80', $dns[0]['ip']);
same('querylog blocked keeps list id', 7, $dns[1]['list']);
same('querylog newest second', strtotime('2026-10-14T13:00:03Z'), $newest);
[$again] = threatshield_map_querylog_events($entries, $newest, $names);
same('querylog no repeats', [], $again);

/* ------------------------------------------------------------- geo */
$csv = "0.0.0.0,0.255.255.255,ZZ\n192.0.2.0,192.0.2.255,DK\n198.51.100.0,198.51.100.127,US\n198.51.100.128,198.51.100.255,US\n203.0.113.0,203.0.113.255,SE\n"
    . "2001:db8::,2001:db8:0:ffff:ffff:ffff:ffff:ffff,DE\n2001:db8:1::,2001:db8:1:ffff:ffff:ffff:ffff:ffff,FR\n";
$asn = "192.0.2.0,192.0.2.255,64500,\"Example, Net\"\n198.51.100.0,198.51.100.255,64501,Documentation\n";
$cgz = $GLOBALS['ts_test_tmp'] . '/dbip-country-lite-2026-10.csv.gz';
$agz = $GLOBALS['ts_test_tmp'] . '/asn.csv.gz';
file_put_contents($cgz, gzencode($csv));
file_put_contents($agz, gzencode($asn));
$stats = null;
check('geo build refuses a tiny database', !threatshield_geo_build($cgz, $agz, THREATSHIELD_GEO_DIR, $stats));
/* the 1000-record floor guards against truncated downloads; build the
 * fixture with that guard satisfied */
$big = '';
for ($i = 0; $i < 1100; $i++) $big .= sprintf("10.%d.%d.0,10.%d.%d.255,%s\n", intdiv($i, 256), $i % 256, intdiv($i, 256), $i % 256, ($i % 2) ? 'NL' : 'BE');
file_put_contents($cgz, gzencode($big . $csv));
check('geo build', threatshield_geo_build($cgz, $agz, THREATSHIELD_GEO_DIR, $stats));
$g = ThreatShieldGeo::open(THREATSHIELD_GEO_DIR);
same('geo lookup', ['cc' => 'DK', 'asn' => 64500, 'org' => 'Example, Net'], $g->lookup('192.0.2.77'));
same('geo merged neighbours', 'US', $g->lookup('198.51.100.200')['cc']);
same('geo gap is unknown', '', $g->lookup('198.51.101.1')['cc']);
same('geo reserved is unknown', '', $g->lookup('0.1.2.3')['cc']);
same('geo after the last range', '', $g->lookup('250.1.1.1')['cc']);
same('geo IPv6', ['DE', 'FR', ''], [$g->lookup('2001:db8::1')['cc'], $g->lookup('2001:db8:1:5::1')['cc'], $g->lookup('2001:db8:2::1')['cc']]);
same('geo month from the file name', '2026-10', $g->meta()['month']);
same('geo next address', "\xc0\x00\x03\x00", threatshield_geo_bin_next("\xc0\x00\x02\xff"));
same('geo next overflows', null, threatshield_geo_bin_next("\xff\xff"));
same('geo download urls', ['https://download.db-ip.com/free/dbip-asn-lite-2026-01.csv.gz', 'https://download.db-ip.com/free/dbip-asn-lite-2025-12.csv.gz'],
    threatshield_geo_dbip_urls('asn', strtotime('2026-01-15')));
$pos = threatshield_geo_position('198.51.100.7', 'US');
same('geo position is stable per network', $pos, threatshield_geo_position('198.51.100.200', 'US'));
check('geo position near the country', abs($pos[0] - 39.5) < 8 && abs($pos[1] + 97.5) < 25);
same('geo position unknown country', null, threatshield_geo_position('198.51.100.7', 'XX'));
same('iso 6709', [55.667, 12.583], threatshield_geo_parse_iso6709('+5540+01235'));
same('iso 6709 seconds', [-33.864, 151.209], threatshield_geo_parse_iso6709('-335152+1511232'));
$tab = "# comment\nDK\t+5540+01235\tEurope/Copenhagen\nAU\t-3352+15113\tAustralia/Sydney\tNew South Wales\n";
same('zone location', [55.667, 12.583, 'DK'], threatshield_geo_zone_location($tab, 'Europe/Copenhagen'));
same('zone location unknown', null, threatshield_geo_zone_location($tab, 'Mars/Base'));

/* ------------------------------------------------------------- trackers */
$used = [];
$a = threatshield_pf_tracker('ThreatShield GeoIP default inbound', $used);
same('tracker stable', $a, threatshield_pf_tracker('ThreatShield GeoIP default inbound', $used));
check('tracker range', $a >= THREATSHIELD_TRACKER_BASE && $a < THREATSHIELD_TRACKER_BASE + 100000000);
$used = [$a => 'something else'];
same('tracker collision steps on', $a + 1, threatshield_pf_tracker('ThreatShield GeoIP default inbound', $used));
$early = threatshield_pf_early_rules(threatshield_config(), ts_test_ctx());
$labelled = preg_match_all('/label "ThreatShield [^"]*"/', $early);
same('every Threat Shield rule has a tracker', $labelled, preg_match_all('/label "ThreatShield [^"]*" ridentifier 41\d{8}/', $early));
check('pass logging for the map', strpos(threatshield_pf_early_rules(threatshield_config(), ts_test_ctx(['log_pass' => true])), 'pass in log quick on vtnet0') !== false);

/* ------------------------------------------------------------- store and summary */
$db = threatshield_map_db();
check('map store opens', $db instanceof SQLite3);
$t0 = time() - 120;
$ins = $db->prepare('INSERT INTO events (t, a, k, flow, ip, cc, asn, proto, port, iface, rule, pol, local, dom, client) VALUES (:t, :a, :k, :f, :ip, :cc, :asn, :p, :port, \'WAN\', :rule, \'\', \'\', :dom, \'\')');
foreach ([['198.51.100.7', 'US', 'block', 'geoip', 22, 'ThreatShield GeoIP default inbound', ''], ['198.51.100.7', 'US', 'block', 'geoip', 22, 'ThreatShield GeoIP default inbound', ''],
    ['203.0.113.9', 'SE', 'block', 'iplist', 3389, 'ThreatShield IP list shdrop inbound', ''], ['192.0.2.50', 'DK', 'pass', 'fw_pass', 443, 'Allow web', ''],
    ['', '', 'dns_block', 'dns', 0, '||ads.example.net^', 'ads.example.net']] as $i => $r) {
	foreach ([':t' => $t0 + $i, ':a' => $r[2], ':k' => $r[3], ':f' => 'in', ':ip' => $r[0], ':cc' => $r[1], ':asn' => 64501, ':p' => 'tcp', ':port' => $r[4], ':rule' => $r[5], ':dom' => $r[6]] as $k => $v) $ins->bindValue($k, $v);
	$ins->execute();
	$ins->reset();
	$db->exec("INSERT INTO agg (m, a, k, cc, n) VALUES (" . (intdiv($t0, 60) * 60) . ", '{$r[2]}', '{$r[3]}', '{$r[1]}', 1) ON CONFLICT(m, a, k, cc) DO UPDATE SET n = n + 1");
	if ($r[4] > 0) $db->exec("INSERT INTO aggp (h, a, proto, port, n) VALUES (" . (intdiv($t0, 3600) * 3600) . ", '{$r[2]}', 'tcp', {$r[4]}, 1) ON CONFLICT(h, a, proto, port) DO UPDATE SET n = n + 1");
}
$sum = threatshield_map_summary($db, time() - 3600, [], false);
same('summary counters', [3, 1, 1], [$sum['counters']['block'], $sum['counters']['pass'], $sum['counters']['dns_block']]);
same('summary top country', ['cc' => 'US', 'name' => 'United States of America', 'n' => 2], $sum['top']['countries'][0]);
same('summary top source', ['198.51.100.7', 2], [$sum['top']['ips'][0]['ip'], $sum['top']['ips'][0]['n']]);
same('summary ports with service names', ['SSH', 'RDP'], array_column($sum['top']['ports'], 'service'));
same('summary blocked domains', 'ads.example.net', $sum['top']['domains'][0]['dom']);
same('summary mix', ['geoip' => 2, 'iplist' => 1, 'dns' => 1], $sum['mix']);
same('summary Threat Shield only', 0, threatshield_map_summary($db, time() - 3600, ['ts' => true], false)['counters']['pass']);
$evs = threatshield_map_events($db, 0, time() - 3600, ['actions' => ['block']], 50, true);
same('events filtered and masked', ['198.51.100.x', '198.51.100.x', '203.0.113.x'], array_column($evs, 'ip'));
same('events search', 1, count(threatshield_map_events($db, 0, time() - 3600, ['q' => 'shdrop'], 50, false)));
same('dots per source (located only)', 3, count(threatshield_map_dots($db, time() - 3600, [], false)));
same('mask IPv6', '2001:db8:1::x', threatshield_map_mask('2001:db8:1:2::5'));
$db->close();
