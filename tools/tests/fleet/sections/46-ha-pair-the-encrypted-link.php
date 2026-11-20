<?php
/* Fleet controller tests: HA pair: the encrypted link. Loaded by ../run.php (shares its variables). */

$hn = fleet_ha_link_net(array(array('10.254.0.1', 24), array('10.1.0.2', 24)));
check(($hn === array('10.254.1.0', '10.254.1.1', '10.254.1.2')) && (fleet_ha_link_net(array(array('10.254.0.0', 15))) === null) && (fleet_ha_link_net(array())[0] === '10.254.0.0') &&
    (fleet_ha_link_net(array(array('10.254.0.2', 32)))[0] === '10.254.0.4'),
    'the encrypted link takes the first free /30 of 10.254.0.0/16, skipping every network either firewall uses');
$hl_a = array('api_level' => 15) + $hfa;
$hl_b = array('api_level' => 15) + $hfb;
$hl_in = array('sync_mode' => 'tunnel', 'sync_iface' => '', 'link_host_p' => '203.0.113.5', 'link_port_p' => '51831', 'link_host_s' => '', 'link_port_s' => '51831') + $hin;
list($hl_err, $hl_plan) = fleet_ha_setup_plan($hl_in, $hl_a, $hl_b);
check(empty($hl_err) && ($hl_plan['sync_mode'] === 'tunnel') && ($hl_plan['link']['endpoint_p'] === '203.0.113.5:51831') && ($hl_plan['link']['endpoint_s'] === '') &&
    ($hl_plan['primary_sync_ip'] === '10.254.0.1') && ($hl_plan['secondary_sync_ip'] === '10.254.0.2') && ($hl_plan['sync_iface'] === '') && ($hl_plan['sync_bits'] === 30),
    'a tunnel plan: the link network and both addresses, no sync interface yet (the firewalls make it)');
list($hl_err) = fleet_ha_setup_plan($hl_in, $hfa, $hl_b);
check((count($hl_err) === 1) && (strpos($hl_err[0], 'REST API level 15') !== false), 'the encrypted link needs REST API level 15 on both firewalls');
list($hl_err) = fleet_ha_setup_plan(array('link_host_p' => '') + $hl_in, $hl_a, $hl_b);
check((count($hl_err) === 1) && (strpos($hl_err[0], 'At least one firewall') !== false), 'the encrypted link needs one firewall the other can reach');
list($hl_err) = fleet_ha_setup_plan(array('link_host_s' => 'a b', 'link_port_p' => '70000') + $hl_in, $hl_a, $hl_b);
check((count($hl_err) === 2), 'the encrypted link refuses a bad host and a bad port');
$hl_p = fleet_ha_link_body($hl_plan, true, 'KEY');
$hl_s = fleet_ha_link_body($hl_plan, false, 'KEY');
check(($hl_p['address'] === '10.254.0.1') && ($hl_p['peer_address'] === '10.254.0.2') && ($hl_p['peer_endpoint'] === '') && ($hl_p['keepalive'] === 0) &&
    ($hl_s['address'] === '10.254.0.2') && ($hl_s['peer_endpoint'] === '203.0.113.5:51831') && ($hl_s['keepalive'] === 25) && ($hl_s['bits'] === 30),
    'the end that has no address waits; the other connects to it and keeps the link open');
$hl_r = fleet_ha_link_rule_bodies($hl_plan, true);
check((count($hl_r) === 2) && ($hl_r[0]['interface'] === 'wan') && ($hl_r[0]['dstbeginport'] === '51831') && ($hl_r[0]['statetype'] === 'none') && (strpos($hl_r[0]['descr'], FLEET_HA_MARK) === 0) &&
    ($hl_r[1]['direction'] === 'out') && !empty($hl_r[1]['floating']) && ($hl_r[1]['srcbeginport'] === '51831') && ($hl_r[1]['statetype'] === 'none') && ($hl_r[1]['interface'] === array('wan')) &&
    (count(fleet_ha_link_rule_bodies($hl_plan, false)) === 2),
    'the packets of the link get stateless rules on the WAN, in and out, on both firewalls (also the one that connects out), marked as Fleet rules');
check((fleet_ha_sync_risk($hl_plan) === null) && (fleet_ha_sync_risk(array('sync_mode' => 'interface', 'sync_iface' => 'wan') + $hl_plan) === 'wan'), 'state sync over the encrypted link is not a risk');
check((fleet_halink_endpoint_of('fw.example.net', 51831) === 'fw.example.net:51831') && (fleet_halink_endpoint_of('203.0.113.5', 1) === '203.0.113.5:1') && (fleet_halink_endpoint_of('a b', 1) === null),
    'a link address is an IPv4 address or a DNS name');

$hrb = fleet_ha_rule_bodies($hplan, 8443);
check((count($hrb) === 3) && ($hrb[1]['proto'] === 'pfsync') && ($hrb[1]['src'] === '10.9.0.0') && ($hrb[1]['srcmask'] === '30') && ($hrb[2]['src'] === '10.9.0.1') &&
    ($hrb[2]['dsttype'] === 'opt1ip') && ($hrb[2]['dstbeginport'] === '8443') && (strpos($hrb[2]['descr'], FLEET_HA_MARK) === 0),
    'the sync interface rules are the same on both and right on either (HA sync copies them): pfsync from the sync network, configuration sync from the primary');
check($hrb[0]['dsttype'] === 'network' && $hrb[0]['dst'] === '10.9.0.0' && $hrb[1]['dsttype'] === 'network' && $hrb[1]['dst'] === '10.9.0.0' && $hrb[1]['dstmask'] === '30', 'the pfsync rules go only to the sync network, not to any address');
check(($hrb[0]['direction'] === 'out') && !empty($hrb[0]['floating']) && !empty($hrb[0]['quick']) && ($hrb[0]['interface'] === array('opt1')) && ($hrb[0]['proto'] === 'pfsync') &&
    ($hrb[0]['statetype'] === 'none') && ($hrb[1]['statetype'] === 'none') && !empty($hrb[0]['allowopts']) && !empty($hrb[1]['allowopts']) && !empty($hrb[2]['nopfsync']),
    'the pfsync rules are stateless and allow IP options, in and out (an outgoing floating rule too), or pfsync syncs the states of its own packets again and again');

$hsg = fleet_ha_suggest($hfa['ifaces'], $hfb['ifaces']);
check(($hsg['sync_iface'] === 'opt1') && ($hsg['vips'] === array(array('iface' => 'lan', 'address' => '10.1.0.1'))) && empty(fleet_ha_setup_plan(array('primary' => 'a', 'secondary' => 'b') + $hsg, $hfa, $hfb)[0]) &&
    (fleet_ha_suggest($hfa['ifaces'], fleet_ha_ifaces(array(array('name' => 'lan', 'ipaddr' => '10.7.0.3', 'subnet' => '255.255.255.0')))) === null),
    'HA setup suggests the sync interface and the first free address of the other shared networks; none when nothing is shared');
$hdup = fleet_ha_ifaces(array(array('name' => 'lan', 'ipaddr' => '10.9.0.1', 'subnet' => '255.255.255.248'), array('name' => 'opt1', 'description' => 'HASYNC', 'ipaddr' => '10.9.0.1', 'subnet' => '255.255.255.248')));
$hdup2 = fleet_ha_ifaces(array(array('name' => 'lan', 'ipaddr' => '10.9.0.2', 'subnet' => '255.255.255.248'), array('name' => 'opt1', 'description' => 'HASYNC', 'ipaddr' => '10.9.0.2', 'subnet' => '255.255.255.248')));
check(fleet_ha_suggest($hdup, $hdup2)['vips'] === array(array('iface' => 'opt1', 'address' => '10.9.0.3')),
    'two assignments of one port on the sync network count as one network');
$hfc = array('label' => 'C', 'ifaces' => fleet_ha_ifaces(array(array('name' => 'lan', 'ipaddr' => '10.5.0.2', 'subnet' => '255.255.255.0')))) + $hfa;
$hcand = fleet_ha_candidates(array('b' => $hfb, 'c' => $hfc, 'a' => $hfa, 'p' => array('in_pair' => true) + $hfa));
check((count($hcand) === 1) && ($hcand[0]['primary'] === 'a') && ($hcand[0]['secondary'] === 'b'),
    'pairing a group pairs managed firewalls sharing a network (lower name primary), never one already paired or alone');

/* Standby controller. */
$sbtok = random_bytes(32);
$sbkey = random_bytes(32);
$sbcode = fleet_standby_code_make('https://ctl.example.net:8443', str_repeat('ab', 32), $sbtok, $sbkey);
$sbc = fleet_standby_code_read(" {$sbcode}\n");
check(($sbc !== null) && ($sbc['url'] === 'https://ctl.example.net:8443') && ($sbc['token'] === $sbtok) && ($sbc['key'] === $sbkey) && (strpos($sbcode, 'FSB1-') === 0) &&
    (fleet_standby_code_read('FSB1-' . fleet_standby_b64u('{"u":"http://x:1","f":"' . str_repeat('ab', 32) . '"}')) === null) && (fleet_standby_code_read('hello') === null),
    'a standby pairing code carries the URL, certificate fingerprint, token and key, and nothing else reads as one');
$sbsealed = fleet_standby_seal('copy', $sbkey);
check((fleet_standby_unseal($sbsealed, $sbkey) === 'copy') && (fleet_standby_unseal($sbsealed, random_bytes(32)) === null) && (fleet_unseal($sbsealed, $sbkey) === null),
    'a standby copy opens only with the pairing key (and is not a store secret)');
check((fleet_standby_endpoints_want('a:1', 'b:1') === array('a:1', 'b:1')) && (fleet_standby_endpoints_want('a:1', '') === array('a:1')) && (fleet_standby_endpoints_want('a:1', 'a:1') === array('a:1')),
    'firewalls know this controller first, then the standby');
$sbw = array('a:1', 'b:1');
check((fleet_standby_box_action(array('api_level' => 12), $sbw, 0) === 'skip') &&
    (fleet_standby_box_action(array('api_level' => 13, 'controller_endpoints' => $sbw, 'controller_epoch' => 2), $sbw, 2) === 'ok') &&
    (fleet_standby_box_action(array('api_level' => 13, 'controller_endpoints' => array('a:1'), 'controller_epoch' => 2), $sbw, 2) === 'push') &&
    (fleet_standby_box_action(array('api_level' => 13, 'controller_endpoints' => $sbw, 'controller_epoch' => 1), $sbw, 2) === 'push') &&
    (fleet_standby_box_action(array('api_level' => 13, 'controller_endpoints' => $sbw, 'controller_epoch' => 3), $sbw, 2) === 'newer'),
    'each firewall\'s controller endpoints are kept current, and one that saw a newer controller means this one was replaced');
$sbp = array('role' => 'standby');
$sbs = array('takeover' => 'auto', 'auto_minutes' => 10, 'snapshot' => array('created' => 1), 'last_alive' => 1000);
check(!fleet_standby_takeover_due($sbp, $sbs, 1000 + 599) && fleet_standby_takeover_due($sbp, $sbs, 1000 + 600) &&
    !fleet_standby_takeover_due($sbp, array('takeover' => 'manual') + $sbs, 99999) && !fleet_standby_takeover_due($sbp, array('snapshot' => null) + $sbs, 99999) &&
    !fleet_standby_takeover_due($sbp, array('last_alive' => 0) + $sbs, 99999) && !fleet_standby_takeover_due(array('role' => 'primary'), $sbs, 99999),
    'automatic takeover only on a standby with a copy, set to automatic, after the primary answered once and was silent long enough');
check((fleet_standby_url_host('https://[2001:db8::5]:8443') === '2001:db8::5') && (fleet_standby_url_host('https://ctl.example.net:8443') === 'ctl.example.net'),
    'the primary\'s host from its URL');
$sbb = array('format' => 'freesense-fleet-self-v1', 'created' => 5, 'schema' => FLEET_DB_SCHEMA, 'db' => '', 'keys' => array(), 'settings' => array(),
    'master' => base64_encode(random_bytes(32)), 'epoch' => 4);
$sbo = fleet_standby_open(fleet_standby_seal(gzencode(json_encode($sbb)), $sbkey), $sbkey);
check(is_array($sbo) && ($sbo[1]['epoch'] === 4) && ($sbo[1]['created'] === 5) && is_string(fleet_standby_open(fleet_standby_seal(gzencode(json_encode(array('master' => '') + $sbb)), $sbkey), $sbkey)) &&
    is_string(fleet_standby_open('s1:x:y:z', $sbkey)), 'a standby copy opens to the bundle with the master key and epoch; anything else is refused');
$sbpoll = (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/sbin/freesense-fleet-poll');
$sbix = (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg/fleet/enroll/index.php');
check((strpos($sbpoll, 'fleet_standby_endpoints_tick()') !== false) && (strpos($sbpoll, 'fleet_standby_fence_tick(') !== false) && (strpos($sbix, 'fleet_standby_handle(') !== false) &&
    (strpos(fleet_enroll_nginx_conf(array(array('10.0.0.1', 8443)), '/fleet/tls.pem'), 'location ^~ /fleet/standby/') !== false),
    'the poll keeps the standby copy and the firewalls\' endpoints current, and the enrollment port serves the standby');
/* Controller access. */
check((fleet_access_cidr(' 203.0.113.5 ') === '203.0.113.5') && (fleet_access_cidr('203.0.113.0/24') === '203.0.113.0/24') && (fleet_access_cidr('203.0.113.5/32') === '203.0.113.5') &&
    (fleet_access_cidr('2001:db8::/48') === '2001:db8::/48') && (fleet_access_cidr('203.0.113.0/33') === null) && (fleet_access_cidr('x') === null) && (fleet_access_cidr('1.2.3.4/0') === null),
    'the allowed list takes addresses and networks, IPv4 and IPv6');
check(fleet_access_in('203.0.113.77', '203.0.113.0/24') && !fleet_access_in('203.0.114.1', '203.0.113.0/24') && fleet_access_in('203.0.113.5', '203.0.113.5') &&
    fleet_access_in('2001:db8:0:1::9', '2001:db8::/48') && !fleet_access_in('2001:db9::1', '2001:db8::/48') && fleet_access_in('10.1.2.3', '10.0.0.0/9') && !fleet_access_in('10.200.0.1', '10.0.0.0/9') &&
    !fleet_access_in('203.0.113.5', '2001:db8::/48'), 'an address is in a network only within its mask');
$acd = fleet_access_from(array());
check(($acd['enroll'] === 'any') && ($acd['tunnel'] === 'any') && $acd['firewalls'] && $acd['block'] && ($acd['block_after'] === 5) && ($acd['block_minutes'] === 60),
    'access defaults: open as before, firewalls allowed automatically, wrong keys blocked after 5 for an hour');
$acl = fleet_access_from(array('enroll' => 'list', 'entries' => array(array('cidr' => '198.51.100.0/24', 'note' => 'Office'), array('cidr' => 'bad'))));
$alw = fleet_access_allowed($acl, array('Shop' => '203.0.113.9'), array(array('ip' => '192.0.2.4', 'label' => 'New', 'expires' => 2000), array('ip' => '192.0.2.5', 'label' => 'Old', 'expires' => 500)),
    array('192.0.2.200' => 'Standby controller'), 1000);
check(($alw === array('198.51.100.0/24' => 'Office', '203.0.113.9' => 'Firewall Shop', '192.0.2.4' => 'Invitation New', '192.0.2.200' => 'Standby controller')) &&
    !isset(fleet_access_allowed(array('firewalls' => false) + $acl, array('Shop' => '203.0.113.9'), array(), array(), 1000)['203.0.113.9']),
    'the allowed list: entries, firewalls\' addresses, open invitations and the standby (an expired invitation is gone)');
$ars = array('enable' => true, 'enroll_port' => 8443, 'wg_port' => 51830);
$ars = fleet_ctl_settings_from(array('enable' => 'on'));
$arl = fleet_access_rule_set($ars, array('wan' => 8443, 'lan' => 8443), $acl, $alw + array('2001:db8::/48' => 'v6'), array('198.18.0.9' => 5000, '198.18.0.10' => 10), 1000);
$arr = array_column($arl['rules'], null, 'descr');
check((count($arl['rules']) === 4) && ($arl['rules'][0]['type'] === 'block') && ($arl['rules'][1]['type'] === 'block') &&
    ($arr['FreeSense Fleet: enrollment']['interface'] === 'wan,lan') && ($arr['FreeSense Fleet: enrollment']['floating'] === 'yes') &&
    ($arr['FreeSense Fleet: enrollment']['source']['address'] === 'FleetEnroll') && ($arr['FreeSense Fleet: enrollment']['destination'] === array('network' => '(self)', 'port' => '8443')) &&
    ($arr['FreeSense Fleet: tunnel']['protocol'] === 'udp') && ($arr['FreeSense Fleet: tunnel']['destination']['port'] === '51830') &&
    empty(array_filter($arl['rules'], function ($r) { return $r['fleet_auto'] !== '1'; })),
    'Fleet\'s rules: visible floating rules on the chosen interfaces, blocked first, marked as Fleet\'s');
check(($arl['aliases']['FleetBlocked']['address'] === '198.18.0.9') && ($arl['aliases']['FleetTunnel']['address'] === '0.0.0.0/0 ::/0') &&
    ($arl['aliases']['FleetEnroll']['address'] === '198.51.100.0/24 203.0.113.9 192.0.2.4 192.0.2.200 2001:db8::/48') &&
    (fleet_access_rule_set($ars, array('wan' => 8443), array('open_until' => 2000) + $acl, array(), array(), 1000)['aliases']['FleetEnroll']['address'] === '0.0.0.0/0 ::/0') &&
    (fleet_access_rule_set($ars, array('wan' => 8443), $acl, array(), array(), 1000)['aliases']['FleetEnroll']['address'] === ''),
    'the aliases: anyone or only the allowed list per port (nothing when it is empty), open for joining lets anyone join for a while');
check((fleet_access_rule_set(array('enable' => false) + $ars, array('wan' => 8443), $acl, $alw, array(), 1000) === array('aliases' => array(), 'rules' => array())) &&
    (fleet_access_rule_set(array('rules_manual' => true) + $ars, array('wan' => 8443), $acl, $alw, array(), 1000)['rules'] === array()) &&
    (fleet_access_rule_set($ars, array(), $acl, $alw, array(), 1000)['rules'] === array()),
    'no rules while off, when the admin opens the ports by hand, or with no interface');
$arp = fleet_access_rule_set($ars, array('wan' => 8443, 'lan' => 9443, 'opt1' => 8443), $acl, $alw, array(), 1000)['rules'];
check((count($arp) === 6) && (array_column($arp, 'type') === array('block', 'block', 'block', 'pass', 'pass', 'pass')) &&
    ($arp[0]['interface'] === 'wan,opt1') && ($arp[1]['interface'] === 'lan') && ($arp[1]['destination']['port'] === '9443') && ($arp[5]['interface'] === 'wan,lan,opt1') &&
    (count(array_unique(array_column($arp, 'tracker'))) === 6),
    'connection points with different ports: an enrollment rule pair per port, the tunnel on all of them');
$amine = array(array('descr' => 'new fleet', 'fleet_auto' => '1'));
check(fleet_access_merge(array(array('descr' => 'a'), array('descr' => 'old fleet', 'fleet_auto' => '1'), array('descr' => 'b')), $amine, true) ===
    array(array('descr' => 'new fleet', 'fleet_auto' => '1'), array('descr' => 'a'), array('descr' => 'b')) &&
    fleet_access_merge(array(array('descr' => 'a'), array('descr' => 'old', 'fleet_auto' => '1')), array(), false) === array(array('descr' => 'a')) &&
    (fleet_access_tracker('x') === fleet_access_tracker('x')) && (fleet_access_tracker('x') !== fleet_access_tracker('y')),
    'Fleet replaces only its own rules (removed when it has none), and keeps their trackers');
fleet_access_fail_hit('198.18.0.1', 500, 99, 10);
fleet_access_fail_hit('198.18.0.2', 10, 99, 10);
$afh = fleet_access_fail_hit('198.18.0.1', 990, 99, 10);
check(($afh === array(2, false)) && (fleet_db()->query("SELECT COUNT(*) FROM access_fails WHERE ip = '198.18.0.2'")->fetchColumn() == 0) &&
    (fleet_access_fail_hit('198.18.0.1', 1000 + FLEET_ACCESS_WINDOW + 1, 99, 10) === array(1, false)),
    'wrong keys count within ten minutes; old ones are forgotten');
check((fleet_access_fail_hit('198.18.0.9', 2000, 2, 10) === array(1, false)) && (fleet_access_fail_hit('198.18.0.9', 2001, 2, 10) === array(2, true)) &&
    (fleet_access_blocked()['198.18.0.9'] === 2001 + 600) && (fleet_access_fail_hit('198.18.0.9', 2002, 2, 10) === array(1, false)) &&
    (fleet_access_fail_hit('198.18.0.9', 2003, 2, 10) === array(2, false)) && (fleet_access_blocked()['198.18.0.9'] === 2001 + 600),
    'enough wrong keys block the address once (its count restarts; a block in force is not extended)');
fleet_db()->exec("DELETE FROM access_blocked; DELETE FROM access_fails");
check((fleet_access_endpoints_parse(array("k1=\t203.0.113.9:51820", "k2=\t[2001:db8::7]:4000", "k3=\t(none)")) === array('k1=' => '203.0.113.9', 'k2=' => '2001:db8::7')),
    'the addresses firewalls connect from, read from the tunnel');
check((fleet_access_reach_kind(array('203.0.113.1'), array('203.0.113.1', '10.0.0.1'))[0] === 'local') && (fleet_access_reach_kind(array('198.51.100.1'), array('10.0.0.1'))[0] === 'forward') &&
    (fleet_access_reach_kind(array(), array('10.0.0.1'))[0] === 'unresolved'), 'the public address is on this controller, or forwarded to it');
$aix = (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg/fleet/enroll/index.php');
check((substr_count($aix, 'fleet_access_failed(') === 2) && (strpos((string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg/fleet.inc'), 'fleet_access_tailnet_rules(') !== false),
    'wrong keys at the enrollment port and the standby route count; the filter hook adds the tailnet rules');
$cpb = array('method' => 'both', 'iface' => 'opt1', 'paths' => array(array('method' => 'direct', 'address' => '10.0.0.2', 'ok' => true), array('method' => 'tailscale', 'address' => '100.64.0.2', 'ok' => false)));
check((fleet_conn_paths(null) === array()) && (fleet_conn_paths(array('method' => 'wireguard')) === array()) && (count(fleet_conn_paths($cpb)) === 2) &&
    (fleet_conn_paths(array('method' => 'tailscale', 'address' => 'x'))[0]['method'] === 'tailscale') && (FLEET_CONN_PATHS['both'] === array('direct', 'tailscale')) &&
    !fleet_conn_pending(array('want' => array('both', 'opt1'), 'state' => $cpb)) && fleet_conn_pending(array('want' => array('both', 'lan'), 'state' => $cpb)) &&
    fleet_conn_pending(array('want' => array('direct', 'opt1'), 'state' => $cpb)) && (fleet_conn_cfg_from(array('conn_method' => 'both', 'conn_iface' => 'opt1'), true)['method'] === 'both') && !empty(fleet_conn_requirements('both')),
    'a firewall can use Direct and Tailscale together: both paths in order, then the tunnel');

/* Dashboard widget. */
check((fleet_widget_cfg(array()) === array('parts' => array_keys(FLEET_WIDGET_PARTS), 'group' => 0, 'rows' => 5)) &&
    (fleet_widget_cfg(array('fleet_parts' => 'problems,bogus,health', 'fleet_group' => '3', 'fleet_rows' => '10')) === array('parts' => array('health', 'problems'), 'group' => 3, 'rows' => 10)) &&
    (fleet_widget_cfg(array('fleet_parts' => '', 'fleet_rows' => '7'))['parts'] === array()) && (fleet_widget_cfg(array('fleet_rows' => '7'))['rows'] === 5),
    'widget settings: all parts by default, unknown parts and row counts are ignored, every part can be off');
$wb = function ($id, $state, $extra = array()) { return $extra + array('id' => $id, 'label' => strtoupper($id), 'state' => $state, 'problem' => '', 'policy' => 0, 'rollback' => true, 'update' => null); };
$wboxes = array($wb('a', 'online', array('update' => array('info', 'Update: 1.2.1'))), $wb('b', 'online', array('rollback' => false)), $wb('c', 'degraded'),
    $wb('d', 'offline', array('problem' => 'FLEET-E105: No route (x). Check it.')), $wb('e', 'online', array('policy' => 2)), $wb('f', 'online'));
$wp = fleet_widget_problems($wboxes, array(array('nodes' => array('a', 'f'), 'problem' => array('split', 'x')), array('nodes' => array('b', 'e'), 'problem' => null)),
    array('a' => 'A', 'f' => 'F'), 10);
check((array_column($wp, 'label') === array('D', 'A + F', 'C', 'E', 'B', 'A')) && ($wp[0]['badge'] === array('block', 'Offline')) && ($wp[0]['text'] === 'No route (x)') &&
    ($wp[1]['badge'][1] === 'Split-brain') && ($wp[3]['text'] === '2 policy rules fail') && ($wp[5]['link'] === '/fleet/fleet_updates.php') &&
    (count(fleet_widget_problems($wboxes, array(), array(), 3)) === 3) && (fleet_widget_problems(array($wb('f', 'online')), array(), array(), 5) === array()),
    'widget problem list: offline, HA problems, degraded, policy, no rollback, updates, worst first and cut to the rows; a healthy fleet lists nothing');
$wpl = (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/pkg-plist') . (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/Makefile');
$wxml = (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg/fleet.xml');
check((substr_count($wpl, 'fleet.widget.json') === 2) && (substr_count($wpl, 'fleet.js') >= 2) && (strpos($wpl, 'widgets/widgets/') === false) &&
    (strpos($wxml, '<type>plugin_restapi</type>') !== false) && function_exists('fleet_plugin_restapi') && function_exists('fleet_restapi_widget'),
    'the dashboard widget is packaged as a manifest and script, with its REST route through plugin_restapi');

/* Load samples. */
check((fleet_samples_last(array(1, 2.5, null, null)) === 2.5) && (fleet_samples_last(array(null)) === null) && (fleet_samples_last(null) === null), 'the last value of an RRD series skips the unfilled end');
$smp = fleet_samples_from(array('cpu' => array('usage' => null), 'memory' => array('total_bytes' => 1000, 'used_bytes' => 250), 'states' => array('current' => 120, 'max' => 400000),
    'temperatures' => array(array('name' => 'CPU 0', 'celsius' => 41.5), array('name' => 'CPU 1', 'celsius' => 44.25))),
    array('cpu' => array(3.2, 7.04, null), 'mem' => array()), array('in_bps' => array(1000, 2500.6, null), 'out_bps' => array(null)));
check(($smp === array('cpu' => 7.0, 'mem' => 25.0, 'states' => 120, 'states_max' => 400000, 'temp' => 44.3, 'rx_bps' => 2501.0, 'tx_bps' => null)) &&
    (fleet_samples_from(array(), null, null) === array_fill_keys(FLEET_SAMPLES_COLS, null)),
    'a sample: CPU from the RRD, memory from the RRD or the live numbers, the hottest sensor, WAN traffic; missing parts stay empty');
$shr = fleet_samples_hourly(array(
    array('node_id' => 'a', 'time' => 7200, 'cpu' => 10, 'mem' => 50, 'states' => 100, 'states_max' => 1000, 'temp' => null, 'rx_bps' => 10, 'tx_bps' => 20),
    array('node_id' => 'a', 'time' => 7500, 'cpu' => 30, 'mem' => null, 'states' => 300, 'states_max' => 1000, 'temp' => null, 'rx_bps' => 30, 'tx_bps' => 40),
    array('node_id' => 'b', 'time' => 7300, 'cpu' => 5, 'mem' => 5, 'states' => 1, 'states_max' => 9, 'temp' => 40, 'rx_bps' => 0, 'tx_bps' => 0),
    array('node_id' => 'a', 'time' => 10800, 'cpu' => 99, 'mem' => 1, 'states' => 1, 'states_max' => 1, 'temp' => 1, 'rx_bps' => 1, 'tx_bps' => 1)));
check((count($shr) === 3) && ($shr[0]['node_id'] === 'a') && ($shr[0]['time'] === 7200) && ($shr[0]['n'] === 2) && ($shr[0]['cpu'] === 20.0) && ($shr[0]['cpu_max'] === 30.0) &&
    ($shr[0]['mem'] === 50.0) && ($shr[0]['temp'] === null) && ($shr[2]['time'] === 10800), 'hourly rows: averages per firewall and hour, the CPU peak, empty values stay empty');
$sdb = fleet_db();
check(((int)$sdb->query('PRAGMA user_version')->fetchColumn() >= 27) && ($sdb->query("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('samples', 'samples_hourly')")->fetchColumn() == 2),
    'schema 27 has the sample tables');
check((strpos((string)$sdb->query("SELECT sql FROM sqlite_master WHERE name = 'kiosk_keys'")->fetchColumn(), 'config') !== false),
    'schema 28: every NOC screen has its own layout');
check((strpos((string)$sdb->query("SELECT sql FROM sqlite_master WHERE name = 'gw_hourly'")->fetchColumn(), 'flaps') !== false) &&
    ((int)$sdb->query("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('gw_samples', 'gw_hourly', 'inet_state', 'inet_log')")->fetchColumn() === 4),
    'schema 29 has the internet tables');
check(((int)$sdb->query('PRAGMA user_version')->fetchColumn() >= 31) && (strpos((string)$sdb->query("SELECT sql FROM sqlite_master WHERE name = 'invitations'")->fetchColumn(), 'via_iface') !== false),
    'schema 31: an invitation keeps how the firewall connects and the interface of a direct path');
$sdb->exec("INSERT INTO samples (node_id, time, cpu) VALUES ('sx', 100, 5), ('sy', 100, 9)");
$sdb->exec("INSERT INTO samples_hourly (node_id, time, n, cpu, cpu_max) VALUES ('sx', 50, 12, 4, 8)");
$sbk = fleet_samples_buckets(null, 0, 100, 2);
check(($sbk['sx']['cpu'] === array(4.0, 5.0)) && ($sbk['sx']['cpu_max'] === array(8.0, 5.0)) && ($sbk['sy']['cpu'] === array(null, 9.0)) && (array_keys(fleet_samples_buckets(array('sx'), 0, 100, 2)) === array('sx')) &&
    (fleet_samples_buckets(array(), 0, 100, 2) === array()), 'sample buckets for some or all firewalls, averaged by the database: hourly rows before five-minute rows');
$sdb->exec("DELETE FROM samples WHERE node_id IN ('sx', 'sy'); DELETE FROM samples_hourly WHERE node_id = 'sx'");

/* Dashboard trends. */
check((fleet_trends_cells('online', array(array(150, 'offline'), array(170, 'online'), array(350, 'degraded')), 100, 100, 4) === array('offline', 'online', 'degraded', 'degraded')) &&
    (fleet_trends_cells(null, array(array(250, 'new'), array(260, 'online')), 100, 100, 3) === array(null, 'new', 'online')),
    'pulse cells: the worst state in each half hour, empty before the firewall joined');
check((fleet_trends_badness(array('online', 'offline', 'degraded', null)) === 110) && (fleet_trends_badness(array('online', 'new')) === 0), 'pulse rows sort by how bad they were');
check((fleet_trends_quantile(array(1, 2, 3, 4, null), .5) === 2.5) && (fleet_trends_quantile(array(10, 20, 30, 40, 50), .9) === 46.0) && (fleet_trends_quantile(array(null), .5) === null),
    'median and 90th percentile skip empty values');
$tdays = fleet_trends_days(mktime(12, 0, 0, 3, 10, 2026), 3);
check(($tdays === array('2026-03-08', '2026-03-09', '2026-03-10')) &&
    (fleet_trends_per_day(array(array(mktime(1, 0, 0, 3, 9, 2026), 'warning'), array(mktime(2, 0, 0, 3, 9, 2026), 'warning'), array(mktime(3, 0, 0, 3, 10, 2026), 'critical'),
    array(mktime(3, 0, 0, 3, 1, 2026), 'critical'), array(mktime(3, 0, 0, 3, 10, 2026), 'bogus')), $tdays, array('critical', 'warning')) ===
    array('critical' => array(0, 0, 1), 'warning' => array(0, 2, 0))), 'counts per day and kind; other days and kinds are left out');
$sdb->exec("DELETE FROM samples; DELETE FROM samples_hourly");
$sdb->exec("INSERT INTO samples_hourly (node_id, time, n, cpu, cpu_max, mem, states, states_max, temp, rx_bps, tx_bps) VALUES
    ('a', 0, 1, 10, 10, 40, 50, 100, NULL, 100, 10), ('a', 50, 1, 30, 60, 60, 70, 100, NULL, 300, 30)");
$sdb->exec("INSERT INTO samples (node_id, time, cpu, mem, states, states_max, temp, rx_bps, tx_bps) VALUES ('b', 120, 90, 10, 1, 10, 70, 1000, NULL), ('b', 999, 1, 1, 1, 1, 1, 1, 1), ('c', 100, 5, 5, 5, 5, 5, 5, 5)");
$tb = fleet_samples_buckets(array('a', 'b'), 0, 100, 2);
$sdb->exec("DELETE FROM samples; DELETE FROM samples_hourly");
check(($tb['a']['cpu'] === array(20.0, null)) && ($tb['a']['cpu_max'] === array(60.0, null)) && ($tb['b']['temp'] === array(null, 70.0)) && !isset($tb['a']['temp']),
    'sample buckets: the average per firewall and bucket, the CPU peak, samples outside the range left out');
$tl = fleet_trends_load($tb, 2);
check(($tl['cpu_med'] === array(20.0, 90.0)) && ($tl['rx'] === array(200.0, 1000.0)) && ($tl['tx'] === array(20.0, null)), 'fleet load: median CPU across firewalls, WAN traffic summed');
$tt = fleet_trends_top($tb, array('a' => 'Alpha', 'b' => 'Beta'), function ($x) { return $x['cpu']; }, 1);
check((count($tt) === 1) && ($tt[0]['label'] === 'Beta') && ($tt[0]['peak'] === 90.0) && ($tt[0]['data'] === array(null, 90.0)), 'top firewalls by their peak');
check(fleet_trends_versions(array(array('version' => '1.2.0'), array('version' => '1.1.5'), array('version' => '1.2.0'), array())) ===
    array(array('label' => '1.2.0', 'value' => 2), array('label' => '1.1.5', 'value' => 1), array('label' => 'Unknown', 'value' => 1)), 'firewalls per version, most first');
check(fleet_users_keys_without_shell('ssh-ed25519 AAAA x', array(array('page-dashboard-all'))) && !fleet_users_keys_without_shell('ssh-ed25519 AAAA x', array(array('user-shell-access'))) &&
    !fleet_users_keys_without_shell('', array()) && !fleet_users_keys_without_shell('ssh-ed25519 AAAA x', array(array('page-all'))), 'an SSH key without the shell privilege is pointed out');
check((fleet_users_difference_kind(null, 'h') === 'pending') && (fleet_users_difference_kind('h', 'h') === 'drift') && (fleet_users_difference_kind('old', 'h') === 'pending') &&
    (fleet_users_desired_hash(array('a' => 1)) === fleet_users_desired_hash(array('a' => 1))), 'users never synced (or changed in Fleet since) are pending, not drift');

check((fleet_kiosk_config_parse(array('heading' => "  ACME <b>NOC</b>
 ", 'subheading' => str_repeat('x', 300)))['heading'] === 'ACME b NOC /b') &&
    (mb_strlen(fleet_kiosk_config_parse(array('subheading' => str_repeat('x', 300)))['subheading']) === 100) && (fleet_kiosk_config_parse(array())['heading'] === ''),
    'live view header text: one plain line, limited in length, empty by default');

/* Internet connectivity */
$thr = array('loss_warn' => 5.0, 'loss_bad' => 20.0, 'latency_warn' => 150.0, 'jitter_warn' => 30.0);
check((fleet_inet_classify(array('status' => 'online', 'delay_ms' => 12, 'stddev_ms' => 1, 'loss_pct' => 0), $thr) === array('up', '')) &&
    (fleet_inet_classify(array('status' => 'online', 'delay_ms' => 12, 'stddev_ms' => 1, 'loss_pct' => 8), $thr)[0] === 'degraded') &&
    (fleet_inet_classify(array('status' => 'online', 'delay_ms' => 220, 'stddev_ms' => 1, 'loss_pct' => 0), $thr) === array('degraded', '220 ms latency')) &&
    (fleet_inet_classify(array('status' => 'online', 'delay_ms' => 20, 'stddev_ms' => 45, 'loss_pct' => 0), $thr)[0] === 'degraded') &&
    (fleet_inet_classify(array('status' => 'down', 'delay_ms' => 0, 'loss_pct' => 100), $thr) === array('down', '100% loss')) &&
    (fleet_inet_classify(array('status' => 'online', 'delay_ms' => 20, 'loss_pct' => 25), $thr)[0] === 'down') &&
    (fleet_inet_classify(array('status' => 'none'), $thr)[0] === 'unknown'),
    'internet: a gateway is up, poor (loss, latency, jitter), down (dpinger down or heavy loss) or not monitored');
$g = function ($name, $state, $def, $d = 10.0) { return array('name' => $name, 'iface' => strtolower($name), 'default' => $def, 'state' => $state, 'reason' => ($state === 'up') ? '' : 'x', 'delay_ms' => $d, 'stddev_ms' => 1.0, 'loss_pct' => 0.0); };
$bs = fleet_inet_box_state(array($g('WAN', 'down', true), $g('WAN2', 'up', false)));
check(($bs['state'] === 'degraded') && ($bs['gw'] === 'WAN2') && (strpos($bs['reason'], 'default gateway WAN down') === 0) &&
    (fleet_inet_box_state(array($g('WAN', 'up', true), $g('WAN2', 'down', false)))['state'] === 'up') &&
    (fleet_inet_box_state(array($g('WAN', 'down', true)))['state'] === 'down') && (fleet_inet_box_state(array())['state'] === 'unknown') &&
    (fleet_inet_box_state(array($g('A', 'degraded', false), $g('B', 'up', false)))['gw'] === 'B'),
    'internet: the default gateway decides; with it down and another up, the firewall is on its backup WAN (poor)');
$down = array('state' => 'down', 'reason' => '100% loss', 'default_gw' => 'WAN');
list($s1, $e1) = fleet_inet_step(array(), $down, 2);
list($s2, $e2) = fleet_inet_step($s1, $down, 2);
list($s3, $e3) = fleet_inet_step($s2, $down, 2);
list($s4, $e4) = fleet_inet_step($s3, array('state' => 'up', 'reason' => '', 'default_gw' => 'WAN'), 2);
list(, $e5) = fleet_inet_step(array(), array('state' => 'up', 'reason' => '', 'default_gw' => 'WAN'), 2);
list(, $e6) = fleet_inet_step(array('state' => 'up', 'bad_count' => 0, 'alerted' => '', 'default_gw' => 'WAN'), array('state' => 'up', 'reason' => '', 'default_gw' => 'WAN2'), 2);
list($s7, $e7) = fleet_inet_step($s2, array('state' => 'unknown', 'reason' => '', 'default_gw' => ''), 2);
check(empty($e1) && ($e2 === array(array('inet_down', '100% loss'))) && empty($e3) && ($e4 === array(array('inet_up', 'internet works again'))) && ($s4['bad_count'] === 0) &&
    empty($e5) && ($e6[0][0] === 'inet_failover') && empty($e7) && ($s7['state'] === 'down'),
    'internet: alerts after the grace checks, once; back only after a told problem; a new default gateway is a failover; unknown keeps the state');
check(fleet_inet_wide(array('a' => 'down', 'b' => 'down', 'c' => 'down', 'd' => 'up'), 30) && !fleet_inet_wide(array('a' => 'down', 'b' => 'down', 'c' => 'up'), 30) &&
    !fleet_inet_wide(array_fill_keys(range(1, 3), 'down') + array_fill_keys(range(4, 20), 'up'), 30) && !fleet_inet_wide(array('a' => 'unknown'), 30),
    'internet: many firewalls down at once (at least three and the share) is one upstream outage');
check((fleet_inet_text(array('state' => 'up', 'delay_ms' => 12.34, 'loss_pct' => 0.0, 'reason' => '')) === '12 ms · 0 % loss') &&
    (fleet_inet_text(array('state' => 'down', 'delay_ms' => null, 'loss_pct' => null, 'reason' => 'gateway down')) === 'gateway down') &&
    (fleet_inet_med_p90(array(1, 2, 3, null, 10)) === array(3.0, 10.0)) && (fleet_inet_med_p90(array()) === array(null, null)),
    'internet: list text and the median/90th percentile');
$thq = array('latency_warn' => 150.0, 'jitter_warn' => 30.0);
check((fleet_inet_score(0.0, 10.0, 1.0, 0, $thq) === 100) && (fleet_inet_score(null, null, null, 0, $thq) === null) &&
    (fleet_inet_score(5.0, 10.0, 1.0, 0, $thq) === 80) && (fleet_inet_score(0.0, 10.0, 1.0, 3, $thq) === 85) &&
    (fleet_inet_score(100.0, 10.0, 1.0, 10, $thq) === 20) && (fleet_inet_score(0.0, 330.0, 60.0, 0, $thq) === 75) &&
    (fleet_inet_score(2.0, 50.0, 5.0, 1, $thq) < fleet_inet_score(0.0, 50.0, 5.0, 0, $thq)) &&
    (fleet_inet_score_word(95) === 'Excellent') && (fleet_inet_score_word(80) === 'Good') && (fleet_inet_score_word(60) === 'Unstable') && (fleet_inet_score_word(10) === 'Bad'),
    'internet quality score: 100 for a clean line; loss weighs most, then flaps, latency and jitter');
check((fleet_inet_flaps(array('up', 'up', 'down', 'down', 'up', 'degraded', 'up')) === 4) && (fleet_inet_flaps(array('up', 'unknown', 'up')) === 0) &&
    (fleet_inet_flaps(array()) === 0) && (fleet_inet_flaps(array('down', null, 'up')) === 1) &&
    fleet_inet_unstable(5, 4) && !fleet_inet_unstable(4, 4) && !fleet_inet_unstable(50, 0),
    'internet flaps: every change between up, poor and down (unknown left out); unstable above the setting, never when it is 0');
$ffs = fleet_inet_fleet_stats(array('a' => array('loss' => 1.0, 'latency' => 10.0, 'jitter' => 1.0, 'score' => 90, 'flaps' => 2, 'loss_min' => 10),
    'b' => array('loss' => 3.0, 'latency' => 30.0, 'jitter' => null, 'score' => 70, 'flaps' => 1, 'loss_min' => 5)));
check(($ffs['loss'] === 2.0) && ($ffs['latency'] === 20.0) && ($ffs['jitter'] === 1.0) && ($ffs['score'] === 80) && ($ffs['flaps'] === 3) && ($ffs['loss_min'] === 15) &&
    (fleet_inet_fleet_stats(array())['score'] === null), 'internet: the fleet figures average the firewalls and add up flaps and minutes with loss');
check((FLEET_DB_SCHEMA >= 30) && isset(FLEET_ALERT_EVENTS['inet_down'], FLEET_ALERT_EVENTS['inet_wide'], FLEET_ALERT_EVENTS['inet_unstable'], FLEET_TUNABLES['inet_enable']) && (fleet_tunables_from(array())['inet_enable'] === false),
    'internet: schema 30, alert kinds, and the option is off by default');

$kb = array(array('id' => 'a', 'label' => 'Alpha', 'state' => 'online', 'groups' => array()), array('id' => 'b', 'label' => 'Beta', 'state' => 'online', 'groups' => array()),
    array('id' => 'c', 'label' => 'Gamma', 'state' => 'degraded', 'groups' => array()));
check(array_column(fleet_kiosk_boxes($kb, fleet_kiosk_config_defaults(), array('b' => 'down')), 'id') === array('c', 'b', 'a') &&
    array_column(fleet_kiosk_boxes($kb, array('sort' => 'name') + fleet_kiosk_config_defaults(), array('a' => 'degraded')), 'id') === array('c', 'a', 'b'),
    'live view list: late firewalls, then no internet, then poor internet come first');

$gb = array(
    array('id' => 'a', 'label' => 'A', 'state' => 'online', 'policy' => 0, 'groups' => array(array('id' => 1, 'name' => 'Shops', 'color' => '2'))),
    array('id' => 'b', 'label' => 'B', 'state' => 'offline', 'policy' => 0, 'groups' => array(array('id' => 2, 'name' => 'Branches', 'color' => '3'))),
    array('id' => 'c', 'label' => 'C', 'state' => 'online', 'policy' => 1, 'groups' => array(array('id' => 1, 'name' => 'Shops', 'color' => '2'), array('id' => 2, 'name' => 'Branches', 'color' => '3'))),
    array('id' => 'd', 'label' => 'D', 'state' => 'online', 'policy' => 0, 'groups' => array()));
$gr = fleet_kiosk_group_rows($gb, array('a' => 'down'), array());
check((array_column($gr, 'name') === array('Branches', 'Shops', 'No group')) && ($gr[0]['worst'] === 'offline') && ($gr[0]['total'] === 2) && ($gr[1]['inet'] === 1) &&
    ($gr[1]['worst'] === 'inet') && ($gr[1]['policy'] === 1) && ($gr[2]['id'] === 0) && ($gr[1]['color'] === '2'),
    'Groups panel: one row per group, counted per member (also in two groups), problem groups first, "No group" last');
$gr1 = fleet_kiosk_group_rows($gb, array(), array('c' => true), array(1));
check((count($gr1) === 1) && ($gr1[0]['name'] === 'Shops') && ($gr1[0]['ha'] === 1) && ($gr1[0]['worst'] === 'ha'), 'a group screen shows only its groups, without "No group"');
$gl = fleet_kiosk_group_list(array(array('name' => 'A', 'g' => 1), array('name' => 'D', 'g' => 0), array('name' => 'B', 'g' => 2), array('name' => 'C', 'g' => 1)), $gr);
check(array_column($gl, 'name') === array('B', 'A', 'C', 'D'), 'a grouped list follows the group order and keeps each group\'s firewalls in their order');
$gview = fleet_kiosk_view(array('boxes' => array(array('id' => 'n1', 'state' => 'online', 'groups' => array(array('id' => 5, 'name' => 'Customer X', 'color' => '4')), 'version' => '1.2', 'seen' => 0,
    'policy' => 0, 'breakglass' => false, 'update' => null, 'op' => null, 'label' => 'fw', 'host' => 'h', 'problem' => '')), 'headline' => '', 'total' => 1, 'counts' => array(), 'checked' => 0, 'now' => 0),
    array(), true, 'T', array('freesense', 'auto'), array('group_rows' => true) + fleet_kiosk_config_defaults());
check(($gview['group_rows'][0]['name'] === 'Group 1') && ($gview['boxes'][0]['groups'] === array()) && ($gview['boxes'][0]['gc'] === array()) && ($gview['boxes'][0]['g'] === 5) &&
    ($gview['panels']['groups']['rows'][0]['name'] === 'Group 1') && (strpos(json_encode($gview), 'Customer X') === false),
    'a screen that hides names numbers its groups and never sends their names');
check((fleet_trends_group_ids(0) === array()) && (fleet_trends_group_ids(3) === array(3)) && (fleet_trends_group_ids(array(2, '4', 0, 2)) === array(2, 4)) &&
    (array_column(fleet_trends_in_groups(array(array('node_id' => 'a'), array('node_id' => 'b'), array('node_id' => 'c')),
    array('a' => array(array('id' => 1)), 'b' => array(array('id' => 2)), 'c' => array(array('id' => 3))), array(1, 3)), 'node_id') === array('a', 'c')),
    'charts for a screen with several groups use the firewalls of all of them');
check(fleet_kiosk_config_parse(array('group_rows' => '1'))['group_rows'] && !fleet_kiosk_config_parse(array())['group_rows'], 'the grouped list is a setting, off by default');

check(fleet_ts_expiry_should_disable(array('id' => 'd1', 'keyExpiryDisabled' => false), true) && !fleet_ts_expiry_should_disable(array('id' => 'd1', 'keyExpiryDisabled' => true), true) &&
    !fleet_ts_expiry_should_disable(array('id' => 'd1'), false) && !fleet_ts_expiry_should_disable(array(), true), 'Tailscale key expiry is turned off by itself only when the setting is on and it is on');

check((fleet_invite_recommend(true, true, true) === 'tailscale') && (fleet_invite_recommend(false, true, true) === 'tunnel') &&
    (fleet_invite_recommend(false, false, true) === 'direct') && (fleet_invite_recommend(false, false, false) === 'tunnel'),
    'an invitation recommends Tailscale when the controller is ready in a tailnet, else the tunnel, Direct only with just an internal point');

/* The sync rules reach both firewalls before either starts pfsync (a pfsync packet under the default LAN rule makes a synced state that the two refresh for each other). */
$ha_src = (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg/fleet/fleet_ha_setup.inc');
check(preg_match("/foreach \\(array\\('rules', 'sync'\\) as \\\$phase\\) \\{\\s*foreach \\(array\\(array\\(\\\$p, \\\$tp, true\\), array\\(\\\$s, \\\$ts, false\\)\\)/", $ha_src) === 1 && strpos($ha_src, "if (\$phase === 'rules')") !== false,
    'HA setup loads the sync rules on both firewalls before any firewall starts state sync');
