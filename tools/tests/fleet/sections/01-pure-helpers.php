<?php
/* Fleet controller tests: pure helpers. Loaded by ../run.php (shares its variables). */

check(fleet_unseal(fleet_seal('secret', str_repeat('k', 32)), str_repeat('k', 32)) === 'secret', 'seal round-trip');
check(fleet_unseal(fleet_seal('secret', str_repeat('k', 32)), str_repeat('x', 32)) === null && fleet_unseal('junk', str_repeat('k', 32)) === null,
    'a wrong master key or junk opens nothing');
$ov = fleet_random_overlay();
check(preg_match('/^fd[0-9a-f]{2}:[0-9a-f]{4}:[0-9a-f]{4}:f1::\/64$/D', $ov) === 1 && fleet_random_overlay() !== $ov, 'a random ULA /64');
check(fleet_overlay_host('fd12:3456:789a:f1::/64', 1) === 'fd12:3456:789a:f1::1' && fleet_overlay_host('fd12:3456:789a:f1::/64', 16) === 'fd12:3456:789a:f1::10',
    'overlay host addresses');
$s = fleet_ctl_settings_from(array('enable' => 'on', 'wg_port' => '99999'));
check($s === array('enable' => true, 'wg_port' => 51830, 'points' => array(), 'rules_manual' => false, 'public_host' => '', 'enroll_port' => 8443, 'primary' => '') +
    fleet_tunables_from(array()), 'settings with defaults');
$sp = fleet_ctl_settings_from(array('points' => json_encode(array(array('iface' => 'tailscale', 'port' => '9443'), array('iface' => 'wan', 'port' => 8443, 'address' => ' hq.example.net '),
    array('iface' => 'lan', 'port' => 99999, 'address' => 'bad host:x'), array('iface' => 'wan', 'port' => 1), array('iface' => 'bad iface'))), 'rules_manual' => 'on'));
check((array_column($sp['points'], 'iface') === array('tailscale', 'wan', 'lan')) && ($sp['points'][0]['port'] === 9443) && ($sp['points'][1]['address'] === 'hq.example.net') &&
    ($sp['points'][2] === array('iface' => 'lan', 'port' => 8443, 'address' => '')) && ($sp['primary'] === 'wan') && ($sp['public_host'] === 'hq.example.net') &&
    ($sp['enroll_port'] === 8443) && $sp['rules_manual'] && (fleet_ctl_point($sp, 'tailscale')['port'] === 9443) && (fleet_ctl_point($sp, 'opt1') === null),
    'connection points: one per interface (the tailnet too), a port each, an address or none; the first one off the tailnet is the main one');
check((fleet_ctl_primary(array(array('iface' => 'tailscale', 'port' => 9443, 'address' => '')))['primary'] === 'tailscale') && fleet_ctl_address_ok('2001:db8::1') &&
    !fleet_ctl_address_ok('hq:8443') && fleet_ctl_address_ok('fleet.example.net'),
    'a tailnet-only controller uses the tailnet point; addresses are hosts without a port');
check(json_decode(fleet_ctl_points_main_address(json_encode(array(array('iface' => 'wan', 'port' => 8443, 'address' => 'old.example.net'))), '198.51.100.7'), true)[0]['address'] === '198.51.100.7' &&
    array_column(json_decode(fleet_ctl_points_main_address(json_encode(array(array('iface' => 'tailscale', 'port' => 8443))), 'b.example.net'), true), 'iface') === array('wan', 'tailscale'),
    'a standby taking over puts its own address on the main connection point');
check((fleet_enroll_listen(array(array('192.0.2.1', 8443), array('2001:db8::1', 8443), array('192.0.2.1', 8443), array('100.64.0.1', 9443))) ===
    "		listen 192.0.2.1:8443 ssl;
		listen [2001:db8::1]:8443 ssl;
		listen 100.64.0.1:9443 ssl;
") &&
    (strpos(fleet_enroll_nginx_conf(array(array('10.0.0.1', 8443)), '/t.pem', '/s'), 'listen 10.0.0.1:8443 ssl;') !== false) &&
    (strpos(fleet_enroll_nginx_conf(array(array('10.0.0.1', 8443)), '/t.pem', '/s'), 'listen [::]:8443') === false),
    'the enrollment endpoint listens on the addresses of each connection point, each with its port');
check(fleet_ctl_settings_from(array('poll_interval' => '30'))['poll_interval'] === 30 && fleet_ctl_settings_from(array('poll_interval' => '7'))['poll_interval'] === 15, 'status interval: 10, 15, 30 or 60 s');
check(fleet_ctl_settings_from(array())['enable'] === false, 'off by default');
check(fleet_hostport('fd12::1', 8443) === '[fd12::1]:8443' && fleet_hostport('hq', 1) === 'hq:1', 'host:port');
$early = fleet_ctl_early_rules(fleet_ctl_settings_from(array('enable' => 'on')));
check(strpos($early, 'pass in quick on wgfctl0') !== false && strpos($early, 'pass out quick on wgfctl0') !== false &&
    fleet_ctl_early_rules(fleet_ctl_settings_from(array())) === '',
    'overlay rules in both directions, as early rules (they must come before "Block all IPv6")');
$conf = fleet_enroll_nginx_conf(array(array('10.0.0.1', 8443)), '/fleet/tls.pem');
check(strpos($conf, 'location ^~ /fleet/join/') !== false && strpos($conf, "return 404") !== false && strpos($conf, 'limit_req zone=fleetjoin') !== false &&
    strpos($conf, 'pid /var/run/fleet-enroll.pid;') !== false && !preg_match('#pid /var/run/nginx[^;]*\.pid#', $conf),
    'the enrollment nginx serves only /fleet/join/, rate-limited, with a pid file rc.restart_webgui does not kill');
check(fleet_box_state(0) === 'online' && fleet_box_state(3) === 'degraded' && fleet_box_state(10) === 'offline', 'missed polls');
check(fleet_valid_label('Copenhagen office') && !fleet_valid_label('') && !fleet_valid_label('<b>') && !fleet_valid_label(str_repeat('x', 81)), 'labels');
