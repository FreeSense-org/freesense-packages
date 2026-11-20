<?php
/* Fleet controller tests: lock. Loaded by ../run.php (shares its variables). */

check(fleet_policy_lockable('SEC-002') && fleet_policy_lockable('CUSTOM') && !fleet_policy_lockable('VER-001') && !fleet_policy_lockable('SEC-001'), 'only configuration rules can be locked');
try {
	fleet_policy_rule_from('VER-001', array('version' => '1.1.5', 'mode' => 'lock'));
	check(false, 'a version rule cannot be locked');
} catch (InvalidArgumentException $e) {
}
$lr = fleet_policy_lock_rules(array('SEC-002' => array(array(), 'lock', 1, 'B', null), 'OPS-001' => array(array(), 'lock', 1, 'B', null),
    'CUSTOM:4' => array(array('path' => 'system/ssh/port', 'op' => 'equals', 'value' => '22', 'title' => 'SSH port'), 'lock', 1, 'B', null),
    'NAME-002' => array(array('value' => 'x.net'), 'audit', 1, 'B', null), 'VER-001' => array(array('version' => '1.1.5'), 'lock', 1, 'B', null)));
check(count($lr) === 3 && $lr[0] === array('id' => 'SEC-002', 'title' => 'WebGUI over HTTPS', 'mode' => 'lock', 'path' => 'system/webgui/protocol', 'op' => 'equals', 'value' => 'https') &&
    $lr[1]['op'] === 'regex' && $lr[1]['value'] === '.' && $lr[2]['id'] === 'CUS-004' && $lr[2]['title'] === 'SSH port', 'lock rules in the firewall\'s form; audit and non-config rules stay home');
if (is_file($src . "/src/etc/inc/fleet_guard.inc")) {
	require_once($src . "/src/etc/inc/fleet_guard.inc");
	/* The firewall's own checker accepts every rule Fleet sends. */
	foreach ($lr as $r) {
		check(fleet_rule_valid($r), "the firewall accepts lock rule {$r['id']}");
	}
	$cfgs = array('system/webgui/protocol' => 'https', 'system/timeservers' => 'pool.ntp.org', 'system/ssh/port' => '22');
	$newc = array('system/webgui/protocol' => 'http') + $cfgs;
	$v = fleet_lock_new_violations($lr, function ($p) use ($newc) { return $newc[$p] ?? null; }, function ($p) use ($cfgs) { return $cfgs[$p] ?? null; });
	check(count($v) === 1 && $v[0]['id'] === 'SEC-002', 'a save switching the WebGUI to HTTP is refused by the firewall');
}
