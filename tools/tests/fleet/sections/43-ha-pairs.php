<?php
/* Fleet controller tests: HA pairs. Loaded by ../run.php (shares its variables). */

$hab = function (string $n, string $state, array $vips, string $peer = '', array $sec = array()) {
	return array('node_id' => $n, 'label' => strtoupper($n), 'state' => $state, 'status' => json_encode(array(
	    'carp_vips' => array_map(function ($v) { return array('vhid' => $v[0], 'address' => $v[1], 'state' => $v[2]); }, $vips),
	    'hasync' => array('peer' => $peer, 'sections' => $sec))));
};
$hboxes = array(
	$hab('a', 'online', array(array(1, '10.0.0.1/24', 'MASTER'), array(2, '192.0.2.1/24', 'MASTER')), '10.9.9.2', array('aliases', 'rules')),
	$hab('b', 'online', array(array(1, '10.0.0.1/24', 'BACKUP'), array(2, '192.0.2.1/24', 'BACKUP'))),
	$hab('c', 'online', array(array(5, '10.5.0.1/24', 'MASTER'))),
	$hab('d', 'online', array()),
);
$hp = fleet_ha_pairs($hboxes);
check((count($hp) === 1) && ($hp[0]['nodes'] === array('a', 'b')) && ($hp[0]['masters'] === array('a')) && ($hp[0]['primary'] === 'a') && ($hp[0]['problem'] === null),
    'HA pairs: firewalls sharing a CARP address are one pair, with its MASTER and its sync primary; a lone CARP firewall is no pair');
$hboxes[1] = $hab('b', 'online', array(array(1, '10.0.0.1/24', 'MASTER'), array(2, '192.0.2.1/24', 'BACKUP')));
check(fleet_ha_pairs($hboxes)[0]['problem'] === array('split', '1@10.0.0.1/24'), 'two MASTERs for one address is split-brain');
$hboxes[1] = $hab('b', 'offline', array(array(1, '10.0.0.1/24', 'MASTER'), array(2, '192.0.2.1/24', 'MASTER')));
check(fleet_ha_pairs($hboxes)[0]['problem'] === array('down', 'b'), 'an offline partner\'s old state does not count: the pair has a member down');
$hboxes[1] = $hab('b', 'online', array(array(1, '10.0.0.1/24', 'MASTER'), array(2, '192.0.2.1/24', 'MASTER'))) + array('misses' => 2);
check(fleet_ha_pairs($hboxes)[0]['problem'] === array('down', 'b'), 'a partner that just stopped answering is down, not split-brain (its MASTER state is old)');
check(fleet_ha_problem_text(array('nodes' => array('a', 'b'), 'masters' => array('a', 'b'), 'problem' => array('down', 'b')), array('a' => array('label' => 'A'), 'b' => array('label' => 'B')), 'A and B') ===
    'HA pair A and B: B does not answer. A carries the shared addresses.', 'a member-down alert says who carries the addresses');
$hboxes[0] = $hab('a', 'online', array(array(1, '10.0.0.1/24', 'BACKUP'), array(2, '192.0.2.1/24', 'MASTER')), '10.9.9.2', array('aliases', 'rules'));
check(fleet_ha_pairs($hboxes)[0]['problem'] === array('nomaster', '1@10.0.0.1/24'), 'no online MASTER for an address is a problem');
$hboxes[0] = $hab('a', 'online', array(array(1, '10.0.0.1/24', 'MASTER'), array(2, '192.0.2.1/24', 'MASTER')), '10.9.9.2', array('aliases', 'rules'));
$hboxes[1] = $hab('b', 'online', array(array(1, '10.0.0.1/24', 'BACKUP'), array(2, '192.0.2.1/24', 'BACKUP')));
$hp = fleet_ha_pairs($hboxes);
check((array_column(array_values(fleet_ha_order($hboxes, $hp)), 'node_id') === array('b', 'c', 'd', 'a')) && (fleet_ha_order(array('a', 'b'), $hp) === array(1 => 'b', 0 => 'a')) &&
    (array_key_first(fleet_ha_order(array(7 => 'a', 9 => 'b'), $hp)) === 9),
    'working order: a pair\'s MASTER after everything else');
check(fleet_ha_rings(array(array('a', 'c'), array('b')), $hp) === array(array('c'), array('b', 'a')), 'a rollout moves the MASTER into its partner\'s later ring, after it');
check((fleet_ha_wait_reason($hp[0], 'a', array('a' => 'online', 'b' => 'offline'), array('b' => 'B')) === 'Waiting for its HA partner B to be online') &&
    (fleet_ha_wait_reason($hp[0], 'a', array('a' => 'online', 'b' => 'online'), array()) === null) && (fleet_ha_wait_reason(null, 'c', array(), array()) === null),
    'Fleet waits for the partner before working on a pair firewall');
$hst = array('a' => array('hasync' => array('sections' => array('aliases', 'rules'))));
check((fleet_ha_synced_from($hp[0], 'b', 'rules', $hst) === 'a') && (fleet_ha_synced_from($hp[0], 'b', 'nat', $hst) === null) &&
    (fleet_ha_synced_from($hp[0], 'a', 'rules', $hst) === null) && (fleet_ha_synced_from($hp[0], 'b', 'dns', $hst) === null),
    'HA config sync: the secondary gets synced kinds from its primary, not from Fleet');

check((fleet_uptime_text(34369) === '9 h 32 min') && (fleet_uptime_text(3 * 86400 + 7200) === '3 days 2 h') && (fleet_uptime_text(86400) === '1 day') && (fleet_uptime_text(59) === '0 min'),
    'uptime in days, hours and minutes');
