<?php
/* Fleet controller tests: HA pair grouping. Loaded by ../run.php (shares its variables). */

$hb = function (string $id, string $vip, string $state) {
	return array('node_id' => $id, 'state' => 'online', 'misses' => 0, 'status' => json_encode(array('carp_vips' => array(array('vhid' => 1, 'address' => $vip, 'state' => $state)))));
};
$two = fleet_ha_pairs(array($hb('n-a', '10.0.0.1', 'MASTER'), $hb('n-b', '10.0.0.1', 'BACKUP')));
$three = fleet_ha_pairs(array($hb('s1-a', '192.168.1.1', 'MASTER'), $hb('s2-a', '192.168.1.1', 'MASTER'), $hb('s3-a', '192.168.1.1', 'BACKUP')));
check((count($two) === 1) && ($two[0]['nodes'] === array('n-a', 'n-b')) && ($two[0]['problem'] === null) && ($three === array()),
    'two firewalls sharing a virtual IP are a pair; three or more (sites that reuse the same default address) are not, so no false split-brain or blocked rollout');
