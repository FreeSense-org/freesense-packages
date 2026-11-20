<?php
/* Fleet controller tests: firewalls list. Loaded by ../run.php (shares its variables). */

$fwb = function ($label, $state, $version, $gids, $extra = array()) {
	return array_merge(array('id' => $label, 'label' => $label, 'host' => strtolower($label), 'overlay' => 'fd00::1', 'state' => $state, 'version' => $version,
	    'groups' => array_map(function ($g) { return array('id' => $g, 'name' => 'g' . $g, 'color' => ''); }, $gids), 'breakglass' => false, 'rollback' => true,
	    'policy' => 0, 'update' => null, 'seen' => 0, 'managed' => true), $extra);
};
$fwall = array($fwb('Alpha', 'online', '1.1.5', array(1)), $fwb('Bravo', 'offline', '1.1.4', array(1, 2)), $fwb('Charlie', 'online', '1.1.5', array(), array('policy' => 2, 'update' => array('info', 'Update: 1.1.6'))),
    $fwb('Delta', 'degraded', '1.1.5', array(2), array('rollback' => false)));
$names = function ($l) { return implode(',', array_column($l, 'label')); };
check($names(fleet_firewalls_filter($fwall, array('q' => 'char'))) === 'Charlie' && $names(fleet_firewalls_filter($fwall, array('state' => 'online'))) === 'Alpha,Charlie' &&
    $names(fleet_firewalls_filter($fwall, array('group' => '2'))) === 'Bravo,Delta' && $names(fleet_firewalls_filter($fwall, array('version' => '1.1.4'))) === 'Bravo',
    'firewall list: search, state, group and version filters');
check($names(fleet_firewalls_filter($fwall, array('problem' => 'attention'))) === 'Bravo,Delta' && $names(fleet_firewalls_filter($fwall, array('problem' => 'update'))) === 'Charlie' &&
    $names(fleet_firewalls_filter($fwall, array('problem' => 'policy'))) === 'Charlie' && $names(fleet_firewalls_filter($fwall, array('problem' => 'unprotected'))) === 'Delta',
    'firewall list: quick filters');
check($names(fleet_firewalls_filter($fwall, array('sort' => 'version'))) === 'Alpha,Charlie,Delta,Bravo' && array_keys(fleet_firewalls_versions($fwall)) === array('1.1.5', '1.1.4'),
    'firewall list: version sort and the version filter');
