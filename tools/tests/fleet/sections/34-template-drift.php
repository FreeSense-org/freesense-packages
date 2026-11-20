<?php
/* Fleet controller tests: template drift. Loaded by ../run.php (shares its variables). */

$dt = array('id' => 7, 'kind' => 'aliases', 'items' => array(
    array('name' => 'office', 'type' => 'network', 'description' => 'Offices', 'entries' => array(array('address' => '10.0.0.0/24', 'detail' => 'HQ'))),
    array('name' => 'ports', 'type' => 'port', 'description' => 'Ports', 'entries' => array(array('address' => '443', 'detail' => '')))));
$dremote = array(
    array('name' => 'office', 'type' => 'network', 'description' => '[Fleet:T7] Offices (local)', 'entries' => array(array('address' => '10.0.0.0/24', 'detail' => 'HQ'), array('address' => '10.9.0.0/24', 'detail' => 'Annex'))),
    array('name' => 'ports', 'type' => 'port', 'description' => '[Fleet:T7] Ports', 'entries' => array(array('address' => '443', 'detail' => ''))),
    array('name' => 'theirs', 'type' => 'host', 'description' => 'local', 'entries' => array()));
list($dfields, $dchanged) = fleet_template_adopted($dt, $dremote);
check($dchanged === array('office') && count($dfields['items'][0]['entries']) === 2 && $dfields['items'][0]['description'] === 'Offices (local)' &&
    $dfields['items'][1] === $dt['items'][1] && count($dfields['items']) === 2, 'adopt takes the firewall\'s version of the template\'s own aliases only');
check(fleet_template_plan(7, $dfields['items'], $dremote)[0]['action'] === 'same', 'after adopting, that firewall is in sync');
list(, $dnone) = fleet_template_adopted(array('id' => 7, 'kind' => 'aliases', 'items' => $dt['items']), array(array('name' => 'office', 'type' => 'network',
    'description' => 'Someone else', 'entries' => array())));
check($dnone === array(), 'an alias another owner holds is never adopted');
list($dset, $dsc) = fleet_template_adopted(array('id' => 8, 'kind' => 'snmp', 'settings' => array('enable' => true, 'syslocation' => 'HQ', 'syscontact' => '', 'rocommunity' => 'sealed')),
    array('enable' => true, 'syslocation' => 'Rack 4', 'syscontact' => ''));
check($dset['settings']['syslocation'] === 'Rack 4' && $dset['settings']['rocommunity'] === 'sealed' && $dsc === array('Location'), 'adopt takes settings, keeps the secret');
$dtid = fleet_template_save(null, array('name' => 'Drift test', 'kind' => 'time', 'targets' => array('all'), 'set_timezone' => 'Etc/UTC', 'set_timeservers' => 'pool.ntp.org'), 'test');
$dtt = fleet_template_get($dtid);
$dthrown = false;
try {
	fleet_template_ignore($dtt, 'n-x', '  ', 'test');
} catch (InvalidArgumentException $e) {
	$dthrown = true;
}
fleet_template_ignore($dtt, 'n-x', 'Ships in another time zone', 'test');
check($dthrown && fleet_template_ignores($dtid)['n-x']['reason'] === 'Ships in another time zone', 'ignoring a firewall needs a reason');
fleet_template_unignore($dtt, 'n-x', 'test');
check(fleet_template_ignores($dtid) === array(), 'stop ignoring');
fleet_template_delete($dtid, 'test');
