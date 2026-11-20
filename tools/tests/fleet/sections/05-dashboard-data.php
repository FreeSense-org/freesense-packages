<?php
/* Fleet controller tests: dashboard data. Loaded by ../run.php (shares its variables). */

$row = function ($id, $label, $state, $status = array(), $error = '') {
	return array('node_id' => $id, 'name' => $id, 'label' => $label, 'overlay' => 'fd00::10', 'role' => 'managed', 'state' => $state,
	    'last_seen' => 100, 'error' => $error, 'status' => json_encode($status), 'api_key' => 'fsk_SECRET');
};
$dash = fleet_dashboard_data(array($row('n1', 'Zeta', 'online', array('hostname' => 'z.lab', 'version' => '1.1.5-RELEASE', 'rollback_protection' => true)),
    $row('n2', 'alpha', 'online', array('rollback_protection' => false)), $row('n3', 'Beta', 'offline', array(), 'FLEET-E105: down'),
    $row('n4', 'Gamma', 'degraded')), 2, 200);
check(array_column($dash['boxes'], 'label') === array('Beta', 'Gamma', 'alpha', 'Zeta'), 'worst state first, then by label');
check($dash['headline'] === '2 of 4 firewalls need attention' && $dash['counts']['online'] === 2 && $dash['counts']['unprotected'] === 1 &&
    $dash['counts']['pending'] === 2 && $dash['checked'] === 100, 'counts and headline');
check($dash['boxes'][0]['problem'] === 'FLEET-E105: down' && $dash['boxes'][3]['problem'] === '' && $dash['boxes'][3]['host'] === 'z.lab' &&
    $dash['boxes'][3]['rollback'] === true && $dash['boxes'][2]['rollback'] === false && $dash['boxes'][1]['rollback'] === null, 'per-box facts');
check(strpos(json_encode($dash), 'SECRET') === false, 'no API key reaches the dashboard');
check(fleet_dashboard_data(array(), 0, 1)['headline'] === 'No firewalls yet' &&
    fleet_dashboard_data(array($row('n1', 'A', 'online')), 0, 1)['headline'] === 'The firewall is online' &&
    fleet_dashboard_data(array($row('n1', 'A', 'online'), $row('n2', 'B', 'online')), 0, 1)['headline'] === 'All 2 firewalls are online', 'headlines');

check(fleet_poll_problem('E105', 'hq is unreachable (No route to host). Check the address.') === 'FLEET-E105: The box did not answer over the tunnel (No route to host). Check that it is powered on and online.' && fleet_poll_problem('E999', 'x') === 'FLEET-E999: x', 'poll problems speak from the controller side');
