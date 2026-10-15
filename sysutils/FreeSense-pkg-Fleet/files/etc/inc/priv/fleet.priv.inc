<?php

global $priv_list;

$priv_list['page-system-fleet-controller'] = [
	'name' => 'WebCfg - System: FreeSense Fleet',
	'descr' => 'Manage the fleet: invite, approve and remove firewalls, and change the controller settings',
	'warn' => 'standard-warning-root',
	'match' => ['fleet/fleet.php*', 'fleet/fleet_action.php*', 'fleet/fleet_group_action.php*'],
];

$priv_list['page-status-fleet-dashboard'] = [
	'name' => 'WebCfg - Status: FreeSense Fleet',
	'descr' => 'View the state of every firewall in the fleet (read only)',
	'match' => ['fleet/fleet_dashboard.php*', 'fleet/fleet_activity.php*', 'fleet/fleet_updates.php*', 'fleet/fleet_schedules.php*', 'fleet/fleet_nav.php*', 'fleet/fleet_data.php*', 'fleet/fleet_box.php*', 'fleet/assets/*'],
];
