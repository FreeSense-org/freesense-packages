<?php

global $priv_list;

$priv_list['page-system-fleet-controller'] = [
	'name' => 'WebCfg - System: FreeSense Fleet',
	'descr' => 'Manage the fleet: invite, approve and remove firewalls, and change the controller settings',
	'warn' => 'standard-warning-root',
	'match' => ['fleet/fleet.php*'],
];
