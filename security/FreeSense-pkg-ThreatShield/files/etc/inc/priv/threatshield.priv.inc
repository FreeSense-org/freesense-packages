<?php

global $priv_list;

$priv_list['page-services-threatshield'] = [
	'name' => 'WebCfg - Services: Threat Shield',
	'descr' => 'Configure FreeSense Threat Shield DNS, IP reputation and GeoIP protection',
	'match' => [
		'threatshield/threatshield.php*',
		'threatshield/threatshield_ajax.php*',
		'threatshield/threatshield_allowlist.php*',
		'threatshield/threatshield_clients.php*',
		'threatshield/threatshield_feeds.php*',
		'threatshield/threatshield_geoip.php*',
		'threatshield/threatshield_inbound.php*',
		'threatshield/threatshield_querylog.php*',
		'threatshield/threatshield_rewrites.php*',
		'threatshield/threatshield_rules.php*',
		'threatshield/threatshield_status.php*',
		'threatshield/threatshield_map.php*',
		'threatshield/threatshield_map_data.php*'
	],
];

/* read only: a wall screen account sees the map and nothing else */
$priv_list['page-status-threatshield-map'] = [
	'name' => 'WebCfg - Status: Threat Shield threat map',
	'descr' => 'View the Threat Shield threat map and its dashboard widget (read only)',
	'match' => [
		'threatshield/threatshield_map.php*',
		'threatshield/threatshield_map_data.php*',
		'widgets/widgets/threatshield_map.widget.php*'
	],
];
