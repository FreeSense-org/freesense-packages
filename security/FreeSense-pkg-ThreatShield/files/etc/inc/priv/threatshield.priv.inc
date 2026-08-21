<?php

global $priv_list;

$priv_list['page-services-threatshield'] = [
	'name' => 'WebCfg - Services: Threat Shield',
	'descr' => 'Configure FreeSense Threat Shield DNS and GeoIP protection',
	'match' => [
		'threatshield/threatshield.php*',
		'threatshield/threatshield_status.php*',
		'threatshield/threatshield_querylog.php*',
		'threatshield/threatshield_feeds.php*',
		'threatshield/threatshield_geoip.php*',
		'threatshield/threatshield_rules.php*',
		'threatshield/threatshield_clients.php*',
		'threatshield/threatshield_rewrites.php*'
	],
];
