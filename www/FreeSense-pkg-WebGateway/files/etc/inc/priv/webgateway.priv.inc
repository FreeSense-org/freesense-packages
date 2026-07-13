<?php

global $priv_list;

$priv_list['page-services-webgateway'] = [
	'name' => 'WebCfg - Services: Web Gateway',
	'descr' => 'Configure the FreeSense Secure Web Gateway',
	'match' => ['webgateway/webgateway.php*', 'webgateway/webgateway_listeners.php*', 'webgateway/webgateway_tls.php*', 'webgateway/webgateway_policies.php*', 'webgateway/webgateway_identity.php*', 'webgateway/webgateway_threat.php*', 'webgateway/webgateway_feeds.php*', 'webgateway/webgateway_cache.php*', 'webgateway/webgateway_pac.php*'],
];
$priv_list['page-status-webgateway'] = [
	'name' => 'WebCfg - Status: Web Gateway',
	'descr' => 'View and control Web Gateway status and diagnostics',
	'match' => ['webgateway/webgateway_status.php*', 'webgateway/webgateway_diagnostics.php*'],
];
