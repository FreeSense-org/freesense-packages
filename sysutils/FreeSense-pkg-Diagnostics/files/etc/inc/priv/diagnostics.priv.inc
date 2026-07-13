<?php
$priv_list[] = [
	'name' => gettext('WebCfg - Diagnostics: Network Tools'),
	'descr' => gettext('Allow access to the FreeSense network diagnostics suite.'),
	'match' => ['diagnostics/network_tools.php*'],
	'priv' => 'page-diagnostics-network-tools',
];
