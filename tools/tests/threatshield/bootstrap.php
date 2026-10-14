<?php
/* Loads Threat Shield against the stand-ins in stubs/ (documentation addresses only). */
error_reporting(E_ALL);
ini_set('display_errors', '1');
set_include_path(__DIR__ . '/stubs' . PATH_SEPARATOR . get_include_path());
$GLOBALS['ts_test_config'] = [
	'system' => ['domain' => 'home.arpa'],
	'interfaces' => [
		'wan' => ['if' => 'vtnet0', 'descr' => 'WAN'],
		'lan' => ['if' => 'vtnet1', 'descr' => 'LAN'],
		'opt1' => ['if' => 'vtnet2', 'descr' => 'GUEST'],
	],
	'aliases' => ['alias' => [['name' => 'Servers', 'type' => 'host', 'address' => '192.0.2.80']]],
];
$GLOBALS['ts_test_ifmap'] = ['wan' => 'vtnet0', 'lan' => 'vtnet1', 'opt1' => 'vtnet2'];
$GLOBALS['ts_test_wans'] = ['wan'];
/* the threat map store and its state live in a scratch directory */
$GLOBALS['ts_test_tmp'] = sys_get_temp_dir() . '/ts-test-' . getmypid();
@mkdir($GLOBALS['ts_test_tmp'], 0700, true);
define('THREATSHIELD_MAP_DB', $GLOBALS['ts_test_tmp'] . '/map.sqlite');
define('THREATSHIELD_MAP_STATE', $GLOBALS['ts_test_tmp'] . '/map_state.json');
define('THREATSHIELD_GEO_DIR', $GLOBALS['ts_test_tmp'] . '/geodb');
register_shutdown_function(function () {
	foreach ((array)glob($GLOBALS['ts_test_tmp'] . '/{,*/}*', GLOB_BRACE) as $f) if (is_file($f)) @unlink($f);
	foreach ((array)glob($GLOBALS['ts_test_tmp'] . '/*', GLOB_ONLYDIR) as $d) @rmdir($d);
	@rmdir($GLOBALS['ts_test_tmp']);
});
require_once dirname(__DIR__, 3) . '/security/FreeSense-pkg-ThreatShield/files/usr/local/pkg/threatshield.inc';

/* System facts for the rule builders, as threatshield_rule_context() collects them. */
function ts_test_ctx(array $overrides = []): array {
	return array_merge([
		'ifmap' => $GLOBALS['ts_test_ifmap'],
		'gw4' => ['wan' => '203.0.113.1'], 'gw6' => ['wan' => ''],
		'replyto' => true, 'healthy' => true, 'dnsbl_up' => true,
		'db' => '/var/db/threatshield', 'ensure' => null, 'aliases' => ['Servers'],
	], $overrides);
}

function ts_test_load(string $fixture): array {
	$GLOBALS['ts_test_config']['installedpackages']['threatshield'] = require __DIR__ . '/fixtures/' . $fixture;
	return threatshield_config();
}
