<?php
/* Prints generated output for a fixture, to refresh golden files or to feed
 * AdGuard Home's --check-config:
 *   php gen.php yaml|nat|pfearly <fixture> [paused] */
require __DIR__ . '/bootstrap.php';
$cfg = ts_test_load($argv[2] ?? 'config_full.php');
switch ($argv[1] ?? 'yaml') {
	case 'nat':
		echo threatshield_pf_nat_rules($cfg, ts_test_ctx());
		break;
	case 'pfearly':
		echo threatshield_pf_early_rules($cfg, ts_test_ctx());
		break;
	default:
		$pause = (($argv[3] ?? '') === 'paused') ? ['active' => true, 'until' => 1893456000] : ['active' => false, 'until' => 0];
		echo threatshield_generate_yaml($cfg, ['bind_hosts' => ['127.0.0.1', '192.0.2.1'], 'domain' => 'home.arpa', 'pause' => $pause]);
}
