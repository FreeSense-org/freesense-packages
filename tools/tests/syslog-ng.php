<?php
/* Copyright (c) 2026 The FreeSense Project. SPDX-License-Identifier: Apache-2.0 */
/* The real validation hook runs against a captured shell boundary, never a live daemon. */
$path = dirname(__DIR__, 2) . '/sysutils/FreeSense-pkg-syslog-ng/files/usr/local/pkg/syslog-ng.inc';
$source = file_get_contents($path);
$start = strpos($source, 'function syslogng_validate_general(');
$end = strpos($source, "\n}\n", $start);
$function = substr($source, $start, $end - $start + 3);
$stubs = <<<'PHP'
namespace SyslogAudit;
function config_get_path($p, $d = null) { return $d; }
function gettext($text) { return $text; }
function is_port($port) { return is_scalar($port) && preg_match('/^[0-9]{1,5}$/D', (string)$port) && (int)$port > 0 && (int)$port <= 65535; }
function shell_exec($command) { $GLOBALS['commands'][] = $command; return ''; }
function syslogng_build_default_objects($post) { return array(); }
function syslogng_merge_objects($a, $b) { return array(); }
function syslogng_test_object_syntax($objects) { return ''; }
PHP;
eval($stubs . $function);
function check_syslog(bool $ok, string $message): void {
	if (!$ok) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}
$good = array('interfaces' => array('lan'), 'default_protocol' => 'udp', 'default_port' => '514',
    'default_logdir' => '/var/syslog-ng', 'default_logfile' => 'syslog.log');
foreach (array(array('default_protocol' => 'udp; id'), array('default_protocol' => array('udp')),
    array('default_port' => '514; id'), array('default_port' => '0'), array('default_port' => array('514'))) as $bad) {
	$GLOBALS['commands'] = array(); $errors = array();
	SyslogAudit\syslogng_validate_general(array_replace($good, $bad), $errors);
	check_syslog((bool)$errors && !$GLOBALS['commands'], 'invalid protocol/port never reaches sockstat');
}
foreach (array('udp', 'tcp', 'tls') as $protocol) {
	$GLOBALS['commands'] = array(); $errors = array();
	SyslogAudit\syslogng_validate_general(array_replace($good, array('default_protocol' => $protocol)), $errors);
	check_syslog(!$errors && count($GLOBALS['commands']) === 1, 'valid listener settings still run the socket conflict check');
	$expected = ($protocol === 'tls') ? 'tcp' : $protocol;
	check_syslog(str_contains($GLOBALS['commands'][0], '-P ' . escapeshellarg($expected)), 'TLS maps to its TCP transport');
}
echo "syslog-ng validation regression tests passed.\n";
