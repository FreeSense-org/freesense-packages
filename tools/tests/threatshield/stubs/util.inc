<?php
function safe_mkdir($path, $mode = 0755) { return true; }
function mwexec($cmd, $mute = false) { $GLOBALS['ts_test_calls'][] = ['mwexec', $cmd]; return 0; }
function mwexec_bg($cmd) { $GLOBALS['ts_test_calls'][] = ['mwexec_bg', $cmd]; }
function logger($level, $msg, $prefix = '') { $GLOBALS['ts_test_calls'][] = ['logger', $msg]; }
function file_notice($id, $msg, $category = '', $url = '', $priority = 1) { $GLOBALS['ts_test_calls'][] = ['file_notice', $msg]; }
function install_cron_job($cmd, $active = false, $min = '0', $hour = '*', $mday = '*', $month = '*', $wday = '*', $who = 'root') {
	$GLOBALS['ts_test_calls'][] = ['cron', $cmd, $active, $min];
}
function get_real_interface($if) { return $GLOBALS['ts_test_ifmap'][$if] ?? ''; }
function get_interface_ip($if) { return $GLOBALS['ts_test_ips'][$if] ?? null; }
function get_interface_subnet($if) { return $GLOBALS['ts_test_subnets'][$if] ?? null; }
function interface_has_gateway($if) { return in_array($if, $GLOBALS['ts_test_wans'] ?? ['wan'], true); }
