<?php
/* Test stand-ins for the FreeSense base functions Threat Shield uses. */

$GLOBALS['ts_test_config'] = $GLOBALS['ts_test_config'] ?? [];
$GLOBALS['ts_test_calls'] = [];

if (!function_exists('gettext')) {
	function gettext($s) { return $s; }
}

function array_get_path(array $arr, string $path, $default = null) {
	foreach (explode('/', trim($path, '/')) as $k) {
		if (!is_array($arr) || !array_key_exists($k, $arr)) return $default;
		$arr = $arr[$k];
	}
	return $arr;
}

function config_get_path(string $path, $default = null) {
	return array_get_path($GLOBALS['ts_test_config'], $path, $default);
}

function config_set_path(string $path, $value) {
	$ref = &$GLOBALS['ts_test_config'];
	foreach (explode('/', trim($path, '/')) as $k) {
		if (!isset($ref[$k]) || !is_array($ref[$k])) $ref[$k] = [];
		$ref = &$ref[$k];
	}
	$ref = $value;
	return $value;
}

function config_del_path(string $path) {
	$keys = explode('/', trim($path, '/'));
	$last = array_pop($keys);
	$ref = &$GLOBALS['ts_test_config'];
	foreach ($keys as $k) {
		if (!isset($ref[$k])) return null;
		$ref = &$ref[$k];
	}
	unset($ref[$last]);
	return true;
}

function config_path_enabled(string $path, string $key = 'enable') {
	return config_get_path("{$path}/{$key}") !== null;
}

function write_config($desc = '') {
	$GLOBALS['ts_test_calls'][] = ['write_config', $desc];
	return $GLOBALS['ts_test_config'];
}
