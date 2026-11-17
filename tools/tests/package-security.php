<?php
/*
 * Copyright (c) 2026 The FreeSense Project
 * SPDX-License-Identifier: Apache-2.0
 * Regression checks for package command, path and custom-option boundaries.
 */
function package_check(bool $ok, string $message): void {
	if (!$ok) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}
function package_functions(string $path, array $names): string {
	$source = file_get_contents(dirname(__DIR__, 2) . '/' . $path);
	$code = '';
	foreach ($names as $name) {
		$start = strpos($source, "function {$name}(");
		package_check($start !== false, "{$name} exists");
		$end = strpos($source, "\n}\n", $start);
		package_check($end !== false, "{$name} has file scope");
		$code .= substr($source, $start, $end - $start + 3) . "\n";
	}
	return $code;
}
eval('namespace PackageAudit;' . package_functions('dns/FreeSense-pkg-bind/files/usr/local/pkg/bind.inc', array('bind_zone_name_valid')));
foreach (array('.', 'example.test', 'example.test.', '_service.example.test', '0.192.in-addr.arpa') as $name) {
	package_check(PackageAudit\bind_zone_name_valid($name), 'normal/root/reverse zone accepted');
}
foreach (array(null, array('example.test'), '', '../conf', '-option', 'example;id', "example.test\n", str_repeat('a', 64) . '.test') as $name) {
	package_check(!PackageAudit\bind_zone_name_valid($name), 'invalid zone rejected');
}
$stubs = <<<'PHP'
namespace PackageAudit;
function gettext($s) { return $s; }
function is_URL($url, $httpOnly = false) {
	if (!$httpOnly) { throw new \RuntimeException('Tailscale must require HTTP(S)'); }
	return filter_var($url, FILTER_VALIDATE_URL) && in_array(strtolower(parse_url($url, PHP_URL_SCHEME)), array('http', 'https'), true);
}
PHP;
eval($stubs . package_functions('security/FreeSense-pkg-Tailscale/files/usr/local/pkg/tailscale/tailscale_auth.inc', array('tailscale_auth_validation_hook')) . package_functions('security/FreeSense-pkg-Tailscale/files/usr/local/pkg/tailscale/tailscale_common.inc', array('tailscale_format_sysrc_variable')));
foreach (array(array(), array('loginserver' => 'https://control.example.test', 'preauthkey' => 'tskey-auth-example_123')) as $post) {
	$errors = array(); PackageAudit\tailscale_auth_validation_hook($post, $errors);
	package_check(!$errors, 'valid Tailscale authentication values accepted');
}
foreach (array(array('loginserver' => array('https://example.test')), array('loginserver' => 'file:///etc/passwd'), array('loginserver' => 'https://example.test/$(id)'), array('preauthkey' => array('key')), array('preauthkey' => "key\n")) as $post) {
	$errors = array(); PackageAudit\tailscale_auth_validation_hook($post, $errors);
	package_check((bool)$errors, 'invalid Tailscale authentication values rejected');
}
foreach (array('YES', 'https://control.example.test/path?key=value', 'value with spaces', 'quote\'value', '$(printf unsafe)') as $value) {
	$formatted = PackageAudit\tailscale_format_sysrc_variable('setting', $value);
	$output = shell_exec('printf "%s" ' . $formatted);
	$expected = 'setting=' . str_replace(array('"', '\\', '$', '`', "\r", "\n", "\0"), '', $value);
	package_check($output === $expected, 'sysrc gets one literal argument with safe rc.conf content');
}
eval('namespace PackageAudit;' . package_functions('www/FreeSense-pkg-WebGateway/files/usr/local/pkg/webgateway.inc', array('webgateway_custom_options_allowed')));
foreach (array('cache_mem 64 MB', "# sslcrtvalidator_program ignored\nmaximum_object_size 32 MB") as $options) {
	package_check(PackageAudit\webgateway_custom_options_allowed($options), 'ordinary expert options accepted');
}
foreach (array('sslcrtvalidator_program /bin/sh', 'sslpassword_program /bin/sh', "sslcrtvalidator_pro\\\ngram /bin/sh", 'auth_param basic program /bin/sh', 'include /etc/file', 'http_access allow all') as $options) {
	package_check(!PackageAudit\webgateway_custom_options_allowed($options), 'protected directives and continuations rejected');
}
$root = sys_get_temp_dir() . '/freesense-package-' . bin2hex(random_bytes(6));
mkdir($root, 0700); mkdir($root . '/files'); mkdir($root . '/files-other');
file_put_contents($root . '/files/good [1].txt', 'ok'); file_put_contents($root . '/outside', 'private'); file_put_contents($root . '/files-other/outside', 'private');
define('PackageAudit\\FILES_DIR', $root . '/files'); define('PackageAudit\\LOG_PREFIX_PKG_TFTPD', 'tftpd');
eval('namespace PackageAudit; function logger(...$a) {} function file_notice(...$a) {}' . package_functions('ftp/FreeSense-pkg-tftpd/files/usr/local/pkg/tftpd.inc', array('tftp_filesdir_bounds_check')));
package_check(PackageAudit\tftp_filesdir_bounds_check($root . '/files/good [1].txt', 'test') === $root . '/files/good [1].txt', 'ordinary TFTP filename is preserved literally');
foreach (array(null, array('x'), $root . '/files/../outside', $root . '/files-other/outside', $root . '/files', $root . '/files/missing') as $path) {
	package_check(PackageAudit\tftp_filesdir_bounds_check($path, 'test') === false, 'TFTP path traversal and invalid files rejected');
}
if (symlink($root . '/outside', $root . '/files/link')) {
	package_check(PackageAudit\tftp_filesdir_bounds_check($root . '/files/link', 'test') === false, 'TFTP symlink escape rejected');
	unlink($root . '/files/link');
}
unlink($root . '/files/good [1].txt'); unlink($root . '/outside'); unlink($root . '/files-other/outside'); rmdir($root . '/files'); rmdir($root . '/files-other'); rmdir($root);
$page = file_get_contents(dirname(__DIR__, 2) . '/ftp/FreeSense-pkg-tftpd/files/usr/local/www/tftp_files.php');
package_check(str_contains($page, "(\$_POST['act'] ?? null) === 'del'") && str_contains($page, "(\$_POST['t'] ?? null) === 'restore'"), 'TFTP mutations take POST only');
package_check(!preg_match('/^\s*unlink_if_exists\(/m', $page) && substr_count($page, 'usepost') >= 2, 'literal deletion and CSRF-aware links retained');
echo "Package security boundary regression tests passed.\n";
