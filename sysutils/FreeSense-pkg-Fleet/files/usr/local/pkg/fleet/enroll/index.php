<?php
/*
 * enroll/index.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2026 The FreeSense Project
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The FreeSense Fleet enrollment endpoint (/fleet/join/*), served by the
 * controller's own nginx on the enrollment port. It deliberately loads no
 * WebGUI code and does not read config.xml: only the Fleet store.
 */

set_include_path('/etc/inc:/usr/local/pkg');
if (!function_exists('gettext')) {
	function gettext($t) { return $t; }
}
require_once('fleet.inc');

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$bearer = '';
if (preg_match('/^\s*Bearer\s+(\S+)\s*$/i', (string)($_SERVER['HTTP_AUTHORIZATION'] ?? ''), $m)) {
	$bearer = $m[1];
}
$body = json_decode((string)file_get_contents('php://input'), true);
$path = (string)parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
/* A standby controller fetching its copy, or asking for this server's role. */
if (strpos($path, '/fleet/standby/') === 0) {
	try {
		list($status, $reply) = fleet_standby_handle(strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')), $path, $bearer, is_array($body) ? $body : array(), time());
	} catch (Throwable $e) {
		error_log('FreeSense Fleet standby: ' . $e->getMessage());
		list($status, $reply) = array(500, array('error' => array('code' => 'internal_error', 'message' => 'Internal error.')));
	}
	http_response_code($status);
	echo json_encode($reply, JSON_UNESCAPED_SLASHES);
	exit;
}
try {
	list($status, $reply) = fleet_enroll_handle(strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')),
	    (string)parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH), $bearer, is_array($body) ? $body : array(),
	    (string)($_SERVER['REMOTE_ADDR'] ?? ''), time(), array(
		'controller_wg_pub' => (string)base64_decode((string)fleet_setting('wg_public', '')),
		'endpoint' => (string)fleet_setting('wg_endpoint', ''),
		'on_joined' => 'fleet_ctl_peer_add',
		'ts_address' => function_exists('fleet_ts_controller_address') ? fleet_ts_controller_address() : null,
	));
} catch (Throwable $e) {
	error_log('FreeSense Fleet enrollment: ' . $e->getMessage());
	list($status, $reply) = array(500, array('error' => array('code' => 'internal_error', 'message' => 'Internal error.')));
}
http_response_code($status);
echo json_encode($reply, JSON_UNESCAPED_SLASHES);
