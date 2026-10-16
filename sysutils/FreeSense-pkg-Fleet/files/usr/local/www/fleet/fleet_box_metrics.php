<?php
/*
 * fleet_box_metrics.php
 *
 * part of FreeSense (https://freesense.org)
 * Copyright (c) 2025-2026 FreeSense
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
 * One firewall's system metrics as JSON, read from the firewall through
 * Fleet (polled by assets/fleet-metrics.js on the firewall's System view):
 * what=live (CPU, memory, disks, states, uptime, interfaces) or
 * what=history&range=1h|24h|7d|30d (CPU and memory from its RRD history).
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-cache');

$box = fleet_ctl_settings()['enable'] ? fleet_box_get((string)($_GET['id'] ?? '')) : null;
if ($box === null) {
	http_response_code(404);
	echo json_encode(array('error' => gettext('That firewall is not in the fleet.')));
	exit;
}
if ($box['state'] === 'offline') {
	http_response_code(503);
	echo json_encode(array('error' => gettext('The firewall is offline; its metrics come back when it answers again.')));
	exit;
}
$what = (string)($_GET['what'] ?? 'live');
try {
	if ($what === 'history') {
		$range = (string)($_GET['range'] ?? '24h');
		if (!in_array($range, array('1h', '24h', '7d', '30d'), true)) {
			$range = '24h';
		}
		list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/status/system/history?range=' . $range);
		if ($code !== 200) {
			throw new RuntimeException(($code === 404) ? gettext('The firewall has no history yet.') : sprintf(gettext('The firewall answered HTTP %d.'), $code));
		}
		echo json_encode(array('history' => $json['data'] ?? null), JSON_UNESCAPED_SLASHES);
		exit;
	}
	list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/status/system');
	if ($code !== 200) {
		throw new RuntimeException(sprintf(gettext('The firewall answered HTTP %d.'), $code));
	}
	list($icode, $ijson) = fleet_box_call($box, 'GET', '/api/v1/status/interfaces');
	$ifs = array();
	foreach ((($icode === 200) ? (array)($ijson['data'] ?? array()) : array()) as $i) {
		$ifs[] = array('name' => (string)($i['description'] ?? $i['name'] ?? ''), 'if' => (string)($i['if'] ?? ''), 'status' => (string)($i['status'] ?? ''),
		    'ip' => (string)($i['ipaddr'] ?? ''), 'mac' => (string)($i['macaddr'] ?? ''), 'errors' => (int)($i['inerrs'] ?? 0) + (int)($i['outerrs'] ?? 0));
	}
	echo json_encode(array('system' => $json['data'] ?? null, 'interfaces' => $ifs, 'time' => time()), JSON_UNESCAPED_SLASHES);
} catch (RuntimeException | FleetJoinError $e) {
	http_response_code(502);
	echo json_encode(array('error' => $e->getMessage()));
}
