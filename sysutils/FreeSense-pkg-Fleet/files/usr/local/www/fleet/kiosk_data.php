<?php
/*
 * kiosk_data.php
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
 * The NOC screen's data. There is no WebUI session here on purpose (a
 * wall screen never logs in): the kiosk key in the X-Kiosk-Key header
 * and the screen's allowed networks decide, on every request. Read only;
 * the answer holds no secrets, and with "hide names" no names or
 * addresses either. A refused request waits and says nothing about why.
 */

require_once('config.inc');
require_once('fleet.inc');

header('Content-Type: application/json');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

$deny = function (int $status) {
	usleep(400000);
	http_response_code($status);
	echo json_encode(array('error' => 'This screen is not allowed. Ask an administrator for a new kiosk link.'));
	exit;
};

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
	$deny(405);
}
if (!fleet_ctl_settings()['enable'] || !is_file(FLEET_DATA . '/fleet.db')) {
	$deny(403);
}
$ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
$now = time();
list($screen, $why) = fleet_kiosk_check((string)($_SERVER['HTTP_X_KIOSK_KEY'] ?? ''), $ip, $now);
if ($screen === null) {
	/* One audit line per address per 10 minutes, so a screen left on with a revoked key does not fill the log. */
	$q = fleet_db()->prepare("SELECT COUNT(*) FROM audit WHERE action = 'kiosk_denied' AND detail LIKE ? AND time > ?");
	$q->execute(array($ip . ':%', $now - 600));
	if ((int)$q->fetchColumn() === 0) {
		fleet_audit('kiosk', 'kiosk_denied', "{$ip}: {$why}");
	}
	$deny(403);
}

$data = fleet_dashboard_data(
    fleet_db()->query('SELECT node_id, name, label, overlay, role, state, last_seen, error, status, update_info, (SELECT MAX(time) FROM backups b WHERE b.node_id = boxes.node_id) AS last_backup FROM boxes')->fetchAll(),
    (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn(), $now, fleet_groups_by_box(), fleet_ops_for_tiles($now), array());
echo json_encode(fleet_kiosk_view($data, fleet_ops_groups_running(), !empty($screen['hide']), (string)$screen['name']));
