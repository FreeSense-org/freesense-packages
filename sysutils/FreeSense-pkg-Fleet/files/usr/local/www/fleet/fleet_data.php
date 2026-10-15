<?php
/*
 * fleet_data.php
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

/* The dashboard's data as JSON (polled by assets/fleet.js), with an ETag so an unchanged fleet costs a 304. */

require_once('guiconfig.inc');
require_once('fleet.inc');

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-cache');
if (!fleet_ctl_settings()['enable'] || !is_file(FLEET_DATA . '/fleet.db')) {
	echo json_encode(fleet_dashboard_data(array(), 0, time()));
	exit;
}
$rows = fleet_db()->query('SELECT node_id, name, label, overlay, role, state, last_seen, error, status, (SELECT MAX(time) FROM backups b WHERE b.node_id = boxes.node_id) AS last_backup FROM boxes')->fetchAll();
$pending = (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn();
$data = fleet_dashboard_data($rows, $pending, time());
/* The clock is not part of the ETag: only a change in the fleet is. */
$etag = '"' . substr(hash('sha256', json_encode(array_diff_key($data, array('now' => 1)))), 0, 16) . '"';
header("ETag: {$etag}");
/* nginx gzip turns the tag into a weak one (W/".."). */
if (preg_replace('#^W/#', '', trim((string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? ''))) === $etag) {
	http_response_code(304);
	exit;
}
echo json_encode($data, JSON_UNESCAPED_SLASHES);
