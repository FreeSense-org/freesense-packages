<?php
/*
 * noc_data.php
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
 * The live NOC view's data, for a logged-in WebUI user (the session and
 * the Fleet dashboard privilege decide). The same answer as a kiosk
 * screen's, with names and links, never hidden.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

header('Content-Type: application/json');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

if (!fleet_ctl_settings()['enable'] || !is_file(FLEET_DATA . '/fleet.db')) {
	http_response_code(403);
	echo json_encode(array('error' => 'This firewall is not a fleet controller.'));
	exit;
}
$now = time();
$data = fleet_dashboard_data(
    fleet_db()->query('SELECT node_id, name, label, overlay, role, state, last_seen, error, status, update_info, (SELECT MAX(time) FROM backups b WHERE b.node_id = boxes.node_id) AS last_backup FROM boxes')->fetchAll(),
    (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn(), $now, fleet_groups_by_box(), fleet_ops_for_tiles($now), array());
echo json_encode(fleet_kiosk_view($data, fleet_ops_groups_running(), false, 'Fleet live view'));
