<?php
/*
 * fleet_action.php
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
 * Quick actions from the dashboard's tile menu (POST, answers JSON). The
 * action is recorded as an operation, so the tile shows its progress on
 * every screen until it is over. Needs the full Fleet privilege.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function fleet_action_answer(int $code, string $message): void {
	http_response_code($code);
	echo json_encode(array('ok' => $code === 200, 'message' => $message));
	exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
	fleet_action_answer(405, gettext('Use POST.'));
}
/* Like the other pages: nothing is created on a controller that is off (or a standby): no database, no actions. */
if (!fleet_ctl_settings()['enable'] || !is_file(FLEET_DATA . '/fleet.db')) {
	fleet_action_answer(404, gettext('Fleet is not turned on on this firewall.'));
}
$box = fleet_box_get((string)($_POST['id'] ?? ''));
if ($box === null) {
	fleet_action_answer(404, gettext('That firewall is not in the fleet any more.'));
}
$who = (string)($_SESSION['Username'] ?? 'admin');
try {
	switch ((string)($_POST['action'] ?? '')) {
	case 'reboot':
		fleet_action_answer(200, fleet_box_reboot($box, $who));
		break;
	case 'backup':
		/* The tile shows "Backing up" while this request runs. */
		session_write_close();
		fleet_action_answer(200, (fleet_box_backup_now($box, $who) === 'stored') ? 'Backed up and checked' : 'No change since the last backup');
		break;
	default:
		fleet_action_answer(400, gettext('Unknown action.'));
	}
} catch (RuntimeException | FleetJoinError $e) {
	fleet_action_answer(409, $e->getMessage());
} catch (Throwable $e) {
	/* The script reads JSON: an uncaught error would send an HTML page. */
	error_log('Fleet action failed: ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine());
	fleet_action_answer(500, gettext('The action failed unexpectedly. See the system log.'));
}
