<?php
/*
 * fleet_nav.php
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
 * The top-bar item as JSON, asked every 15 s by freesense-ui.js
 * (plugin_navbar), with the notices for actions that finished since the
 * last ask (?since=<time>; the first ask only gets the cursor).
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

/* ?panel=1: the summary under the item, as HTML. */
if (!empty($_GET['panel'])) {
	header('Content-Type: text/html; charset=utf-8');
	header('Cache-Control: no-store');
	echo (fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db')) ? fleet_nav_panel_html(time()) : '';
	exit;
}
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
$item = fleet_plugin_navbar(array());
if ($item === null) {
	echo json_encode(array('hidden' => true, 'badge' => 0));
	exit;
}
$now = time();
$since = (string)($_GET['since'] ?? '');
$item['cursor'] = $now;
$item['toasts'] = ctype_digit($since)
    ? fleet_nav_toasts(fleet_ops_finished_since(max((int)$since, $now - 3600), $now), fleet_opt('toast_done'), fleet_opt('toast_failed')) : array();
echo json_encode($item);
