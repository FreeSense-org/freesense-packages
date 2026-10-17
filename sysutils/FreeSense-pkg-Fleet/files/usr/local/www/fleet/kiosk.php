<?php
/*
 * kiosk.php
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
 * The NOC screen: a static page with no session. Its kiosk key is in the
 * URL fragment (#fkk_...), which the browser never sends, and
 * fleet-kiosk.js asks kiosk_data.php with it. Nothing here reads fleet
 * data.
 */

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'");
require_once('fleet/fleet_kiosk.inc');
$v = function ($f) {
	return (int)@filemtime('/usr/local/www/fleet/assets/' . $f);
};
/* ?style= and ?theme= pin the look; otherwise the screen takes the one saved for it. */
list($style, $theme) = fleet_kiosk_look((string)($_GET['style'] ?? ''), (string)($_GET['theme'] ?? ''));
echo fleet_kiosk_page(false, $style, $theme, isset($_GET['style']) || isset($_GET['theme']), array('css' => $v('fleet-kiosk.css'), 'js' => $v('fleet-kiosk.js'), 'charts' => $v('fleet-charts.js')));
