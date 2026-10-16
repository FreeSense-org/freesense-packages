<?php
/*
 * noc.php
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
 * The live NOC view inside the WebUI: the NOC screen for a logged-in
 * user, full screen in its own tab, with a style picker and links to the
 * firewalls. It needs no kiosk key: the WebUI session decides
 * (noc_data.php). ?style= and ?theme= choose the look.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'self'");
$v = function ($f) {
	return (int)@filemtime('/usr/local/www/fleet/assets/' . $f);
};
list($style, $theme) = fleet_kiosk_look((string)($_GET['style'] ?? ''), (string)($_GET['theme'] ?? ''));
echo fleet_kiosk_page(true, $style, $theme, true, array('css' => $v('fleet-kiosk.css'), 'js' => $v('fleet-kiosk.js')));
