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
$v = function ($f) {
	return (int)@filemtime('/usr/local/www/fleet/assets/' . $f);
};
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>FreeSense Fleet</title>
<link rel="stylesheet" href="/fleet/assets/fleet-kiosk.css?v=<?=$v('fleet-kiosk.css')?>">
</head>
<body>
<header class="k-top">
	<div class="k-brand"><span class="k-mark" aria-hidden="true">FS</span><span id="k-title">FreeSense Fleet</span></div>
	<p class="k-headline" id="k-headline" aria-live="polite">Connecting...</p>
	<ul class="k-counts" id="k-counts" aria-label="Firewalls by state"></ul>
	<div class="k-side">
		<time class="k-clock" id="k-clock"></time>
		<span class="k-fresh" id="k-fresh"></span>
		<span class="k-tools">
			<button type="button" id="k-sound" aria-pressed="false">Turn sound on</button>
			<button type="button" id="k-full">Full screen</button>
		</span>
	</div>
</header>
<div class="k-ops" id="k-ops" hidden></div>
<main class="k-grid" id="k-grid" aria-label="Firewalls"></main>
<footer class="k-foot"><span id="k-page"></span></footer>
<div class="k-blocked" id="k-blocked" hidden>
	<h1>This screen is not connected</h1>
	<p id="k-blocked-text">The kiosk link is missing its key, or the key was revoked, or this screen is on a network the key is not allowed from.</p>
	<p>An administrator makes a new link in FreeSense Fleet under Dashboard, NOC screens.</p>
</div>
<script src="/fleet/assets/fleet-kiosk.js?v=<?=$v('fleet-kiosk.js')?>"></script>
</body>
</html>
