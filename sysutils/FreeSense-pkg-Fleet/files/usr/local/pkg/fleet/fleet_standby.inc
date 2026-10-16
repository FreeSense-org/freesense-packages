<?php
/*
 * fleet_standby.inc
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
 * A standby controller: a second FreeSense with the Fleet package that
 * keeps a verified copy of this controller and can take over.
 *
 * - Pairing: the primary makes a one-time code (its enrollment URL, TLS
 *   fingerprint, a pull token and a pairing key). Both servers keep
 *   FLEET_STANDBY_PAIRING; the roles swap after a takeover.
 * - Snapshots: the primary's poll seals its self-backup bundle, the master
 *   key and the controller epoch with the pairing key every few minutes;
 *   the standby pulls it over the enrollment port (/fleet/standby/pull).
 * - Firewalls learn the standby: the poll keeps every firewall's
 *   controller endpoints at [primary, standby] (API level 13); a firewall
 *   whose controller stops answering moves to the next endpoint itself.
 * - Takeover: by hand, or automatically after the primary has been silent
 *   for a while. The standby restores the snapshot (same keys, overlay and
 *   tunnel identity) under its own address with a higher epoch.
 * - Fencing: a controller that meets a higher epoch (at a firewall, or at
 *   its partner) steps down and becomes the standby.
 */

define('FLEET_STANDBY_DIR', FLEET_DATA . '/standby');
define('FLEET_STANDBY_PAIRING', FLEET_STANDBY_DIR . '/pairing.json');
define('FLEET_STANDBY_STATE', FLEET_STANDBY_DIR . '/state.json');
define('FLEET_STANDBY_OUTBOX', FLEET_STANDBY_DIR . '/outbox.enc');
define('FLEET_STANDBY_INBOX', FLEET_STANDBY_DIR . '/inbox.enc');
define('FLEET_STANDBY_CRON', '/usr/local/bin/php /usr/local/sbin/freesense-fleet-standby');
define('FLEET_STANDBY_AAD', 'FreeSense-Fleet-Standby-v1');
define('FLEET_STANDBY_CODE_PREFIX', 'FSB1-');
/* The firewall API level that knows controller endpoints. */
define('FLEET_STANDBY_API_LEVEL', 13);
define('FLEET_STANDBY_TAKEOVER', array('manual' => 'By hand', 'auto' => 'Automatically'));
/* How often the snapshot is rebuilt (minutes), and after how long without the primary an automatic takeover happens. */
define('FLEET_STANDBY_INTERVALS', array(2, 5, 10, 15, 30));
define('FLEET_STANDBY_AUTO_MINUTES', array(5, 10, 15, 30, 60));
/* A standby that has not pulled for this long is a problem (seconds). */
define('FLEET_STANDBY_LATE', 900);

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: base64url without padding, and back. */
function fleet_standby_b64u(string $bytes): string {
	return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

function fleet_standby_unb64u(string $s): ?string {
	$b = base64_decode(strtr($s, '-_', '+/'), true);
	return ($b === false) ? null : $b;
}

/* pure: the pairing code for the standby. */
function fleet_standby_code_make(string $url, string $fp, string $token, string $key): string {
	return FLEET_STANDBY_CODE_PREFIX . fleet_standby_b64u(json_encode(array('u' => $url, 'f' => $fp, 't' => fleet_standby_b64u($token), 'k' => fleet_standby_b64u($key)),
	    JSON_UNESCAPED_SLASHES));
}

/* pure: a pairing code read back as {url, fp, token, key}, or null. */
function fleet_standby_code_read(string $code): ?array {
	$code = preg_replace('/\s+/', '', $code);
	if (strpos($code, FLEET_STANDBY_CODE_PREFIX) !== 0) {
		return null;
	}
	$j = json_decode((string)fleet_standby_unb64u(substr($code, strlen(FLEET_STANDBY_CODE_PREFIX))), true);
	if (!is_array($j)) {
		return null;
	}
	$token = fleet_standby_unb64u((string)($j['t'] ?? ''));
	$key = fleet_standby_unb64u((string)($j['k'] ?? ''));
	if (!preg_match('~^https://(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9][A-Za-z0-9.-]*):[0-9]{1,5}$~D', (string)($j['u'] ?? '')) ||
	    !preg_match('/^[0-9a-f]{64}$/D', (string)($j['f'] ?? '')) || ($token === null) || (strlen($token) !== 32) || ($key === null) || (strlen($key) !== 32)) {
		return null;
	}
	return array('url' => $j['u'], 'fp' => $j['f'], 'token' => $token, 'key' => $key);
}

/* pure: seal and open a snapshot with the pairing key (AES-256-GCM, its own associated data). */
function fleet_standby_seal(string $plain, string $key): string {
	$nonce = random_bytes(12);
	$tag = '';
	$data = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, FLEET_STANDBY_AAD);
	return 's1:' . base64_encode($nonce) . ':' . base64_encode($tag) . ':' . base64_encode((string)$data);
}

function fleet_standby_unseal(string $sealed, string $key): ?string {
	$p = explode(':', $sealed);
	$nonce = (count($p) === 4) ? (string)base64_decode($p[1]) : '';
	$tag = (count($p) === 4) ? (string)base64_decode($p[2]) : '';
	if (($p[0] !== 's1') || (strlen($nonce) !== 12) || (strlen($tag) !== 16)) {
		return null;
	}
	$plain = openssl_decrypt((string)base64_decode($p[3]), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag,
	    FLEET_STANDBY_AAD);
	return ($plain === false) ? null : $plain;
}

/* pure: the controller endpoints firewalls should know: this controller, then the standby. */
function fleet_standby_endpoints_want(string $own, string $standby): array {
	return (($standby === '') || ($standby === $own)) ? array($own) : array($own, $standby);
}

/*
 * pure: what to do about one firewall's controller endpoints, from its
 * status: 'ok', 'push', 'newer' (it has seen a newer controller: this one
 * was replaced) or 'skip' (too old, or never answered).
 */
function fleet_standby_box_action(array $status, array $want, int $epoch): string {
	if ((int)($status['api_level'] ?? 0) < FLEET_STANDBY_API_LEVEL) {
		return 'skip';
	}
	$has = (int)($status['controller_epoch'] ?? 0);
	if ($has > $epoch) {
		return 'newer';
	}
	return ((($status['controller_endpoints'] ?? null) === $want) && ($has === $epoch)) ? 'ok' : 'push';
}

/* pure: is an automatic takeover due? */
function fleet_standby_takeover_due(array $pairing, array $state, int $now): bool {
	if ((($pairing['role'] ?? '') !== 'standby') || (($state['takeover'] ?? 'manual') !== 'auto') || empty($state['snapshot'])) {
		return false;
	}
	$minutes = in_array((int)($state['auto_minutes'] ?? 0), FLEET_STANDBY_AUTO_MINUTES, true) ? (int)$state['auto_minutes'] : 15;
	/* Only after the primary answered at least once, and has been silent since. */
	return ((int)($state['last_ok'] ?? 0) > 0) && (($now - (int)$state['last_ok']) >= 60 * $minutes);
}

/* pure: the host part of an https://host:port URL. */
function fleet_standby_url_host(string $url): string {
	$h = (string)parse_url($url, PHP_URL_HOST);
	return trim($h, '[]');
}

/* ------------------------------------------------------------------ */
/* Files                                                               */
/* ------------------------------------------------------------------ */

function fleet_standby_read(string $file): array {
	$j = json_decode((string)@file_get_contents($file), true);
	return is_array($j) ? $j : array();
}

function fleet_standby_write(string $file, array $data): void {
	if (!is_dir(FLEET_STANDBY_DIR)) {
		@mkdir(FLEET_STANDBY_DIR, 0700, true);
	}
	$tmp = $file . '.tmp';
	if ((@file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES)) === false) || !@chmod($tmp, 0600) || !@rename($tmp, $file)) {
		throw new RuntimeException("{$file} could not be written.");
	}
}

/* The pairing: {role: primary|standby, token, key (base64), ...}; [] when there is none. */
function fleet_standby_pairing(): array {
	$p = fleet_standby_read(FLEET_STANDBY_PAIRING);
	if (!in_array($p['role'] ?? '', array('primary', 'standby'), true)) {
		return array();
	}
	$p['token'] = (string)base64_decode((string)($p['token'] ?? ''));
	$p['key'] = (string)base64_decode((string)($p['key'] ?? ''));
	return ((strlen($p['token']) === 32) && (strlen($p['key']) === 32)) ? $p : array();
}

function fleet_standby_pairing_save(array $p): void {
	$p['token'] = base64_encode($p['token']);
	$p['key'] = base64_encode($p['key']);
	fleet_standby_write(FLEET_STANDBY_PAIRING, $p);
}

function fleet_standby_state(): array {
	return fleet_standby_read(FLEET_STANDBY_STATE);
}

function fleet_standby_state_merge(array $set): array {
	$s = array_merge(fleet_standby_state(), $set);
	fleet_standby_write(FLEET_STANDBY_STATE, $s);
	return $s;
}

/* This server's role: 'primary', 'standby' or '' (no standby set up). */
function fleet_standby_role(): string {
	return (string)(fleet_standby_pairing()['role'] ?? '');
}

/* ------------------------------------------------------------------ */
/* Primary                                                             */
/* ------------------------------------------------------------------ */

/* The controller epoch (raised by every takeover). */
function fleet_ctl_epoch(): int {
	return (int)fleet_setting('ctl_epoch', '0');
}

/* Start pairing a standby: a new token and key. Returns the pairing code (shown once). */
function fleet_standby_pair_new(string $takeover, int $interval, int $auto_minutes, string $who): string {
	$s = fleet_ctl_settings();
	if (!$s['enable'] || ($s['public_host'] === '')) {
		throw new RuntimeException('Turn on the controller and set its address first.');
	}
	$p = array('role' => 'primary', 'token' => random_bytes(32), 'key' => random_bytes(32), 'created' => time(), 'peer_addr' => '', 'peer_seen' => 0,
	    'peer_version' => '');
	fleet_standby_pairing_save($p);
	fleet_standby_settings_save($takeover, $interval, $auto_minutes);
	@unlink(FLEET_STANDBY_OUTBOX);
	fleet_audit($who, 'standby', 'A standby controller pairing code was made');
	return fleet_standby_code_make('https://' . fleet_hostport($s['public_host'], $s['enroll_port']), fleet_cert_fingerprint(fleet_tls_pem()), $p['token'], $p['key']);
}

/* The takeover settings: kept on the primary, handed to the standby with every pull. */
function fleet_standby_settings(): array {
	$j = json_decode((string)fleet_setting('standby_settings', '{}'), true) ?: array();
	return array(
		'takeover' => isset(FLEET_STANDBY_TAKEOVER[$j['takeover'] ?? '']) ? $j['takeover'] : 'manual',
		'interval' => in_array((int)($j['interval'] ?? 0), FLEET_STANDBY_INTERVALS, true) ? (int)$j['interval'] : 5,
		'auto_minutes' => in_array((int)($j['auto_minutes'] ?? 0), FLEET_STANDBY_AUTO_MINUTES, true) ? (int)$j['auto_minutes'] : 15,
	);
}

function fleet_standby_settings_save(string $takeover, int $interval, int $auto_minutes): void {
	fleet_setting_set('standby_settings', json_encode(array('takeover' => isset(FLEET_STANDBY_TAKEOVER[$takeover]) ? $takeover : 'manual',
	    'interval' => in_array($interval, FLEET_STANDBY_INTERVALS, true) ? $interval : 5,
	    'auto_minutes' => in_array($auto_minutes, FLEET_STANDBY_AUTO_MINUTES, true) ? $auto_minutes : 15)));
}

/* Remove the standby: firewalls go back to this controller only. */
function fleet_standby_remove(string $who): void {
	@unlink(FLEET_STANDBY_PAIRING);
	@unlink(FLEET_STANDBY_OUTBOX);
	@unlink(FLEET_STANDBY_STATE);
	fleet_audit($who, 'standby', 'The standby controller was removed');
}

/* The standby's tunnel endpoint (host:port) as firewalls should know it, or ''. */
function fleet_standby_peer_endpoint(): string {
	$p = fleet_standby_pairing();
	return ((($p['role'] ?? '') === 'primary') && (($p['peer_addr'] ?? '') !== '')) ? fleet_hostport($p['peer_addr'], fleet_ctl_settings()['wg_port']) : '';
}

/* Build the snapshot for the standby when it is due. */
function fleet_standby_outbox_tick(int $now): void {
	$p = fleet_standby_pairing();
	if (($p['role'] ?? '') !== 'primary') {
		return;
	}
	$age = $now - (int)@filemtime(FLEET_STANDBY_OUTBOX);
	if (is_file(FLEET_STANDBY_OUTBOX) && ($age < 60 * fleet_standby_settings()['interval'])) {
		return;
	}
	$bundle = fleet_self_bundle();
	$bundle['master'] = base64_encode(fleet_master_key());
	$bundle['epoch'] = fleet_ctl_epoch();
	$sealed = fleet_standby_seal(gzencode(json_encode($bundle), 6), $p['key']);
	if (!is_dir(FLEET_STANDBY_DIR)) {
		@mkdir(FLEET_STANDBY_DIR, 0700, true);
	}
	if ((@file_put_contents(FLEET_STANDBY_OUTBOX . '.tmp', $sealed) !== false) && @chmod(FLEET_STANDBY_OUTBOX . '.tmp', 0600)) {
		@rename(FLEET_STANDBY_OUTBOX . '.tmp', FLEET_STANDBY_OUTBOX);
	}
}

/*
 * Keep the firewalls' controller endpoints and epoch current (also the
 * ones that joined later). A firewall that has seen a newer controller
 * means this one was replaced: it steps down.
 */
function fleet_standby_endpoints_tick(): void {
	$own = (string)fleet_setting('wg_endpoint', '');
	if ($own === '') {
		return;
	}
	$want = fleet_standby_endpoints_want($own, fleet_standby_peer_endpoint());
	$epoch = fleet_ctl_epoch();
	foreach (fleet_db()->query("SELECT * FROM boxes WHERE state = 'online'")->fetchAll() as $box) {
		$act = fleet_standby_box_action(json_decode((string)$box['status'], true) ?: array(), $want, $epoch);
		if ($act === 'newer') {
			fleet_standby_step_down(sprintf('%s has seen a newer Fleet controller', $box['label']));
			return;
		}
		if ($act !== 'push') {
			continue;
		}
		list($code, $json) = fleet_box_call($box, 'PUT', '/api/v1/management/controller-endpoints', array('endpoints' => $want, 'epoch' => $epoch));
		if ($code === 409) {
			fleet_standby_step_down(sprintf('%s refused this controller: %s', $box['label'], fleet_box_error($code, $json)));
			return;
		}
	}
}

/* Is the partner the primary with a newer epoch? Asked every few minutes; steps down when it is. */
function fleet_standby_fence_tick(int $now): void {
	$p = fleet_standby_pairing();
	if ((($p['role'] ?? '') !== 'primary') || (($p['peer_addr'] ?? '') === '') || (($now - (int)fleet_setting('standby_fence_checked', '0')) < 120)) {
		return;
	}
	fleet_setting_set('standby_fence_checked', (string)$now);
	$url = 'https://' . fleet_hostport($p['peer_addr'], fleet_ctl_settings()['enroll_port']);
	list($code, $json) = fleet_standby_http($url, fleet_cert_fingerprint(fleet_tls_pem()), $p['token'], '/fleet/standby/state', array());
	if (($code === 200) && (($json['role'] ?? '') === 'primary') && ((int)($json['epoch'] ?? 0) > fleet_ctl_epoch())) {
		fleet_standby_step_down('the standby took over');
	}
}

/* Is the standby late? Alerts once when it stops pulling, once when it is back. */
function fleet_standby_watch_tick(int $now): void {
	$p = fleet_standby_pairing();
	if (($p['role'] ?? '') !== 'primary') {
		return;
	}
	$late = ((int)($p['peer_seen'] ?? 0) > 0) && (($now - (int)$p['peer_seen']) > FLEET_STANDBY_LATE);
	$was = (fleet_setting('standby_late', '0') === '1');
	if ($late !== $was) {
		fleet_setting_set('standby_late', $late ? '1' : '0');
		fleet_alert($late ? 'standby_problem' : 'standby_ok', '', $late ?
		    sprintf('The standby controller %s has not fetched a copy for %d minutes.', $p['peer_addr'], round(($now - (int)$p['peer_seen']) / 60)) :
		    sprintf('The standby controller %s is fetching copies again.', $p['peer_addr']));
	}
}

/*
 * This controller was replaced: stop it (tunnel, enrollment, poll) and
 * become the standby of the new primary, so it follows from now on.
 */
function fleet_standby_step_down(string $why): void {
	$p = fleet_standby_pairing();
	$s = fleet_ctl_settings();
	fleet_audit('system', 'standby', "This controller stepped down: {$why}");
	fleet_alert('controller_takeover', '', "This Fleet controller stepped down ({$why}); it is now the standby.");
	if (!empty($p) && (($p['peer_addr'] ?? '') !== '')) {
		fleet_standby_pairing_save(array('role' => 'standby', 'url' => 'https://' . fleet_hostport($p['peer_addr'], $s['enroll_port']),
		    'fp' => fleet_cert_fingerprint(fleet_tls_pem()), 'token' => $p['token'], 'key' => $p['key'], 'own_addr' => $s['public_host'], 'created' => time()));
		@unlink(FLEET_STANDBY_OUTBOX);
	}
	$cfg = (array)config_get_path('installedpackages/fleet/config/0', array());
	$cfg['enable'] = '';
	config_set_path('installedpackages/fleet/config/0', $cfg);
	write_config('FreeSense Fleet: this controller stepped down; it is now the standby.');
	fleet_sync_config();
	install_cron_job(FLEET_STANDBY_CRON, !empty($p), '*', '*', '*', '*', '*', 'root');
}

/*
 * The enrollment endpoint's /fleet/standby/ part. Answers
 * array(HTTP status, reply). pull: the snapshot (when the standby's copy
 * is older) and the takeover settings; state: this server's role and epoch.
 */
function fleet_standby_handle(string $method, string $path, string $bearer, array $body, int $now): array {
	$p = fleet_standby_pairing();
	if (($method !== 'POST') || empty($p) || !hash_equals(hash('sha256', $p['token']), hash('sha256', (string)fleet_standby_unb64u($bearer)))) {
		return array(404, array('error' => array('code' => 'not_found')));
	}
	if ($path === '/fleet/standby/state') {
		return array(200, array('role' => $p['role'], 'epoch' => ($p['role'] === 'primary') ? fleet_ctl_epoch() : 0));
	}
	if (($path !== '/fleet/standby/pull') || ($p['role'] !== 'primary')) {
		return array(404, array('error' => array('code' => 'not_found')));
	}
	$addr = trim((string)($body['addr'] ?? ''));
	$was = (string)($p['peer_addr'] ?? '');
	if (($addr !== '') && preg_match('/^(\[[0-9a-fA-F:.]+\]|[0-9a-fA-F:.]+|[A-Za-z0-9][A-Za-z0-9.-]*)$/D', $addr)) {
		$p['peer_addr'] = trim($addr, '[]');
	}
	/* A new standby address joins the allowed list. */
	if (($p['peer_addr'] !== $was) && function_exists('fleet_access_reload')) {
		fleet_access_reload();
	}
	$p['peer_seen'] = $now;
	$p['peer_version'] = substr((string)($body['version'] ?? ''), 0, 64);
	fleet_standby_pairing_save($p);
	$sealed = (string)@file_get_contents(FLEET_STANDBY_OUTBOX);
	$sha = ($sealed === '') ? '' : hash('sha256', $sealed);
	return array(200, array('role' => 'primary', 'epoch' => fleet_ctl_epoch(), 'settings' => fleet_standby_settings(), 'sha' => $sha,
	    'snapshot' => (($sha !== '') && ($sha !== (string)($body['last'] ?? ''))) ? $sealed : null));
}

/* ------------------------------------------------------------------ */
/* Standby                                                             */
/* ------------------------------------------------------------------ */

/* POST JSON to the partner's enrollment port with the pinned certificate. Returns array(HTTP status or 0, decoded reply). */
function fleet_standby_http(string $url, string $fp, string $token, string $path, array $body, int $timeout = 30): array {
	$ctx = stream_context_create(array(
		'http' => array('method' => 'POST', 'timeout' => $timeout, 'ignore_errors' => true, 'content' => json_encode($body),
		    'header' => "Content-Type: application/json\r\nAuthorization: Bearer " . fleet_standby_b64u($token) . "\r\n"),
		'ssl' => array('verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true, 'peer_fingerprint' => array('sha256' => $fp)),
	));
	$raw = @file_get_contents($url . $path, false, $ctx);
	$head = function_exists('http_get_last_response_headers') ? (array)http_get_last_response_headers() : array();
	$code = preg_match('/^HTTP\/\S+\s+(\d{3})/', (string)($head[0] ?? ''), $m) ? (int)$m[1] : 0;
	return array($code, ($raw === false) ? array() : (json_decode($raw, true) ?: array()));
}

/* pure: a snapshot opened and checked: array(bundle, summary) or a problem text. */
function fleet_standby_open(string $sealed, string $key) {
	$plain = fleet_standby_unseal($sealed, $key);
	$bundle = ($plain === null) ? null : json_decode((string)@gzdecode($plain), true);
	if (!is_array($bundle) || (($bundle['format'] ?? '') !== 'freesense-fleet-self-v1') || (strlen((string)base64_decode((string)($bundle['master'] ?? ''))) !== 32)) {
		return 'The copy could not be opened (wrong pairing key, or damaged).';
	}
	return array($bundle, array('created' => (int)$bundle['created'], 'schema' => (int)$bundle['schema'], 'epoch' => (int)($bundle['epoch'] ?? 0)));
}

/* Check a snapshot's database opens and is sound; adds what it holds to $summary. Returns a problem text or null. */
function fleet_standby_db_check(array $bundle, array &$summary): ?string {
	$tmp = FLEET_STANDBY_DIR . '/check.db';
	@unlink($tmp);
	if (@file_put_contents($tmp, (string)base64_decode((string)$bundle['db'])) === false) {
		return 'The copy could not be checked: no space.';
	}
	try {
		$db = new PDO('sqlite:' . $tmp, null, null, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
		if ((string)$db->query('PRAGMA quick_check')->fetchColumn() !== 'ok') {
			return 'The database in the copy is damaged.';
		}
		$summary['boxes'] = (int)$db->query('SELECT COUNT(*) FROM boxes')->fetchColumn();
		$summary['groups'] = (int)$db->query('SELECT COUNT(*) FROM fleet_groups')->fetchColumn();
		$db = null;
	} catch (Throwable $e) {
		return 'The database in the copy could not be read: ' . $e->getMessage();
	} finally {
		@unlink($tmp);
	}
	return null;
}

/* Make this server the standby of the primary in $code, after one good pull. Returns a problem text or null. */
function fleet_standby_join(string $code, string $own_addr, string $who): ?string {
	$c = fleet_standby_code_read($code);
	if ($c === null) {
		return 'That is not a standby pairing code. Copy it again from the primary: Fleet > Settings > Standby server.';
	}
	if (!preg_match('/^(\[[0-9a-fA-F:.]+\]|[0-9a-fA-F:.]+|[A-Za-z0-9][A-Za-z0-9.-]*)$/D', $own_addr)) {
		return 'Enter the address firewalls can reach this server at (an IP address or DNS name).';
	}
	if (fleet_ctl_settings()['enable']) {
		return 'This server runs as a Fleet controller. A standby must not be a controller: turn the controller off first.';
	}
	$err = fleet_data_prepare();
	if ($err !== null) {
		return $err;
	}
	$p = array('role' => 'standby', 'url' => $c['url'], 'fp' => $c['fp'], 'token' => $c['token'], 'key' => $c['key'], 'own_addr' => trim($own_addr, '[]'), 'created' => time());
	fleet_standby_pairing_save($p);
	@unlink(FLEET_STANDBY_STATE);
	$problem = fleet_standby_pull(time());
	if ($problem !== null) {
		@unlink(FLEET_STANDBY_PAIRING);
		return $problem;
	}
	install_cron_job(FLEET_STANDBY_CRON, true, '*', '*', '*', '*', '*', 'root');
	logger(LOG_NOTICE, localize_text('FreeSense Fleet: this server is now the standby of %s (by %s)', $c['url'], $who));
	return null;
}

/* Stop being a standby (the copy is deleted). */
function fleet_standby_leave(string $who): void {
	install_cron_job(FLEET_STANDBY_CRON, false, '*', '*', '*', '*', '*', 'root');
	foreach (array(FLEET_STANDBY_PAIRING, FLEET_STANDBY_STATE, FLEET_STANDBY_INBOX) as $f) {
		@unlink($f);
	}
	logger(LOG_NOTICE, localize_text('FreeSense Fleet: this server is no longer a standby (by %s)', $who));
}

/* Fetch a newer copy from the primary and keep it when it checks out. Returns a problem text or null. */
function fleet_standby_pull(int $now): ?string {
	$p = fleet_standby_pairing();
	if (($p['role'] ?? '') !== 'standby') {
		return 'This server is not a standby.';
	}
	$st = fleet_standby_state();
	list($code, $json) = fleet_standby_http($p['url'], $p['fp'], $p['token'], '/fleet/standby/pull',
	    array('addr' => $p['own_addr'], 'version' => trim((string)@file_get_contents('/etc/version')), 'last' => (string)($st['sha'] ?? '')));
	if ($code !== 200) {
		$problem = ($code === 0) ? 'The primary did not answer (or its certificate is not the paired one).' :
		    "The primary refused the request (HTTP {$code}); pair this standby again.";
		fleet_standby_state_merge(array('last_try' => $now, 'last_error' => $problem));
		return $problem;
	}
	$set = array('last_try' => $now, 'last_ok' => $now, 'last_error' => '', 'primary_epoch' => (int)($json['epoch'] ?? 0)) + array_intersect_key((array)($json['settings'] ?? array()),
	    array('takeover' => 1, 'interval' => 1, 'auto_minutes' => 1));
	if (is_string($json['snapshot'] ?? null)) {
		$opened = fleet_standby_open($json['snapshot'], $p['key']);
		$summary = is_array($opened) ? $opened[1] : array();
		$problem = is_array($opened) ? fleet_standby_db_check($opened[0], $summary) : $opened;
		if ($problem !== null) {
			fleet_standby_state_merge(array('last_try' => $now, 'last_error' => $problem));
			return $problem;
		}
		if ((@file_put_contents(FLEET_STANDBY_INBOX . '.tmp', $json['snapshot']) === false) || !@chmod(FLEET_STANDBY_INBOX . '.tmp', 0600) ||
		    !@rename(FLEET_STANDBY_INBOX . '.tmp', FLEET_STANDBY_INBOX)) {
			fleet_standby_state_merge(array('last_try' => $now, 'last_error' => 'The copy could not be stored. Check the free space.'));
			return 'The copy could not be stored. Check the free space.';
		}
		$set += array('sha' => (string)($json['sha'] ?? ''), 'snapshot' => $summary + array('received' => $now));
	}
	fleet_standby_state_merge($set);
	return null;
}

/*
 * Take over as the controller from the newest copy: same keys, overlay
 * and tunnel identity, this server's address, a higher epoch. Firewalls
 * move here by themselves within a few minutes.
 */
function fleet_standby_promote(string $who, string $why): void {
	$p = fleet_standby_pairing();
	$st = fleet_standby_state();
	if (($p['role'] ?? '') !== 'standby') {
		throw new RuntimeException('This server is not a standby.');
	}
	$opened = fleet_standby_open((string)@file_get_contents(FLEET_STANDBY_INBOX), $p['key']);
	if (!is_array($opened)) {
		throw new RuntimeException(is_string($opened) ? $opened : 'There is no copy to take over from.');
	}
	list($bundle) = $opened;
	$epoch = max((int)($bundle['epoch'] ?? 0), (int)($st['primary_epoch'] ?? 0)) + 1;
	$settings = fleet_recover_apply(array((string)base64_decode($bundle['master']), $bundle, array()), true, $who);
	$settings['public_host'] = $p['own_addr'];
	$settings['enable'] = 'on';
	config_set_path('installedpackages/fleet/config/0', $settings);
	write_config('FreeSense Fleet: this server took over as the Fleet controller.');
	fleet_setting_set('ctl_epoch', (string)$epoch);
	fleet_setting_set('standby_settings', json_encode(array_intersect_key($st, array('takeover' => 1, 'interval' => 1, 'auto_minutes' => 1))));
	fleet_standby_pairing_save(array('role' => 'primary', 'token' => $p['token'], 'key' => $p['key'], 'created' => time(),
	    'peer_addr' => fleet_standby_url_host($p['url']), 'peer_seen' => 0, 'peer_version' => ''));
	@unlink(FLEET_STANDBY_STATE);
	install_cron_job(FLEET_STANDBY_CRON, false, '*', '*', '*', '*', '*', 'root');
	fleet_sync_config();
	fleet_audit($who, 'standby', sprintf('This server took over as the controller (%s); copy of %s, epoch %d', $why, date('Y-m-d H:i', (int)$bundle['created']), $epoch));
	fleet_alert('controller_takeover', '', sprintf('The standby %s took over as the Fleet controller (%s).', $p['own_addr'], $why));
}

/* Every minute on a standby (cron): fetch, and take over automatically when that is set and due. */
function fleet_standby_tick(int $now): string {
	if (fleet_standby_role() !== 'standby') {
		install_cron_job(FLEET_STANDBY_CRON, false, '*', '*', '*', '*', '*', 'root');
		return 'not a standby';
	}
	$problem = fleet_standby_pull($now);
	if (($problem !== null) && fleet_standby_takeover_due(fleet_standby_pairing(), fleet_standby_state(), $now)) {
		fleet_standby_promote('system', 'the primary did not answer for ' . (int)fleet_standby_state()['auto_minutes'] . ' minutes');
		return 'took over';
	}
	return $problem ?? 'up to date';
}

/* The standby as this primary sees it, for Settings and the firewall list: address, last fetch, and how many firewalls know it. */
function fleet_standby_overview(): array {
	$p = fleet_standby_pairing();
	$ep = fleet_standby_peer_endpoint();
	$known = 0;
	$total = 0;
	foreach (fleet_db()->query('SELECT status FROM boxes')->fetchAll(PDO::FETCH_COLUMN) as $st) {
		$total++;
		if (($ep !== '') && in_array($ep, (array)((json_decode((string)$st, true) ?: array())['controller_endpoints'] ?? array()), true)) {
			$known++;
		}
	}
	return array('role' => (string)($p['role'] ?? ''), 'addr' => (string)($p['peer_addr'] ?? ''), 'seen' => (int)($p['peer_seen'] ?? 0),
	    'version' => (string)($p['peer_version'] ?? ''), 'endpoint' => $ep, 'known' => $known, 'total' => $total) + fleet_standby_settings();
}
