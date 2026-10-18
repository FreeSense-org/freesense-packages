<?php
/*
 * fleet_tailscale.inc
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
 * The tailnet as Fleet sees it, through an optional Tailscale API access
 * token: which device each firewall's tailnet address is, and what would
 * make its Tailscale path drop later (key expiry on: FLEET-E136, not
 * authorized, not connected). Without a token the path is only probed.
 * The token is sealed in the Fleet store and never shown or logged.
 * Functions marked "pure" touch neither the network nor the database.
 */

require_once('fleet/fleet_store.inc');

define('FLEET_TS_API', 'https://api.tailscale.com/api/v2');
/* Reuse the device list this many seconds (the page and each apply read it). */
define('FLEET_TS_CACHE', 300);
/* Warn this many days before a node key expires. */
define('FLEET_TS_EXPIRY_WARN_DAYS', 14);

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: whether a string looks like a Tailscale API access token. */
function fleet_ts_token_valid(string $token): bool {
	return (bool)preg_match('/^tskey-api-[A-Za-z0-9-]{10,200}$/', $token);
}

/* pure: the device that has this tailnet address, or null. */
function fleet_ts_device_for(array $devices, string $address): ?array {
	foreach ($devices as $d) {
		if (in_array($address, (array)($d['addresses'] ?? array()), true)) {
			return $d;
		}
	}
	return null;
}

/*
 * pure: what would make a device's path drop: a list of array(code,
 * severity, text). $d is a device from the API (fields=all).
 */
function fleet_ts_device_problems(array $d, int $now): array {
	$out = array();
	if (array_key_exists('authorized', $d) && !$d['authorized']) {
		$out[] = array('', 'error', 'The device waits for approval in the tailnet.');
	}
	$expires = strtotime((string)($d['expires'] ?? '')) ?: 0;
	if (empty($d['keyExpiryDisabled']) && ($expires > 0)) {
		$out[] = ($expires <= $now) ? array('FLEET-E136', 'error', 'Its node key expired on ' . gmdate('Y-m-d', $expires) . '; the path is down until it logs in again.') :
		    array('FLEET-E136', (($expires - $now) < FLEET_TS_EXPIRY_WARN_DAYS * 86400) ? 'error' : 'warn',
		    'Key expiry is on: the path drops on ' . gmdate('Y-m-d', $expires) . ' unless key expiry is turned off.');
	}
	if (array_key_exists('connectedToControl', $d) && !$d['connectedToControl']) {
		$seen = strtotime((string)($d['lastSeen'] ?? '')) ?: 0;
		$out[] = array('', 'warn', 'Not connected to Tailscale' . (($seen > 0) ? ' (last seen ' . gmdate('Y-m-d H:i', $seen) . ' UTC)' : '') . '.');
	}
	return $out;
}

/* pure: whether Fleet turns this device's key expiry off by itself (setting on, expiry on, device known). */
function fleet_ts_expiry_should_disable(array $d, bool $auto): bool {
	return $auto && (($d['id'] ?? '') !== '') && empty($d['keyExpiryDisabled']);
}

/*
 * pure: the API body for a one-time auth key: single use, approved in
 * advance, not ephemeral (the firewall stays in the tailnet). Tailscale
 * allows letters, digits, spaces and dashes in a description of 50.
 */
function fleet_ts_authkey_body(string $label, int $ttl): array {
	$desc = trim(substr(preg_replace('/[^A-Za-z0-9 -]+/', '', 'FreeSense Fleet ' . $label), 0, 50));
	return array('capabilities' => array('devices' => array('create' => array('reusable' => false, 'ephemeral' => false, 'preauthorized' => true))),
	    'expirySeconds' => max(3600, min(90 * 86400, $ttl)), 'description' => $desc);
}

/* pure: why joining over Tailscale cannot be offered now (a list of sentences; empty = ready). */
function fleet_ts_join_problems(?string $token_state, ?string $address): array {
	$out = array();
	if ($token_state === null) {
		$out[] = 'Add a Tailscale API token (Firewalls > Connections) so Fleet can create a one-time Tailscale key for each new firewall.';
	} elseif ($token_state !== '') {
		$out[] = $token_state;
	}
	if ($address === null) {
		$out[] = 'This controller is not in a tailnet: install Tailscale here and log it in first.';
	}
	return $out;
}

/* ------------------------------------------------------------------ */
/* The API                                                             */
/* ------------------------------------------------------------------ */

/* The stored API token, or null. */
function fleet_ts_token(): ?string {
	$sealed = fleet_setting('tailscale_api_token');
	return (($sealed === null) || ($sealed === '')) ? null : fleet_unseal($sealed, fleet_master_key());
}

/* One API call: array(HTTP code, decoded JSON). Throws RuntimeException; the token never appears in a message. */
function fleet_ts_api(string $verb, string $path, ?array $body = null, ?string $token = null): array {
	$token = $token ?? fleet_ts_token();
	if ($token === null) {
		throw new RuntimeException('No Tailscale API token is set.');
	}
	$c = curl_init(FLEET_TS_API . $path);
	$headers = array('Authorization: Bearer ' . $token, 'Accept: application/json');
	$opts = array(CURLOPT_CUSTOMREQUEST => $verb, CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_TIMEOUT => 15,
	    CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS);
	if ($body !== null) {
		$headers[] = 'Content-Type: application/json';
		$opts[CURLOPT_POSTFIELDS] = json_encode($body);
	}
	$opts[CURLOPT_HTTPHEADER] = $headers;
	curl_setopt_array($c, $opts);
	$raw = curl_exec($c);
	$code = (int)curl_getinfo($c, CURLINFO_RESPONSE_CODE);
	if ($code === 0) {
		throw new RuntimeException('The Tailscale API could not be reached (' . curl_error($c) . ').');
	}
	if (in_array($code, array(401, 403), true)) {
		throw new RuntimeException('The Tailscale API refused the token (HTTP ' . $code . '): it expired, was revoked or may not read devices.');
	}
	return array($code, json_decode((string)$raw, true));
}

/* Save (after it worked) or remove the token. */
function fleet_ts_token_set(string $token, string $who): void {
	$token = trim($token);
	if ($token === '') {
		fleet_setting_set('tailscale_api_token', '');
		fleet_setting_set('tailscale_devices', '');
		fleet_audit($who, 'connections', 'Tailscale API token removed');
		return;
	}
	if (!fleet_ts_token_valid($token)) {
		throw new InvalidArgumentException('That is not a Tailscale API access token (it starts with tskey-api-).');
	}
	list($code, $json) = fleet_ts_api('GET', '/tailnet/-/devices', null, $token);
	if (($code !== 200) || !isset($json['devices'])) {
		throw new InvalidArgumentException("The Tailscale API answered HTTP {$code}; the token was not saved.");
	}
	fleet_setting_set('tailscale_api_token', fleet_seal($token, fleet_master_key()));
	fleet_setting_set('tailscale_devices', '');
	fleet_audit($who, 'connections', 'Tailscale API token saved (' . count($json['devices']) . ' devices in the tailnet)');
}

/* The tailnet's devices, cached FLEET_TS_CACHE seconds; null without a token. Throws RuntimeException. */
function fleet_ts_devices(bool $fresh = false): ?array {
	if (fleet_ts_token() === null) {
		return null;
	}
	$cache = json_decode((string)fleet_setting('tailscale_devices', ''), true);
	if (!$fresh && is_array($cache) && ((time() - (int)($cache['time'] ?? 0)) < FLEET_TS_CACHE)) {
		return (array)$cache['devices'];
	}
	list($code, $json) = fleet_ts_api('GET', '/tailnet/-/devices?fields=all');
	if (($code !== 200) || !isset($json['devices'])) {
		throw new RuntimeException("The Tailscale API answered HTTP {$code}.");
	}
	$keep = array();
	foreach ($json['devices'] as $d) {
		$keep[] = array_intersect_key($d, array_flip(array('id', 'nodeId', 'name', 'hostname', 'addresses', 'authorized', 'keyExpiryDisabled', 'expires',
		    'lastSeen', 'connectedToControl', 'tags')));
	}
	fleet_setting_set('tailscale_devices', json_encode(array('time' => time(), 'devices' => $keep)));
	return $keep;
}

/*
 * For every firewall with a Tailscale path: node => {device, problems}.
 * null without a token; array('error' => text) when the API fails.
 */
function fleet_ts_check(array $overview): ?array {
	try {
		$devices = fleet_ts_devices();
	} catch (RuntimeException $e) {
		return array('error' => $e->getMessage());
	}
	if ($devices === null) {
		return null;
	}
	$out = array();
	foreach ($overview as $node => $r) {
		$address = (string)($r['state']['address'] ?? '');
		if ((($r['state']['method'] ?? '') !== 'tailscale') || ($address === '')) {
			continue;
		}
		$d = fleet_ts_device_for($devices, $address);
		$out[$node] = array('device' => $d, 'problems' => ($d === null) ? array(array('', 'error', "No device in the tailnet has {$address}; the token may be for another tailnet.")) :
		    fleet_ts_device_problems($d, time()));
	}
	return $out;
}

/* This controller's IPv4 tailnet address, or null when it is not in a tailnet. */
function fleet_ts_controller_address(): ?string {
	if (!is_executable('/usr/local/bin/tailscale')) {
		return null;
	}
	$out = array();
	exec('/usr/local/bin/tailscale ip -4 2>/dev/null', $out, $rc);
	$ip = trim((string)($out[0] ?? ''));
	return (($rc === 0) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) ? $ip : null;
}

/* Whether a firewall can join over Tailscale now: array(problems, controller tailnet address). */
function fleet_ts_join_ready(): array {
	$state = null;
	if (fleet_ts_token() !== null) {
		try {
			fleet_ts_devices();
			$state = '';
		} catch (RuntimeException $e) {
			$state = $e->getMessage();
		}
	}
	$address = fleet_ts_controller_address();
	return array(fleet_ts_join_problems($state, $address), $address);
}

/* A one-time, pre-approved auth key for one new firewall, kept with its invitation by id. Throws RuntimeException. */
function fleet_ts_authkey_mint(string $label, int $ttl, string $who, string $token_id = ''): string {
	list($code, $json) = fleet_ts_api('POST', '/tailnet/-/keys', fleet_ts_authkey_body($label, $ttl));
	$key = (string)($json['key'] ?? '');
	if (($code !== 200) || (strncmp($key, 'tskey-auth-', 11) !== 0)) {
		throw new RuntimeException("Tailscale did not create an auth key (HTTP {$code}): the API token may need the auth keys permission.");
	}
	fleet_audit($who, 'connections', "One-time Tailscale key created for \"{$label}\" (id " . (string)($json['id'] ?? '?') . ')');
	if ($token_id !== '') {
		fleet_db()->prepare('UPDATE invitations SET ts_key_id = ? WHERE token_id = ?')->execute(array((string)($json['id'] ?? ''), $token_id));
	}
	return $key;
}

/* Delete an unused one-time key (a revoked invitation). Never throws: the key expires anyway. */
function fleet_ts_authkey_delete(string $id, string $who): void {
	try {
		list($code) = fleet_ts_api('DELETE', '/tailnet/-/keys/' . rawurlencode($id));
		fleet_audit($who, 'connections', ($code < 300) ? "One-time Tailscale key {$id} deleted" : "One-time Tailscale key {$id} not deleted (HTTP {$code}); it expires by itself");
	} catch (RuntimeException $e) {
		fleet_audit($who, 'connections', "One-time Tailscale key {$id} not deleted ({$e->getMessage()}); it expires by itself");
	}
}

/* Turn key expiry off for a firewall's tailnet device (fixes FLEET-E136). */
function fleet_ts_key_expiry_off(string $node, string $who): string {
	$box = fleet_box_get($node);
	$st = null;
	foreach (($box === null) ? array() : fleet_conn_paths(json_decode((string)($box['conn_state'] ?? ''), true) ?: null) as $p) {
		$st = ($p['method'] === 'tailscale') ? $p : $st;
	}
	if ($st === null) {
		throw new InvalidArgumentException('That firewall has no Tailscale path.');
	}
	$d = fleet_ts_device_for((array)fleet_ts_devices(true), (string)$st['address']);
	if ($d === null) {
		throw new RuntimeException('Its device was not found in the tailnet.');
	}
	list($code) = fleet_ts_api('POST', '/device/' . rawurlencode((string)$d['id']) . '/key', array('keyExpiryDisabled' => true));
	if (($code < 200) || ($code >= 300)) {
		throw new RuntimeException("The Tailscale API answered HTTP {$code}.");
	}
	fleet_setting_set('tailscale_devices', '');
	fleet_audit($who, 'connections', "{$box['label']}: Tailscale key expiry turned off for device {$d['name']}");
	return "Key expiry is off for {$box['label']} ({$d['name']}).";
}

/*
 * Put this controller in the tailnet: save the API token when one is given,
 * install the Tailscale package and log in with a one-time key Fleet makes
 * (the same steps a joining firewall takes). Returns the controller's tailnet
 * address; throws RuntimeException with something the admin can act on.
 */
function fleet_ts_controller_setup(string $token, string $who): string {
	$token = trim($token);
	if ($token !== '') {
		try {
			fleet_ts_token_set($token, $who);
		} catch (InvalidArgumentException $e) {
			throw new RuntimeException($e->getMessage());
		}
	}
	$address = fleet_ts_controller_address();
	if ($address !== null) {
		return $address;
	}
	if (fleet_ts_token() === null) {
		throw new RuntimeException('Add a Tailscale API token (tskey-api-...): Fleet needs it to make the one-time key this controller logs in with.');
	}
	/* Installing the package and waiting for the tailnet can take a few minutes. */
	set_time_limit(300);
	require_once('fleet_seed.inc');
	$key = fleet_ts_authkey_mint('controller', 3600, $who);
	try {
		$address = fleet_seed_tailscale_up($key, function (string $step) {
		});
	} catch (FleetJoinError $e) {
		throw new RuntimeException($e->getMessage());
	}
	fleet_audit($who, 'connections', "Tailscale set up on this controller ({$address})");
	return $address;
}
