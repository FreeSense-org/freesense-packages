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

/* Turn key expiry off for a firewall's tailnet device (fixes FLEET-E136). */
function fleet_ts_key_expiry_off(string $node, string $who): string {
	$box = fleet_box_get($node);
	$st = json_decode((string)($box['conn_state'] ?? ''), true);
	if (($box === null) || (($st['method'] ?? '') !== 'tailscale')) {
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
