<?php
/*
 * fleet_kiosk.inc
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
 * NOC screens: a full-screen, read-only view of the fleet for a wall
 * screen that never logs in. Each screen has its own kiosk key (shown
 * once, kept only as a hash) and the networks it may be used from; a
 * key can be revoked at any time. A screen in a public place can hide
 * names and addresses. The kiosk page (www/fleet/kiosk.php) carries the
 * key in the URL fragment, which browsers never send or log, and asks
 * kiosk_data.php with it in a header; that answer is read-only and
 * holds no secrets.
 */

require_once('fleet/fleet_store.inc');

define('FLEET_KIOSK_PREFIX', 'fkk_');

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: the networks a screen may use, one per line or comma separated; returns array(list, problem or null). */
function fleet_kiosk_networks(string $text): array {
	$out = array();
	foreach (preg_split('/[\s,]+/', trim($text), -1, PREG_SPLIT_NO_EMPTY) as $n) {
		if (strpos($n, '/') === false) {
			$n .= (strpos($n, ':') !== false) ? '/128' : '/32';
		}
		list($ip, $bits) = explode('/', $n, 2);
		$v6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
		if (((filter_var($ip, FILTER_VALIDATE_IP) === false)) || !ctype_digit($bits) || ((int)$bits > ($v6 ? 128 : 32))) {
			return array(array(), sprintf('"%s" is not an address or network (like 10.0.5.0/24).', $n));
		}
		if ((int)$bits === 0) {
			return array(array(), 'A screen cannot be allowed from everywhere: give the network the screen is on.');
		}
		$out[] = $ip . '/' . (int)$bits;
	}
	if (empty($out)) {
		return array(array(), 'Give the network or address the screen is on.');
	}
	return array(array_values(array_unique($out)), null);
}

/* pure: is $ip in one of the networks? */
function fleet_kiosk_ip_allowed(string $ip, array $networks): bool {
	$bin = @inet_pton($ip);
	if ($bin === false) {
		return false;
	}
	foreach ($networks as $n) {
		list($net, $bits) = explode('/', $n, 2);
		$nb = @inet_pton($net);
		if (($nb === false) || (strlen($nb) !== strlen($bin))) {
			continue;
		}
		$bits = (int)$bits;
		$bytes = intdiv($bits, 8);
		if (strncmp($bin, $nb, $bytes) !== 0) {
			continue;
		}
		$rest = $bits % 8;
		if (($rest === 0) || (((ord($bin[$bytes]) ^ ord($nb[$bytes])) >> (8 - $rest)) === 0)) {
			return true;
		}
	}
	return false;
}

/*
 * pure: what a screen is sent, from fleet_dashboard_data() and the
 * running group operations. With $hide, names, hostnames, addresses and
 * error texts are left out and firewalls are numbered.
 */
function fleet_kiosk_view(array $data, array $running, bool $hide, string $title): array {
	$boxes = array();
	foreach ($data['boxes'] as $i => $b) {
		$box = array('state' => $b['state'], 'groups' => array_column($b['groups'], 'name'), 'version' => $b['version'], 'seen' => $b['seen'],
		    'policy' => $b['policy'], 'breakglass' => $b['breakglass'], 'update' => ($b['update'] !== null),
		    'op' => ($b['op'] !== null) ? array('text' => (string)($b['op']['text'] ?? ''), 'progress' => $b['op']['progress'] ?? null) : null);
		if ($hide) {
			$box['name'] = sprintf('Firewall %d', $i + 1);
			$box['host'] = '';
			/* A group is often named after a customer or site. */
			$box['groups'] = array();
			/* The state line says it; an error text could name a host or an address. */
			$box['problem'] = '';
			if ($box['op'] !== null) {
				$box['op']['text'] = 'Working';
			}
		} else {
			$box['name'] = $b['label'];
			$box['host'] = $b['host'];
			$box['problem'] = mb_strimwidth((string)$b['problem'], 0, 90, '...');
		}
		$boxes[] = $box;
	}
	$ops = array();
	foreach ($running as $o) {
		$ops[] = array('title' => $hide ? 'Fleet operation' : (string)$o['title'], 'done' => (int)($o['done'] ?? 0), 'total' => (int)($o['total'] ?? 0),
		    'percent' => (int)($o['percent'] ?? 0));
	}
	return array('title' => $title, 'headline' => $data['headline'], 'total' => $data['total'], 'counts' => $data['counts'], 'boxes' => $boxes, 'ops' => $ops,
	    'checked' => $data['checked'], 'now' => $data['now']);
}

/* ------------------------------------------------------------------ */
/* Keys                                                                */
/* ------------------------------------------------------------------ */

function fleet_kiosk_row(array $r): array {
	$r['networks'] = json_decode((string)$r['networks'], true) ?: array();
	return $r;
}

function fleet_kiosks_all(): array {
	return array_map('fleet_kiosk_row', fleet_db()->query('SELECT * FROM kiosk_keys WHERE revoked IS NULL ORDER BY name COLLATE NOCASE')->fetchAll());
}

/* A screen's name from its form, or InvalidArgumentException. */
function fleet_kiosk_name(array $in): string {
	$name = trim((string)($in['name'] ?? ''));
	if (($name === '') || (mb_strlen($name) > 60) || preg_match('/[<>\x00-\x1f\x7f]/u', $name)) {
		throw new InvalidArgumentException('Give the screen a name of 1 to 60 characters.');
	}
	return $name;
}

/* A new screen: returns array(id, key). The key is shown once. */
function fleet_kiosk_create(array $in, string $who): array {
	$name = fleet_kiosk_name($in);
	list($nets, $problem) = fleet_kiosk_networks((string)($in['networks'] ?? ''));
	if ($problem !== null) {
		throw new InvalidArgumentException($problem);
	}
	$key = FLEET_KIOSK_PREFIX . rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
	fleet_db()->prepare('INSERT INTO kiosk_keys (name, hash, networks, hide, created, who) VALUES (?, ?, ?, ?, ?, ?)')
	    ->execute(array($name, hash('sha256', $key), json_encode($nets), empty($in['hide']) ? 0 : 1, time(), $who));
	$id = (int)fleet_db()->lastInsertId();
	fleet_audit($who, 'kiosk', sprintf('Screen %s: key made, from %s%s', $name, implode(', ', $nets), empty($in['hide']) ? '' : ', names hidden'));
	return array($id, $key);
}

/* Change a screen's name, networks or hiding (the key stays). */
function fleet_kiosk_update(int $id, array $in, string $who): void {
	$name = fleet_kiosk_name($in);
	list($nets, $problem) = fleet_kiosk_networks((string)($in['networks'] ?? ''));
	if ($problem !== null) {
		throw new InvalidArgumentException($problem);
	}
	fleet_db()->prepare('UPDATE kiosk_keys SET name = ?, networks = ?, hide = ? WHERE id = ? AND revoked IS NULL')->execute(array($name, json_encode($nets), empty($in['hide']) ? 0 : 1, $id));
	fleet_audit($who, 'kiosk', sprintf('Screen %s: from %s%s', $name, implode(', ', $nets), empty($in['hide']) ? '' : ', names hidden'));
}

function fleet_kiosk_revoke(int $id, string $who): void {
	fleet_db()->prepare('UPDATE kiosk_keys SET revoked = ? WHERE id = ?')->execute(array(time(), $id));
	fleet_audit($who, 'kiosk', "Screen {$id}: key revoked");
}

/*
 * The screen a key and address belong to, or array(null, reason). The
 * reason is for the audit log, never for the caller.
 */
function fleet_kiosk_check(string $key, string $ip, int $now): array {
	if ((strncmp($key, FLEET_KIOSK_PREFIX, strlen(FLEET_KIOSK_PREFIX)) !== 0) || (strlen($key) > 80)) {
		return array(null, 'not a kiosk key');
	}
	$q = fleet_db()->prepare('SELECT * FROM kiosk_keys WHERE hash = ? AND revoked IS NULL');
	$q->execute(array(hash('sha256', $key)));
	$row = $q->fetch();
	if (!is_array($row)) {
		return array(null, 'unknown or revoked key');
	}
	$row = fleet_kiosk_row($row);
	if (!fleet_kiosk_ip_allowed($ip, $row['networks'])) {
		return array(null, "screen {$row['name']} used from {$ip}");
	}
	if ($now - (int)$row['last_used'] > 60) {
		fleet_db()->prepare('UPDATE kiosk_keys SET last_used = ?, last_ip = ? WHERE id = ?')->execute(array($now, $ip, (int)$row['id']));
	}
	return array($row, null);
}
