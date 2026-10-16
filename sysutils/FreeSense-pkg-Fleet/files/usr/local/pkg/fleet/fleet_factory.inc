<?php
/*
 * fleet_factory.inc
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
 * Deployment Factory: prepare many new firewalls at once. A batch has
 * settings (access, key mode, naming group, how long invitations last)
 * and rows (site, label, serial, cloud instance id, hostname). The
 * preview names every row from its group and finds problems (E120);
 * generating makes one invitation per row and a bundle:
 *
 *   <hostname>/fleet-join.conf   the seed System reads from a USB stick,
 *                                CD or second disk (fleet_seed.inc)
 *   <hostname>/README.txt
 *   join-cards.html              one printable card per firewall (no key)
 *   key-sheet.html               the join keys or PINs (attended, PIN)
 *   manifest.json
 *
 * The bundle is a .tar.gz encrypted with the batch passphrase in the
 * format of "openssl enc -aes-256-cbc -pbkdf2 -iter 200000", so it opens
 * anywhere. Unattended seeds hold the key: such a row is bound to its
 * serial or instance id (a different firewall gets E121) and may be
 * approved automatically.
 */

require_once('fleet/fleet_store.inc');

define('FLEET_FACTORY_MODES', array('attended' => 'Attended: the key is typed at the console',
    'pin' => 'PIN: the key is in the seed, locked with a PIN sent separately', 'unattended' => 'Unattended: bound to the serial or instance id'));
define('FLEET_FACTORY_MAX_ROWS', 500);
define('FLEET_FACTORY_ITER', 200000);

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/*
 * pure: rows from pasted CSV (site,label,serial,instance_id,hostname; a
 * header line is skipped). Returns rows with their line number.
 */
function fleet_factory_rows(string $csv): array {
	$rows = array();
	foreach (preg_split('/\r\n|\r|\n/', $csv) as $i => $line) {
		if (trim($line) === '') {
			continue;
		}
		$f = array_map('trim', str_getcsv($line, (substr_count($line, ';') > substr_count($line, ',')) ? ';' : ',', '"', '\\'));
		if ((count($rows) === 0) && (strtolower($f[0] ?? '') === 'site')) {
			continue;
		}
		$rows[] = array('line' => $i + 1, 'site' => (string)($f[0] ?? ''), 'label' => (string)($f[1] ?? ''), 'serial' => (string)($f[2] ?? ''),
		    'instance_id' => (string)($f[3] ?? ''), 'hostname' => strtolower((string)($f[4] ?? '')));
	}
	return $rows;
}

/*
 * pure: name and check every row. $naming: {pattern, domain, gid,
 * group} of the batch's group (or null); $counters: scope => next;
 * $taken: hostnames in use. Returns array(rows with hostname, domain,
 * scope, n, problems[]; counters after). Names are only reserved when
 * the batch is generated.
 */
function fleet_factory_plan(array $rows, array $settings, ?array $naming, array $counters, array $taken): array {
	$taken = array_flip(array_map('strtolower', $taken));
	$seen_label = array();
	$seen_bind = array();
	foreach ($rows as &$r) {
		$r['problems'] = array();
		$r['domain'] = (string)($naming['domain'] ?? '');
		$r['scope'] = null;
		$r['n'] = null;
		if (($r['label'] === '') || (mb_strlen($r['label']) > 80) || preg_match('/[\x00-\x1f\x7f]/u', $r['label'])) {
			$r['problems'][] = 'Give a label of up to 80 characters';
		} elseif (isset($seen_label[strtolower($r['label'])])) {
			$r['problems'][] = 'The same label as line ' . $seen_label[strtolower($r['label'])];
		} else {
			$seen_label[strtolower($r['label'])] = $r['line'];
		}
		foreach (array('serial', 'instance_id') as $b) {
			if ($r[$b] === '') {
				continue;
			}
			if (!preg_match('/^[A-Za-z0-9._:-]{1,64}$/D', $r[$b])) {
				$r['problems'][] = "The {$b} has characters a firewall never reports";
			} elseif (isset($seen_bind[$b . ':' . $r[$b]])) {
				$r['problems'][] = "The same {$b} as line " . $seen_bind[$b . ':' . $r[$b]];
			} else {
				$seen_bind[$b . ':' . $r[$b]] = $r['line'];
			}
		}
		if (($settings['mode'] === 'unattended') && ($r['serial'] === '') && ($r['instance_id'] === '')) {
			$r['problems'][] = 'Unattended needs a serial or an instance id to bind to';
		}
		if ($r['hostname'] !== '') {
			if (!preg_match('/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/D', $r['hostname'])) {
				$r['problems'][] = 'The hostname is letters, digits and - only';
			}
		} elseif (($naming !== null) && ($naming['pattern'] !== '')) {
			$vars = array('site' => $r['site'], 'group' => $naming['group'], 'role' => '');
			$scope = fleet_naming_scope((int)$naming['gid'], $naming['pattern'], $vars);
			$got = fleet_naming_next($naming['pattern'], $vars, (int)($counters[$scope] ?? 1), array_keys($taken));
			if ($got === null) {
				$r['problems'][] = 'The group pattern gives no name here (is the site filled in?)';
			} else {
				list($r['hostname'], $r['n']) = $got;
				$r['scope'] = $scope;
				$counters[$scope] = $got[1] + 1;
			}
		}
		if ($r['hostname'] !== '') {
			if (isset($taken[$r['hostname']])) {
				$r['problems'][] = 'Another firewall, invitation or row already has this name';
			}
			$taken[$r['hostname']] = true;
		}
	}
	unset($r);
	return array($rows, $counters);
}

/*
 * pure: what a seed file holds for one row (System's fleet_seed.inc reads
 * it). $tskey: the row's one-time Tailscale key, plain only when
 * unattended, else sealed to the PIN or to the join key's data, so it is
 * opened by what the admin types anyway.
 */
function fleet_factory_seed(string $link, string $mode, string $key, ?string $pin, ?string $tskey = null): array {
	$seed = array('version' => 1, 'link' => $link, 'mode' => $mode);
	if ($mode === 'unattended') {
		$seed['key'] = $key;
	} elseif ($mode === 'pin') {
		$salt = random_bytes(16);
		$nonce = random_bytes(12);
		$tag = '';
		$data = openssl_encrypt($key, 'aes-256-gcm', hash_pbkdf2('sha256', (string)$pin, $salt, 200000, 32, true), OPENSSL_RAW_DATA, $nonce, $tag, 'FreeSense-Fleet-Seed-v1');
		$seed['sealed_key'] = array('salt' => base64_encode($salt), 'nonce' => base64_encode($nonce), 'tag' => base64_encode($tag), 'data' => base64_encode((string)$data));
	}
	if ($tskey !== null) {
		require_once('fleet_seed.inc');
		$seed['tailscale'] = ($mode === 'unattended') ? array('key' => $tskey) :
		    array('sealed' => fleet_seed_seal_key($tskey, ($mode === 'pin') ? (string)$pin : (string)fleet_join_key_normalize($key)));
	}
	return $seed;
}

/* pure: encrypt like "openssl enc -aes-256-cbc -salt -pbkdf2 -iter N" (key and IV from PBKDF2-SHA256). */
function fleet_factory_encrypt(string $data, string $passphrase, int $iter = FLEET_FACTORY_ITER): string {
	$salt = random_bytes(8);
	$kiv = hash_pbkdf2('sha256', $passphrase, $salt, $iter, 48, true);
	return 'Salted__' . $salt . openssl_encrypt($data, 'aes-256-cbc', substr($kiv, 0, 32), OPENSSL_RAW_DATA, substr($kiv, 32, 16));
}

/* pure: the reverse (for tests and checks); null for a wrong passphrase. */
function fleet_factory_decrypt(string $blob, string $passphrase, int $iter = FLEET_FACTORY_ITER): ?string {
	if (strncmp($blob, 'Salted__', 8) !== 0) {
		return null;
	}
	$kiv = hash_pbkdf2('sha256', $passphrase, substr($blob, 8, 8), $iter, 48, true);
	$out = openssl_decrypt(substr($blob, 16), 'aes-256-cbc', substr($kiv, 0, 32), OPENSSL_RAW_DATA, substr($kiv, 32, 16));
	return ($out === false) ? null : $out;
}

/* pure: a passphrase good enough to protect join keys. */
function fleet_factory_passphrase_problem(string $p): ?string {
	if (strlen($p) < 12) {
		return 'The bundle passphrase has at least 12 characters.';
	}
	if (count(array_unique(str_split($p))) < 6) {
		return 'Choose a passphrase that is not one repeated character or pattern.';
	}
	return null;
}

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

function fleet_batch_row(array $r): array {
	$r['settings'] = json_decode((string)$r['settings'], true) ?: array();
	return $r;
}

function fleet_batches_all(): array {
	return array_map('fleet_batch_row', fleet_db()->query('SELECT * FROM batches ORDER BY created DESC')->fetchAll());
}

function fleet_batch_get(int $id): ?array {
	$q = fleet_db()->prepare('SELECT * FROM batches WHERE id = ?');
	$q->execute(array($id));
	$r = $q->fetch();
	return is_array($r) ? fleet_batch_row($r) : null;
}

function fleet_batch_rows(int $id): array {
	$q = fleet_db()->prepare('SELECT r.*, i.state AS inv_state, i.expires, b.node_id AS box, b.label AS box_label FROM batch_rows r
	    LEFT JOIN invitations i ON i.token_id = r.token_id LEFT JOIN boxes b ON b.node_id = i.node_id WHERE r.batch_id = ? ORDER BY r.n');
	$q->execute(array($id));
	return $q->fetchAll();
}

/* pure: a row's state: joined | waiting | expired | revoked | burned. */
function fleet_batch_row_state(array $r, int $now): string {
	if (($r['box'] ?? null) !== null) {
		return 'joined';
	}
	$s = (string)($r['inv_state'] ?? 'revoked');
	if (($s === 'open') && ((int)$r['expires'] <= $now)) {
		return 'expired';
	}
	return ($s === 'open') ? 'waiting' : (($s === 'used') ? 'joined' : $s);
}

/* The settings of a new batch from its form, or InvalidArgumentException. */
function fleet_factory_settings(array $in): array {
	$name = trim((string)($in['name'] ?? ''));
	if (($name === '') || (mb_strlen($name) > 60) || preg_match('/[<>\x00-\x1f\x7f]/u', $name)) {
		throw new InvalidArgumentException('Give the batch a name of 1 to 60 characters.');
	}
	$mode = (string)($in['mode'] ?? 'attended');
	if (!isset(FLEET_FACTORY_MODES[$mode])) {
		throw new InvalidArgumentException('Choose how the key reaches the firewalls.');
	}
	$role = in_array($in['role'] ?? '', array('monitor', 'managed'), true) ? $in['role'] : 'managed';
	$days = max(1, min(30, (int)($in['days'] ?? 14)));
	$gid = (int)($in['group'] ?? 0);
	if (($gid > 0) && (fleet_group_get($gid) === null)) {
		throw new InvalidArgumentException('That group no longer exists.');
	}
	return array('name' => $name, 'mode' => $mode, 'role' => $role, 'days' => $days, 'group' => $gid, 'auto_approve' => ($mode === 'unattended') && !empty($in['auto_approve']),
	    'via' => ((string)($in['via'] ?? '') === 'tailscale') ? 'tailscale' : '');
}

/* The naming of a group for the planner, or null. */
function fleet_factory_naming(int $gid): ?array {
	$g = ($gid > 0) ? fleet_group_get($gid) : null;
	return ($g === null) ? null : array('gid' => $gid, 'group' => $g['name'], 'pattern' => (string)$g['naming_pattern'], 'domain' => (string)$g['naming_domain']);
}

/* scope => next for the counters a plan may use. */
function fleet_factory_counters(): array {
	return fleet_db()->query('SELECT scope, next FROM name_counters')->fetchAll(PDO::FETCH_KEY_PAIR);
}

/*
 * Generate a batch: invitations (names reserved, counters kept), the
 * encrypted bundle. Returns array(batch id, bundle path). Nothing is
 * kept when a row has a problem.
 */
function fleet_factory_generate(array $settings, string $csv, string $passphrase, string $who, string $authority): array {
	$problem = fleet_factory_passphrase_problem($passphrase);
	if ($problem !== null) {
		throw new InvalidArgumentException($problem);
	}
	$rows = fleet_factory_rows($csv);
	if (empty($rows) || (count($rows) > FLEET_FACTORY_MAX_ROWS)) {
		throw new InvalidArgumentException('Add 1 to ' . FLEET_FACTORY_MAX_ROWS . ' rows.');
	}
	$naming = fleet_factory_naming($settings['group']);
	list($rows, $counters) = fleet_factory_plan($rows, $settings, $naming, fleet_factory_counters(), fleet_naming_taken());
	foreach ($rows as $r) {
		if (!empty($r['problems'])) {
			throw new InvalidArgumentException('FLEET-E120: line ' . $r['line'] . ': ' . implode('; ', $r['problems']) . '. Nothing was made.');
		}
	}
	$via = (string)($settings['via'] ?? '');
	if ($via === 'tailscale') {
		/* Over Tailscale the links use the controller's tailnet address, and every firewall gets its own one-time key. */
		list($ts_problems, $ts_address) = fleet_ts_join_ready();
		if (!empty($ts_problems)) {
			throw new InvalidArgumentException(implode(' ', $ts_problems));
		}
		$authority = fleet_hostport($ts_address, fleet_ctl_settings()['enroll_port']);
	}
	$now = time();
	fleet_db()->prepare('INSERT INTO batches (name, settings, created, who) VALUES (?, ?, ?, ?)')->execute(array($settings['name'], json_encode($settings), $now, $who));
	$bid = (int)fleet_db()->lastInsertId();
	$dir = FLEET_DATA . '/tmp/batch-' . $bid;
	exec('rm -rf ' . escapeshellarg($dir));
	@mkdir($dir . '/bundle', 0700, true);
	$cards = array();
	$keys = array();
	$manifest = array('batch' => $settings['name'], 'created' => gmdate('c', $now), 'mode' => $settings['mode'], 'expires' => gmdate('c', $now + 86400 * $settings['days']), 'firewalls' => array());
	foreach ($rows as $i => $r) {
		list($link, $key, $tid, $expires) = fleet_invite_create($settings['role'], $r['label'], 86400 * $settings['days'], $who, $authority, $now, $via);
		$tskey = null;
		if ($via === 'tailscale') {
			try {
				$tskey = fleet_ts_authkey_mint($r['label'], 86400 * $settings['days'], $who, $tid);
			} catch (RuntimeException $e) {
				/* Nothing half-made: the batch's invitations and keys so far go again. */
				fleet_db()->prepare('INSERT INTO batch_rows (batch_id, n, site, label, hostname, domain, serial, instance_id, token_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
				    ->execute(array($bid, $i + 1, $r['site'], $r['label'], $r['hostname'], $r['domain'], $r['serial'], $r['instance_id'], $tid));
				fleet_batch_revoke($bid, $who);
				exec('rm -rf ' . escapeshellarg($dir));
				throw new RuntimeException('Tailscale key for line ' . $r['line'] . ': ' . $e->getMessage() . ' Nothing was made.');
			}
		}
		$host = $r['hostname'];
		if ($r['scope'] !== null) {
			fleet_db()->prepare('INSERT OR REPLACE INTO name_counters (scope, next) VALUES (?, ?)')->execute(array($r['scope'], (int)$r['n'] + 1));
		}
		fleet_db()->prepare('UPDATE invitations SET group_id = ?, hostname = ?, domain = ?, bind_serial = ?, bind_instance = ?, auto_approve = ?, batch_id = ? WHERE token_id = ?')
		    ->execute(array($settings['group'] ?: null, $host, $r['domain'], $r['serial'], $r['instance_id'], $settings['auto_approve'] ? 1 : 0, $bid, $tid));
		fleet_db()->prepare('INSERT INTO batch_rows (batch_id, n, site, label, hostname, domain, serial, instance_id, token_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
		    ->execute(array($bid, $i + 1, $r['site'], $r['label'], $host, $r['domain'], $r['serial'], $r['instance_id'], $tid));
		$pin = ($settings['mode'] === 'pin') ? sprintf('%06d', random_int(0, 999999)) : null;
		$folder = ($host !== '') ? $host : sprintf('firewall-%03d', $i + 1);
		@mkdir("{$dir}/bundle/{$folder}", 0700);
		file_put_contents("{$dir}/bundle/{$folder}/fleet-join.conf", json_encode(fleet_factory_seed($link, $settings['mode'], $key, $pin, $tskey), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
		file_put_contents("{$dir}/bundle/{$folder}/README.txt", fleet_factory_readme($r, $settings, $host, $expires));
		$fqdn = $host . (($host !== '' && $r['domain'] !== '') ? '.' . $r['domain'] : '');
		$cards[] = array('label' => $r['label'], 'site' => $r['site'], 'name' => $fqdn, 'serial' => $r['serial'], 'link' => $link, 'folder' => $folder);
		if ($settings['mode'] !== 'unattended') {
			$keys[] = array('label' => $r['label'], 'name' => $fqdn, 'secret' => ($settings['mode'] === 'pin') ? $pin : $key);
		}
		$manifest['firewalls'][] = array('folder' => $folder, 'label' => $r['label'], 'site' => $r['site'], 'hostname' => $host, 'domain' => $r['domain'],
		    'serial' => $r['serial'], 'instance_id' => $r['instance_id'], 'invitation' => $tid);
	}
	file_put_contents("{$dir}/bundle/join-cards.html", fleet_factory_cards_html($settings, $cards));
	if (!empty($keys)) {
		file_put_contents("{$dir}/bundle/key-sheet.html", fleet_factory_keys_html($settings, $keys));
	}
	file_put_contents("{$dir}/bundle/manifest.json", json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
	list($rc) = fleet_ctl_exec(array('/usr/bin/tar', '-czf', "{$dir}/bundle.tar.gz", '-C', "{$dir}/bundle", '.'));
	exec('rm -rf ' . escapeshellarg("{$dir}/bundle"));
	if ($rc !== 0) {
		throw new RuntimeException('The bundle could not be packed.');
	}
	$out = "{$dir}/bundle.tar.gz.enc";
	file_put_contents($out, fleet_factory_encrypt((string)file_get_contents("{$dir}/bundle.tar.gz"), $passphrase));
	@unlink("{$dir}/bundle.tar.gz");
	@chmod($out, 0600);
	fleet_audit($who, 'factory', sprintf('Batch %s: %d firewalls, %s, for %d days', $settings['name'], count($rows), $settings['mode'], $settings['days']) . (($via === 'tailscale') ? ', over Tailscale' : ''));
	return array($bid, $out);
}

/* The encrypted bundle of a batch, while it is kept. */
function fleet_batch_bundle(int $bid): ?string {
	$p = FLEET_DATA . '/tmp/batch-' . $bid . '/bundle.tar.gz.enc';
	return is_file($p) ? $p : null;
}

/* Revoke the invitations of a batch that have not been used (or one row). Returns how many. */
function fleet_batch_revoke(int $bid, string $who, ?string $token = null): int {
	$n = 0;
	foreach (fleet_batch_rows($bid) as $r) {
		if ((($token === null) || ($r['token_id'] === $token)) && fleet_invite_revoke((string)$r['token_id'], $who)) {
			$n++;
		}
	}
	if ($token === null) {
		$p = fleet_batch_bundle($bid);
		if ($p !== null) {
			@unlink($p);
		}
	}
	return $n;
}

/* ------------------------------------------------------------------ */
/* Bundle documents                                                    */
/* ------------------------------------------------------------------ */

function fleet_factory_readme(array $r, array $s, string $host, int $expires): string {
	$how = array(
		'attended' => "Copy fleet-join.conf to a USB stick (FAT) and plug it in before the first boot.\nAt the console choose option 17 and type the join key from the key sheet.",
		'pin' => "Copy fleet-join.conf to a USB stick (FAT) and plug it in before the first boot.\nAt the console choose option 17 and type the PIN from the key sheet.",
		'unattended' => "Copy fleet-join.conf to a USB stick (FAT) and plug it in before the first boot.\nThe firewall joins by itself once it is online. It only works on the firewall with this serial or instance id.",
	);
	return "FreeSense Fleet: {$r['label']}\n" . str_repeat('=', 24 + mb_strlen($r['label'])) . "\n\n" .
	    (($host !== '') ? "Name when it joins: {$host}" . (($r['domain'] !== '') ? ".{$r['domain']}" : '') . "\n" : '') .
	    (($r['site'] !== '') ? "Site: {$r['site']}\n" : '') . (($r['serial'] !== '') ? "Serial: {$r['serial']}\n" : '') .
	    (($r['instance_id'] !== '') ? "Instance id: {$r['instance_id']}\n" : '') .
	    'Valid until: ' . gmdate('Y-m-d H:i', $expires) . " UTC\n\n" . $how[$s['mode']] . "\n\n" . ((($s['via'] ?? '') === 'tailscale') ?
	    "Over Tailscale: the seed holds a one-time Tailscale key for this firewall. Joining installs Tailscale (the firewall needs internet and the FreeSense package repository), logs it in to the tailnet and joins the controller there; no public port is needed.\n" :
	    "The firewall needs to reach the controller on the enrollment and tunnel ports.\n");
}

function fleet_factory_cards_html(array $s, array $cards): string {
	$h = function ($v) { return htmlspecialchars((string)$v, ENT_QUOTES); };
	$out = '<!doctype html><html lang="en"><meta charset="utf-8"><title>' . $h('Join cards: ' . $s['name']) . '</title><style>' .
	    'body{font:14px system-ui,sans-serif;margin:24px;color:#111}h1{font-size:18px}.c{border:1px solid #999;border-radius:8px;padding:12px 14px;margin:0 0 12px;' .
	    'break-inside:avoid;max-width:560px}.n{font:600 16px ui-monospace,monospace}.m{color:#555}.l{font:11px ui-monospace,monospace;word-break:break-all}' .
	    '@media print{body{margin:0}}</style><h1>' . $h('Join cards: ' . $s['name']) . '</h1><p class="m">' .
	    $h('One card per firewall. The cards hold no key; ' . (($s['mode'] === 'unattended') ? 'these firewalls join by themselves.' : 'the key or PIN is on the separate key sheet.')) . '</p>';
	foreach ($cards as $c) {
		$out .= '<div class="c"><div class="n">' . $h($c['name'] !== '' ? $c['name'] : $c['label']) . '</div><div>' . $h($c['label']) . '</div><div class="m">' .
		    $h(trim(($c['site'] !== '' ? 'Site ' . $c['site'] : '') . ($c['serial'] !== '' ? '  Serial ' . $c['serial'] : ''))) . '</div><div class="m">Seed folder: ' .
		    $h($c['folder']) . '</div><div class="l">' . $h($c['link']) . '</div></div>';
	}
	return $out . '</html>';
}

function fleet_factory_keys_html(array $s, array $keys): string {
	$h = function ($v) { return htmlspecialchars((string)$v, ENT_QUOTES); };
	$what = ($s['mode'] === 'pin') ? 'PIN' : 'Join key';
	$out = '<!doctype html><html lang="en"><meta charset="utf-8"><title>' . $h('Key sheet: ' . $s['name']) . '</title><style>' .
	    'body{font:14px system-ui,sans-serif;margin:24px;color:#111}table{border-collapse:collapse}td,th{border:1px solid #999;padding:6px 10px;text-align:left}' .
	    '.k{font:600 15px ui-monospace,monospace}</style><h1>' . $h('Key sheet: ' . $s['name']) . '</h1><p><strong>' .
	    $h('Keep this apart from the seeds and the join cards. Send each ' . strtolower($what) . ' by another channel than the seed.') . '</strong></p><table><tr><th>Firewall</th><th>Name</th><th>' . $h($what) . '</th></tr>';
	foreach ($keys as $k) {
		$out .= '<tr><td>' . $h($k['label']) . '</td><td>' . $h($k['name']) . '</td><td class="k">' . $h($k['secret']) . '</td></tr>';
	}
	return $out . '</table></html>';
}
