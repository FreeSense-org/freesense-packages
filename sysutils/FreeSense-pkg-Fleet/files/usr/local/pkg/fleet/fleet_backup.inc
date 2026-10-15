<?php
/*
 * fleet_backup.inc
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
 * Fleet Backup, part 1: the controller keeps a copy of every box's
 * config.xml. A backup is taken when a box's configuration changed (after a
 * quiet period, so a burst of saves gives one backup), every night, and on
 * request. Each file is encrypted with the controller's master key
 * (AES-256-GCM), read back and checked after writing, and listed in the
 * backups table. An unchanged configuration is not stored twice.
 */

require_once('fleet/fleet_store.inc');

define('FLEET_BACKUP_DIR', FLEET_DATA . '/backups');
/* A configuration must have been quiet this long before an on-change backup. */
define('FLEET_BACKUP_QUIET', 300);
/* How many boxes "Back up all now" works on at the same time. */
define('FLEET_BACKUP_PARALLEL', 10);

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: why this is not a usable configuration, or null. */
function fleet_backup_problem(string $xml): ?string {
	if (trim($xml) === '') {
		return 'The box sent an empty configuration.';
	}
	$prev = libxml_use_internal_errors(true);
	$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET);
	libxml_clear_errors();
	libxml_use_internal_errors($prev);
	if ($doc === false) {
		return 'The configuration is not valid XML.';
	}
	if (!in_array($doc->getName(), array('freesense', 'pfsense'), true) || !isset($doc->version)) {
		return 'The file is not a FreeSense configuration.';
	}
	return null;
}

/* pure: what a backup says about itself: when the configuration was saved, why, and its config version. */
function fleet_backup_meta(string $xml): array {
	$meta = array('config_time' => null, 'description' => '', 'version' => '');
	if (preg_match('~<version>([^<]{1,20})</version>~', $xml, $m)) {
		$meta['version'] = $m[1];
	}
	if (preg_match('~<revision>(.*?)</revision>~s', $xml, $r)) {
		if (preg_match('~<time>(\d{1,12})</time>~', $r[1], $m)) {
			$meta['config_time'] = (int)$m[1];
		}
		if (preg_match('~<description>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</description>~s', $r[1], $m)) {
			$meta['description'] = mb_substr(html_entity_decode(trim($m[1]), ENT_QUOTES | ENT_XML1, 'UTF-8'), 0, 200);
		}
	}
	return $meta;
}

/*
 * pure: should the status check take an on-change backup now? Yes when the
 * box's configuration differs from the newest backup and was last saved at
 * least FLEET_BACKUP_QUIET seconds ago.
 */
function fleet_backup_due(?array $latest, array $status, int $now): bool {
	$rev = (array)($status['config_revision'] ?? array());
	$sha = (string)($rev['sha256'] ?? '');
	if (!preg_match('/^[0-9a-f]{64}$/D', $sha)) {
		return false;
	}
	if (($latest !== null) && hash_equals((string)$latest['sha256'], $sha)) {
		return false;
	}
	return ($now - (int)($rev['time'] ?? 0)) >= FLEET_BACKUP_QUIET;
}

/* pure: where a backup's file lives, relative to FLEET_BACKUP_DIR. */
function fleet_backup_file(string $node_id, int $time, string $sha256): string {
	return preg_replace('/[^A-Za-z0-9_-]/', '', $node_id) . '/' . gmdate('Ymd-His', $time) . '-' . substr($sha256, 0, 12) . '.xml.enc';
}

/* pure: the words for why a backup was taken. */
function fleet_backup_reason_text(string $reason): string {
	$names = array('change' => 'Configuration changed', 'nightly' => 'Nightly', 'manual' => 'Backed up by hand', 'all' => 'Back up all',
	    'safety' => 'Before a restore');
	return $names[$reason] ?? ucfirst($reason);
}

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

function fleet_backup_latest(string $node_id): ?array {
	$q = fleet_db()->prepare('SELECT * FROM backups WHERE node_id = ? ORDER BY time DESC, id DESC LIMIT 1');
	$q->execute(array($node_id));
	$row = $q->fetch();
	return is_array($row) ? $row : null;
}

function fleet_backup_get(int $id): ?array {
	$q = fleet_db()->prepare('SELECT * FROM backups WHERE id = ?');
	$q->execute(array($id));
	$row = $q->fetch();
	return is_array($row) ? $row : null;
}

function fleet_backup_list(string $node_id, int $limit = 50): array {
	$q = fleet_db()->prepare('SELECT * FROM backups WHERE node_id = ? ORDER BY time DESC, id DESC LIMIT ' . max(1, $limit));
	$q->execute(array($node_id));
	return $q->fetchAll();
}

/* The configuration in a backup, or null when the file is missing or does not decrypt to what was stored. */
function fleet_backup_read(array $row): ?string {
	$sealed = @file_get_contents(FLEET_BACKUP_DIR . '/' . $row['file']);
	$xml = ($sealed === false) ? null : fleet_unseal($sealed, fleet_master_key());
	return (($xml !== null) && hash_equals((string)$row['sha256'], hash('sha256', $xml))) ? $xml : null;
}

/*
 * Store a configuration. Returns array('stored' | 'unchanged', backup row).
 * The file is written, read back and checked before the row is added.
 */
function fleet_backup_store(array $box, string $xml, string $reason, string $who, int $now): array {
	$problem = fleet_backup_problem($xml);
	if ($problem !== null) {
		throw new RuntimeException($problem);
	}
	$sha = hash('sha256', $xml);
	$latest = fleet_backup_latest($box['node_id']);
	if (($latest !== null) && hash_equals((string)$latest['sha256'], $sha)) {
		return array('unchanged', $latest);
	}
	$file = fleet_backup_file($box['node_id'], $now, $sha);
	$path = FLEET_BACKUP_DIR . '/' . $file;
	if (!is_dir(dirname($path)) && !@mkdir(dirname($path), 0700, true)) {
		throw new RuntimeException('The backup directory could not be created.');
	}
	$tmp = $path . '.tmp';
	if (@file_put_contents($tmp, fleet_seal($xml, fleet_master_key()), LOCK_EX) === false) {
		throw new RuntimeException('The backup could not be written. Check the free space on the controller.');
	}
	@chmod($tmp, 0600);
	rename($tmp, $path);
	$meta = fleet_backup_meta($xml);
	$row = array('node_id' => $box['node_id'], 'time' => $now, 'reason' => $reason, 'who' => $who, 'sha256' => $sha,
	    'size' => strlen($xml), 'file' => $file) + $meta;
	if (fleet_backup_read($row) === null) {
		@unlink($path);
		throw new RuntimeException('FLEET-E802: The backup failed its check after writing and was discarded.');
	}
	fleet_db()->prepare('INSERT INTO backups (node_id, time, reason, who, sha256, size, file, config_time, description, version)
	    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')->execute(array($row['node_id'], $now, $reason, $who, $sha, $row['size'], $file,
	    $meta['config_time'], $meta['description'], $meta['version']));
	$row['id'] = (int)fleet_db()->lastInsertId();
	fleet_audit($who, 'backup', "{$box['node_id']} ({$box['label']}): " . fleet_backup_reason_text($reason) . ', ' . substr($sha, 0, 12));
	return array('stored', $row);
}

/* One API call to a box over the tunnel. Returns array(status, JSON, raw body); a connection problem is a RuntimeException. */
function fleet_box_call(array $box, string $method, string $path, ?array $body = null): array {
	$key = (string)fleet_unseal((string)$box['api_key'], fleet_master_key());
	try {
		return fleet_http_pinned(fleet_box_target($box), $method, $path, $body, $key);
	} catch (FleetJoinError $e) {
		throw new RuntimeException(fleet_poll_problem($e->fleet_code, $e->getMessage()));
	}
}

/* A box's running configuration, fetched over the tunnel. */
function fleet_backup_fetch(array $box): string {
	list($code, , $raw) = fleet_box_call($box, 'GET', '/api/v1/config/revisions/current');
	if ($code !== 200) {
		throw new RuntimeException("The box answered HTTP {$code} when asked for its configuration.");
	}
	return (string)$raw;
}

/* Fetch a box's running configuration over the tunnel and store it. */
function fleet_backup_box(array $box, string $reason, string $who): array {
	return fleet_backup_store($box, fleet_backup_fetch($box), $reason, $who, time());
}

/* How long the box waits for the controller to confirm a restore before it goes back by itself. */
define('FLEET_RESTORE_CONFIRM', 300);

/* pure: the error text of a box's JSON answer. */
function fleet_box_error(int $code, array $json): string {
	/* A validation error names the field; that message says more than the general one. */
	$fields = array_filter((array)($json['error']['details']['fields'] ?? array()), 'is_string');
	$msg = !empty($fields) ? implode(' ', $fields) : (string)($json['error']['message'] ?? '');
	return ($msg !== '') ? $msg : "The box answered HTTP {$code}.";
}

/*
 * Restore a backup onto its box: a safety backup first, then the restore
 * inside a commit-confirm window, then the box must still answer over the
 * tunnel before the controller confirms. Returns the words for the result;
 * a RuntimeException says what went wrong (the box reverts by itself when
 * it was left unconfirmed).
 */
function fleet_backup_restore(array $box, array $row, string $who, ?callable $sleep = null): string {
	$sleep = $sleep ?? 'sleep';
	$xml = fleet_backup_read($row);
	if ($xml === null) {
		throw new RuntimeException('FLEET-E802: That backup could not be read. Its file is missing or damaged.');
	}
	fleet_backup_box($box, 'safety', $who);
	$when = date('Y-m-d H:i', (int)$row['time']);
	list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/management/commit-confirm',
	    array('seconds' => FLEET_RESTORE_CONFIRM, 'label' => "Fleet: restore of the backup from {$when}"));
	$id = (string)($json['data']['id'] ?? '');
	if (($code !== 201) || ($id === '')) {
		throw new RuntimeException('The box could not take a snapshot first: ' . fleet_box_error($code, $json));
	}
	list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/management/restore',
	    array('config' => $xml, 'commit_confirm' => $id, 'description' => "Restored from the Fleet backup of {$when} by {$who}"));
	if ($code !== 200) {
		/* Nothing was restored; close the window (the snapshot is the running configuration). */
		try {
			fleet_box_call($box, 'DELETE', '/api/v1/management/commit-confirm/' . rawurlencode($id));
		} catch (RuntimeException $e) {
		}
		fleet_audit($who, 'restore_failed', "{$box['node_id']} ({$box['label']}): " . fleet_box_error($code, $json));
		throw new RuntimeException('The box refused the restore: ' . fleet_box_error($code, $json));
	}
	/* The box reloads its rules; it must still answer before the restore is kept. */
	for ($try = 0; $try < 12; $try++) {
		$sleep(5);
		try {
			list($code) = fleet_box_call($box, 'POST', '/api/v1/management/commit-confirm/' . rawurlencode($id) . '/confirm');
			if ($code === 200) {
				fleet_audit($who, 'restore', "{$box['node_id']} ({$box['label']}): backup of {$when}");
				return "Restored the backup of {$when}. The firewall answered afterwards, so the restore was kept.";
			}
		} catch (RuntimeException $e) {
		}
	}
	fleet_audit($who, 'restore_failed', "{$box['node_id']} ({$box['label']}): no answer after the restore of {$when}; it reverts by itself");
	throw new RuntimeException('FLEET-E310: The firewall did not answer after the restore. It goes back to its previous configuration by itself within ' .
	    (FLEET_RESTORE_CONFIRM / 60) . ' minutes.');
}

/*
 * A unified diff of two configurations (diff(1) on temporary files that
 * only root can read). Empty when they are the same.
 */
function fleet_backup_diff(string $old, string $new): string {
	$dir = FLEET_DATA . '/tmp';
	if (!is_dir($dir)) {
		@mkdir($dir, 0700, true);
	}
	$a = tempnam($dir, 'diff');
	$b = tempnam($dir, 'diff');
	file_put_contents($a, $old);
	file_put_contents($b, $new);
	$lines = array();
	exec('/usr/bin/diff -u ' . escapeshellarg($a) . ' ' . escapeshellarg($b), $lines);
	@unlink($a);
	@unlink($b);
	/* The two header lines name the temporary files; they mean nothing to the reader. */
	return implode("\n", array_slice($lines, 2));
}

/*
 * Back up many boxes, FLEET_BACKUP_PARALLEL at a time (each in its own
 * process, so one slow box does not hold up the rest). Returns
 * array(node_id => 'stored' | 'unchanged' | error text).
 */
function fleet_backup_many(array $boxes, string $reason, string $who): array {
	$results = array();
	foreach (array_chunk($boxes, FLEET_BACKUP_PARALLEL) as $chunk) {
		$procs = array();
		foreach ($chunk as $box) {
			$spec = array(1 => array('pipe', 'w'), 2 => array('file', '/dev/null', 'w'));
			$p = proc_open(array('/usr/local/bin/php', '/usr/local/sbin/freesense-fleet-backup', 'one', $box['node_id'], $reason, $who), $spec, $pipes);
			if (is_resource($p)) {
				$procs[$box['node_id']] = array($p, $pipes[1]);
			} else {
				$results[$box['node_id']] = 'The backup could not be started.';
			}
		}
		foreach ($procs as $node_id => list($p, $out)) {
			$results[$node_id] = trim((string)stream_get_contents($out)) ?: 'The backup stopped without an answer.';
			fclose($out);
			proc_close($p);
		}
	}
	return $results;
}
