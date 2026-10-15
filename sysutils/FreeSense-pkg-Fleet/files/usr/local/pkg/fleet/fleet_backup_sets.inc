<?php
/*
 * fleet_backup_sets.inc
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
 * Backup sets and retention. A set names firewalls (the same targets as
 * schedules: all, groups, firewalls) and how many backups they keep: the
 * newest N, plus the newest of each day, week and month for a number of
 * days, weeks and months. A firewall in several sets keeps what any of
 * them wants; one in no set uses the default rule (Settings > Backups).
 * Never pruned: the newest backup of a firewall, pinned backups, and
 * safety backups (taken before a restore) younger than
 * backup_safety_days. When backups are taken is up to Schedules and the
 * change and nightly backups; this only decides what is kept.
 */

require_once('fleet/fleet_store.inc');

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: a retention rule from a form, or InvalidArgumentException. */
function fleet_keep_rule_from(array $in): array {
	$rule = array();
	foreach (array('last' => array(1, 500), 'daily' => array(0, 366), 'weekly' => array(0, 260), 'monthly' => array(0, 120)) as $k => list($min, $max)) {
		$v = trim((string)($in['keep_' . $k] ?? ''));
		if (!preg_match('/^\d{1,4}$/', $v) || ((int)$v < $min) || ((int)$v > $max)) {
			throw new InvalidArgumentException(sprintf('Keep %s: a whole number from %d to %d.', $k, $min, $max));
		}
		$rule[$k] = (int)$v;
	}
	return $rule;
}

/* pure: "last 10, 14 daily, 8 weekly, 12 monthly" */
function fleet_keep_rule_text(array $r): string {
	$parts = array(sprintf('last %d', $r['last']));
	foreach (array('daily', 'weekly', 'monthly') as $k) {
		if ($r[$k] > 0) {
			$parts[] = sprintf('%d %s', $r[$k], $k);
		}
	}
	return implode(', ', $parts);
}

/*
 * pure: which of one firewall's backups to keep. $rows: id, time, reason,
 * pinned (any order). $rules: retention rules (union). Returns
 * id => why it is kept (the first reason found), for every kept backup.
 */
function fleet_backup_keep(array $rows, array $rules, int $now, int $safety_days, string $tz = 'UTC'): array {
	usort($rows, function ($a, $b) {
		return ((int)$b['time'] <=> (int)$a['time']) ?: ((int)$b['id'] <=> (int)$a['id']);
	});
	$keep = array();
	$why = function (int $id, string $text) use (&$keep) {
		if (!isset($keep[$id])) {
			$keep[$id] = $text;
		}
	};
	if (!empty($rows)) {
		$why((int)$rows[0]['id'], 'Newest');
	}
	foreach ($rows as $r) {
		if (!empty($r['pinned'])) {
			$why((int)$r['id'], 'Pinned');
		} elseif (($r['reason'] === 'safety') && ($now - (int)$r['time'] < 86400 * $safety_days)) {
			$why((int)$r['id'], 'Safety backup');
		}
	}
	$zone = new DateTimeZone($tz);
	foreach ($rules as $rule) {
		foreach (array_slice($rows, 0, $rule['last']) as $r) {
			$why((int)$r['id'], 'One of the last ' . $rule['last']);
		}
		/* The newest backup in each period, for the newest N periods that have one and lie within reach. */
		foreach (array('daily' => array('Y-m-d', 86400), 'weekly' => array('o-W', 7 * 86400), 'monthly' => array('Y-m', 31 * 86400)) as $k => list($fmt, $span)) {
			if ($rule[$k] <= 0) {
				continue;
			}
			$seen = array();
			foreach ($rows as $r) {
				if ((int)$r['time'] < $now - $rule[$k] * $span) {
					break;
				}
				$period = (new DateTimeImmutable('@' . (int)$r['time']))->setTimezone($zone)->format($fmt);
				if (!isset($seen[$period]) && (count($seen) < $rule[$k])) {
					$seen[$period] = true;
					$why((int)$r['id'], ucfirst($k));
				}
			}
		}
	}
	return $keep;
}

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

function fleet_backup_default_rule(): array {
	return array('last' => fleet_opt('backup_keep_last'), 'daily' => fleet_opt('backup_keep_daily'), 'weekly' => fleet_opt('backup_keep_weekly'),
	    'monthly' => fleet_opt('backup_keep_monthly'));
}

function fleet_backup_set_row(array $r): array {
	$r['targets'] = json_decode((string)$r['targets'], true) ?: array('all');
	$r['rule'] = array('last' => (int)$r['keep_last'], 'daily' => (int)$r['keep_daily'], 'weekly' => (int)$r['keep_weekly'], 'monthly' => (int)$r['keep_monthly']);
	return $r;
}

function fleet_backup_sets_all(): array {
	return array_map('fleet_backup_set_row', fleet_db()->query('SELECT * FROM backup_sets ORDER BY name COLLATE NOCASE')->fetchAll());
}

function fleet_backup_set_save(?int $id, array $in, string $who): int {
	$name = trim((string)($in['name'] ?? ''));
	if (($name === '') || (strlen($name) > 60) || preg_match('/[<>\x00-\x1f\x7f]/', $name)) {
		throw new InvalidArgumentException('Give the set a name of 1 to 60 characters.');
	}
	$targets = fleet_targets_from($in['targets'] ?? array());
	list(, $gone) = fleet_targets_now($targets);
	if (!empty($gone)) {
		throw new InvalidArgumentException('A chosen group or firewall does not exist any more. Choose again.');
	}
	$r = fleet_keep_rule_from($in);
	$q = fleet_db()->prepare('SELECT COUNT(*) FROM backup_sets WHERE name = ? COLLATE NOCASE AND id != ?');
	$q->execute(array($name, $id ?? 0));
	if ((int)$q->fetchColumn() > 0) {
		throw new InvalidArgumentException('There is already a set with that name.');
	}
	$args = array($name, json_encode($targets), $r['last'], $r['daily'], $r['weekly'], $r['monthly']);
	if ($id === null) {
		fleet_db()->prepare('INSERT INTO backup_sets (name, targets, keep_last, keep_daily, keep_weekly, keep_monthly, created) VALUES (?, ?, ?, ?, ?, ?, ?)')
		    ->execute(array_merge($args, array(time())));
		$id = (int)fleet_db()->lastInsertId();
	} else {
		fleet_db()->prepare('UPDATE backup_sets SET name = ?, targets = ?, keep_last = ?, keep_daily = ?, keep_weekly = ?, keep_monthly = ? WHERE id = ?')
		    ->execute(array_merge($args, array($id)));
	}
	fleet_audit($who, 'backup_set', sprintf('%s: %s, keep %s', $name, fleet_targets_text($targets, fleet_target_names()), fleet_keep_rule_text($r)));
	return $id;
}

function fleet_backup_set_delete(int $id, string $who): void {
	$q = fleet_db()->prepare('SELECT name FROM backup_sets WHERE id = ?');
	$q->execute(array($id));
	$name = (string)$q->fetchColumn();
	fleet_db()->prepare('DELETE FROM backup_sets WHERE id = ?')->execute(array($id));
	fleet_audit($who, 'backup_set', "{$name}: deleted (its firewalls fall back to the sets they are still in, or the default rule)");
}

/* node_id => array(rules, set names) for every firewall: the sets it is in, or the default rule. */
function fleet_backup_rules_by_box(): array {
	$sets = fleet_backup_sets_all();
	$out = array();
	foreach (fleet_db()->query('SELECT node_id FROM boxes')->fetchAll(PDO::FETCH_COLUMN) as $n) {
		$out[$n] = array(array(), array());
	}
	foreach ($sets as $set) {
		list($boxes) = fleet_targets_now($set['targets']);
		foreach ($boxes as $b) {
			$out[$b['node_id']][0][] = $set['rule'];
			$out[$b['node_id']][1][] = $set['name'];
		}
	}
	foreach ($out as $n => $v) {
		if (empty($v[0])) {
			$out[$n] = array(array(fleet_backup_default_rule()), array());
		}
	}
	return $out;
}

/* Remove the backups no rule keeps. Returns array(backups removed, bytes freed). Backups of firewalls that left the fleet are left alone. */
function fleet_backup_prune(string $who, ?int $now = null): array {
	$now = $now ?? time();
	$removed = 0;
	$freed = 0;
	foreach (fleet_backup_rules_by_box() as $node => list($rules)) {
		$q = fleet_db()->prepare('SELECT id, time, reason, pinned, file, size FROM backups WHERE node_id = ?');
		$q->execute(array($node));
		$rows = $q->fetchAll();
		$keep = fleet_backup_keep($rows, $rules, $now, fleet_opt('backup_safety_days'), fleet_tz());
		foreach ($rows as $r) {
			if (isset($keep[(int)$r['id']])) {
				continue;
			}
			@unlink(FLEET_BACKUP_DIR . '/' . $r['file']);
			fleet_db()->prepare('DELETE FROM backups WHERE id = ?')->execute(array($r['id']));
			$removed++;
			$freed += (int)$r['size'];
		}
	}
	if ($removed > 0) {
		fleet_audit($who, 'backup_prune', sprintf('%d old backups removed by the keep rules', $removed));
	}
	return array($removed, $freed);
}

function fleet_backup_pin(int $id, bool $pin, string $who): void {
	$row = fleet_backup_get($id);
	if ($row === null) {
		throw new RuntimeException('That backup does not exist any more.');
	}
	fleet_db()->prepare('UPDATE backups SET pinned = ? WHERE id = ?')->execute(array((int)$pin, $id));
	fleet_audit($who, 'backup_pin', sprintf('%s: backup of %s %s', $row['node_id'], date('Y-m-d H:i', (int)$row['time']), $pin ? 'pinned (never removed)' : 'unpinned'));
}

/*
 * Test restore: for every firewall, read one backup back (a random one,
 * and always the newest), decrypt it, check its hash and that it is a
 * configuration this Fleet could restore. Results per firewall in the
 * verify setting; a failure is FLEET-E806 in the audit log.
 */
function fleet_backup_verify_all(string $who): array {
	$results = array();
	foreach (fleet_db()->query('SELECT DISTINCT node_id FROM backups')->fetchAll(PDO::FETCH_COLUMN) as $node) {
		$q = fleet_db()->prepare('SELECT * FROM backups WHERE node_id = ? ORDER BY time DESC');
		$q->execute(array($node));
		$rows = $q->fetchAll();
		$pick = array($rows[0]);
		if (count($rows) > 1) {
			$pick[] = $rows[random_int(1, count($rows) - 1)];
		}
		$bad = array();
		foreach ($pick as $r) {
			$xml = fleet_backup_read($r);
			$problem = ($xml === null) ? 'it could not be decrypted or its hash does not match' : fleet_backup_problem($xml);
			if ($problem !== null) {
				$bad[] = date('Y-m-d H:i', (int)$r['time']) . ': ' . $problem;
			}
		}
		$results[$node] = array('time' => time(), 'tested' => count($pick), 'problems' => $bad);
		if (!empty($bad)) {
			fleet_audit($who, 'backup_verify', "FLEET-E806: {$node}: " . implode('; ', $bad));
		}
	}
	fleet_setting_set('verify_results', json_encode($results));
	fleet_setting_set('verify_last', (string)time());
	$failed = count(array_filter($results, function ($r) { return !empty($r['problems']); }));
	fleet_audit($who, 'backup_verify', sprintf('%d firewalls tested, %d with problems', count($results), $failed));
	return $results;
}

function fleet_backup_verify_results(): array {
	return json_decode((string)fleet_setting('verify_results', '{}'), true) ?: array();
}

