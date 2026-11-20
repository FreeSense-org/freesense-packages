<?php
/*
 * fleet_groups.inc
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
 * Groups of firewalls. A firewall can be in several groups ("Denmark",
 * "Retail", "Canary"); policies, backup sets, update rings and bulk actions
 * target groups. Deleting a group never touches its firewalls, and a group
 * something still uses cannot be deleted (fleet_group_users()).
 */

require_once('fleet/fleet_store.inc');

/* The colours a group can have: chart series tokens, readable in both themes. */
define('FLEET_GROUP_COLORS', array('1', '2', '3', '4', '5', '6', '7', '8'));

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: why a group name cannot be used, or null. $taken: the other groups' names. */
function fleet_group_name_problem(string $name, array $taken): ?string {
	if (($name === '') || (mb_strlen($name) > 40)) {
		return 'A group name has 1 to 40 characters.';
	}
	if (preg_match('/[\x00-\x1f\x7f<>]/u', $name)) {
		return 'A group name cannot contain control characters, < or >.';
	}
	if (strcasecmp($name, 'All firewalls') === 0) {
		return '"All firewalls" is built in.';
	}
	foreach ($taken as $t) {
		if (mb_strtolower((string)$t) === mb_strtolower($name)) {
			return "There is already a group called \"{$name}\".";
		}
	}
	return null;
}

/* pure: a colour from the form, or the first one. */
function fleet_group_color(string $color): string {
	return in_array($color, FLEET_GROUP_COLORS, true) ? $color : FLEET_GROUP_COLORS[0];
}

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

/* Every group with its member count, by name. */
function fleet_groups_all(): array {
	return fleet_db()->query('SELECT g.*, (SELECT COUNT(*) FROM box_groups bg WHERE bg.group_id = g.id) AS members
	    FROM fleet_groups g ORDER BY g.name COLLATE NOCASE')->fetchAll();
}

function fleet_group_get(int $id): ?array {
	$q = fleet_db()->prepare('SELECT * FROM fleet_groups WHERE id = ?');
	$q->execute(array($id));
	$row = $q->fetch();
	return is_array($row) ? $row : null;
}

/* Create a group, or change one when $id is given. Returns the group's id; throws InvalidArgumentException with the problem. */
function fleet_group_save(?int $id, string $name, string $description, string $color, string $who): int {
	$name = trim($name);
	$q = fleet_db()->prepare('SELECT name FROM fleet_groups WHERE id != ?');
	$q->execute(array($id ?? 0));
	$problem = fleet_group_name_problem($name, $q->fetchAll(PDO::FETCH_COLUMN));
	if ($problem !== null) {
		throw new InvalidArgumentException($problem);
	}
	$description = mb_substr(trim(preg_replace('/[\x00-\x1f\x7f]/u', ' ', $description)), 0, 200);
	$color = fleet_group_color($color);
	if ($id === null) {
		fleet_db()->prepare('INSERT INTO fleet_groups (name, description, color, created) VALUES (?, ?, ?, ?)')
		    ->execute(array($name, $description, $color, time()));
		$id = (int)fleet_db()->lastInsertId();
		fleet_audit($who, 'group_create', "group {$id}: {$name}");
	} else {
		fleet_db()->prepare('UPDATE fleet_groups SET name = ?, description = ?, color = ? WHERE id = ?')->execute(array($name, $description, $color, $id));
		fleet_audit($who, 'group_change', "group {$id}: {$name}");
	}
	return $id;
}

/*
 * What still uses a group, as words ("policy Baseline", "2 schedules"): the
 * policies, schedules, backup sets, templates and user groups that target it
 * ("g:<id>"), a rollout that is not finished and has it as a ring, a NOC screen
 * that shows it, and open invitations that put new firewalls in it. A group in
 * use cannot be deleted: its Lock policy, backups or rings would silently stop
 * covering the firewalls.
 */
function fleet_group_users(int $id): array {
	$db = fleet_db();
	$found = array();
	foreach (array('policies' => 'policy', 'schedules' => 'schedule', 'backup_sets' => 'backup set', 'templates' => 'template', 'ugroups' => 'user group') as $table => $what) {
		$q = $db->prepare("SELECT name FROM {$table} WHERE EXISTS (SELECT 1 FROM json_each({$table}.targets) WHERE value = ?) ORDER BY name COLLATE NOCASE");
		$q->execute(array('g:' . $id));
		$found[$what] = $q->fetchAll(PDO::FETCH_COLUMN);
	}
	$q = $db->prepare("SELECT target FROM rollouts WHERE state IN ('running', 'paused')
	    AND EXISTS (SELECT 1 FROM json_each(rollouts.rings) WHERE json_extract(value, '$.group') = CAST(? AS INTEGER)) ORDER BY id");
	$q->execute(array($id));
	$found['rollout'] = $q->fetchAll(PDO::FETCH_COLUMN);
	$found['NOC screen'] = array();
	foreach ($db->query('SELECT name, config FROM kiosk_keys WHERE revoked IS NULL OR revoked = 0 ORDER BY name COLLATE NOCASE')->fetchAll() as $k) {
		$config = json_decode((string)$k['config'], true);
		if (is_array($config) && in_array($id, array_map('intval', (array)($config['groups'] ?? array())), true)) {
			$found['NOC screen'][] = $k['name'];
		}
	}
	$q = $db->prepare("SELECT label FROM invitations WHERE state = 'open' AND group_id = ? ORDER BY created");
	$q->execute(array($id));
	$found['open invitation'] = $q->fetchAll(PDO::FETCH_COLUMN);
	return fleet_group_users_words($found);
}

/* pure: the users as words from what was found (kind => names): "policy Baseline, 3 schedules". */
function fleet_group_users_words(array $found): array {
	$words = array();
	foreach ($found as $what => $names) {
		if (count($names) === 1) {
			$words[] = "{$what} \"{$names[0]}\"";
		} elseif (count($names) > 1) {
			$words[] = count($names) . " {$what}s (" . implode(', ', array_slice($names, 0, 3)) . ((count($names) > 3) ? ', ...' : '') . ')';
		}
	}
	return $words;
}

/* Delete a group (its firewalls stay). Throws RuntimeException when something still uses it. */
function fleet_group_delete(int $id, string $who): void {
	$db = fleet_db();
	$db->exec('BEGIN IMMEDIATE');
	try {
		$group = fleet_group_get($id);
		if ($group === null) {
			$db->exec('ROLLBACK');
			return;
		}
		$users = fleet_group_users($id);
		if (!empty($users)) {
			throw new RuntimeException("\"{$group['name']}\" is still used by " . implode(', ', $users) . '. Remove it there first.');
		}
		$db->prepare('DELETE FROM box_groups WHERE group_id = ?')->execute(array($id));
		$db->prepare('DELETE FROM fleet_groups WHERE id = ?')->execute(array($id));
		$db->exec('COMMIT');
	} catch (Throwable $e) {
		$db->exec('ROLLBACK');
		throw $e;
	}
	fleet_audit($who, 'group_delete', "group {$id}: {$group['name']}");
}

/* The groups a firewall is in, by name. */
function fleet_box_groups(string $node_id): array {
	$q = fleet_db()->prepare('SELECT g.* FROM fleet_groups g JOIN box_groups bg ON bg.group_id = g.id WHERE bg.node_id = ? ORDER BY g.name COLLATE NOCASE');
	$q->execute(array($node_id));
	return $q->fetchAll();
}

/* Put a firewall in exactly these groups (unknown ids are ignored). */
function fleet_box_set_groups(array $box, array $group_ids, string $who): void {
	$valid = array_map('intval', fleet_db()->query('SELECT id FROM fleet_groups')->fetchAll(PDO::FETCH_COLUMN));
	$ids = array_values(array_intersect(array_unique(array_map('intval', $group_ids)), $valid));
	$db = fleet_db();
	$db->beginTransaction();
	$db->prepare('DELETE FROM box_groups WHERE node_id = ?')->execute(array($box['node_id']));
	$ins = $db->prepare('INSERT INTO box_groups (node_id, group_id) VALUES (?, ?)');
	foreach ($ids as $gid) {
		$ins->execute(array($box['node_id'], $gid));
	}
	$db->commit();
	$names = array_column(fleet_box_groups($box['node_id']), 'name');
	fleet_audit($who, 'groups', "{$box['node_id']} ({$box['label']}): " . (empty($names) ? 'in no group' : 'in ' . implode(', ', $names)));
}

/* Every firewall's groups as node_id => [array(id, name, color), ...], for the dashboard. */
function fleet_groups_by_box(): array {
	$out = array();
	foreach (fleet_db()->query('SELECT bg.node_id, g.id, g.name, g.color FROM box_groups bg JOIN fleet_groups g ON g.id = bg.group_id ORDER BY g.name COLLATE NOCASE') as $r) {
		$out[$r['node_id']][] = array('id' => (int)$r['id'], 'name' => (string)$r['name'], 'color' => (string)$r['color']);
	}
	return $out;
}
