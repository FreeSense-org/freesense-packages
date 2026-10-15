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
 * What still uses a group (policies, backup sets, rings, templates as they
 * arrive), as words. A group in use cannot be deleted.
 */
function fleet_group_users(int $id): array {
	return array();
}

/* Delete a group (its firewalls stay). Throws RuntimeException when something still uses it. */
function fleet_group_delete(int $id, string $who): void {
	$group = fleet_group_get($id);
	if ($group === null) {
		return;
	}
	$users = fleet_group_users($id);
	if (!empty($users)) {
		throw new RuntimeException("\"{$group['name']}\" is still used by " . implode(', ', $users) . '.');
	}
	fleet_db()->prepare('DELETE FROM box_groups WHERE group_id = ?')->execute(array($id));
	fleet_db()->prepare('DELETE FROM fleet_groups WHERE id = ?')->execute(array($id));
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
