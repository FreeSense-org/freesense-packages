<?php
/*
 * fleet_manage.inc
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
 * Managing a firewall from the controller: reboot, its services and the
 * state table. Only for firewalls joined as Managed (a monitor-only box
 * refuses these calls itself). Halt is not offered: a halted box cannot be
 * started again remotely. Every action is audited on the controller and
 * logged on the box.
 */

require_once('fleet/fleet_store.inc');

/* pure: may the controller change this firewall? */
function fleet_manage_allowed(array $box): bool {
	return ($box['role'] ?? '') === 'managed';
}

/* pure: the services a box reported, sorted by description, with what each can do. */
function fleet_services_from(array $json): array {
	$out = array();
	foreach ((array)($json['data'] ?? array()) as $svc) {
		if (!is_array($svc) || !is_string($svc['name'] ?? null) || !preg_match('/^[A-Za-z0-9._-]{1,64}$/D', $svc['name'])) {
			continue;
		}
		$entry = array('name' => $svc['name'], 'description' => html_entity_decode((string)($svc['description'] ?? ''), ENT_QUOTES),
		    'running' => !empty($svc['running']));
		foreach (array('mode', 'vpnid', 'zone') as $f) {
			if (isset($svc[$f])) {
				$entry[$f] = $svc[$f];
			}
		}
		$out[] = $entry;
	}
	usort($out, function ($a, $b) {
		return strcasecmp($a['description'] ?: $a['name'], $b['description'] ?: $b['name']);
	});
	return $out;
}

/* pure: the body that addresses one service (OpenVPN instances and captive portal zones need more than a name). */
function fleet_service_body(array $svc): array {
	$body = array('confirm' => true);
	if (isset($svc['mode'])) {
		$body['mode'] = (string)$svc['mode'];
	}
	if (isset($svc['vpnid'])) {
		$body['vpnid'] = (int)$svc['vpnid'];
	}
	if (isset($svc['zone'])) {
		$body['zone'] = (string)$svc['zone'];
	}
	return $body;
}

/* Who asks, as the box logs it: "admin@fleetctl". */
function fleet_operator(string $who): string {
	return substr($who . '@' . (string)config_get_path('system/hostname', 'controller'), 0, 80);
}

function fleet_manage_require(array $box): void {
	if (!fleet_manage_allowed($box)) {
		throw new RuntimeException('This firewall joined as Monitor only, so the controller may not change it. Let it leave and join again as Managed.');
	}
}

/* Reboot a firewall. Returns the words for the result. $task: the group operation's task for it, if any. */
function fleet_box_reboot(array $box, string $who, ?int $task = null): string {
	fleet_manage_require($box);
	if (($task === null) && (fleet_op_running($box['node_id']) !== null)) {
		throw new RuntimeException('Something is already running on this firewall. Wait until it is done.');
	}
	list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/management/reboot', array('confirm' => true, 'operator' => fleet_operator($who)));
	if ($code !== 202) {
		throw new RuntimeException('The firewall refused the reboot: ' . fleet_box_error($code, $json));
	}
	fleet_audit($who, 'reboot', "{$box['node_id']} ({$box['label']}): reboot started");
	if ($task === null) {
		fleet_op_start($box['node_id'], 'reboot', 'Rebooting', $who);
	} else {
		/* Started now: the poll compares the box's boot time with this. */
		fleet_db()->prepare("UPDATE ops SET state = 'running', text = 'Rebooting', started = ?, updated = ? WHERE id = ?")->execute(array(time(), time(), $task));
	}
	return 'The firewall is rebooting. It is usually back within a few minutes; the dashboard shows when it is online again.';
}

/* The firewall's services, as it reports them now. */
function fleet_box_services(array $box): array {
	list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/status/services');
	if ($code !== 200) {
		throw new RuntimeException('The firewall did not list its services: ' . fleet_box_error($code, $json));
	}
	return fleet_services_from($json);
}

/* Start, stop or restart one service. Returns the words for the result. */
function fleet_box_service(array $box, array $svc, string $action, string $who): string {
	fleet_manage_require($box);
	if (!in_array($action, array('start', 'stop', 'restart'), true)) {
		throw new RuntimeException('Unknown action.');
	}
	list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/services/' . rawurlencode($svc['name']) . '/' . $action, fleet_service_body($svc));
	if ($code !== 200) {
		throw new RuntimeException(fleet_box_error($code, $json));
	}
	$label = ($svc['description'] ?? '') ?: $svc['name'];
	fleet_audit($who, 'service', "{$box['node_id']} ({$box['label']}): {$action} {$label}");
	$done = array('start' => 'started', 'stop' => 'stopped', 'restart' => 'restarted');
	return ucfirst("{$label} {$done[$action]}.");
}

/* Reset the state table (every connection through the firewall is dropped). */
function fleet_box_states_reset(array $box, string $who): string {
	fleet_manage_require($box);
	list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/diagnostics/states/reset', array('confirm' => true));
	if (($code !== 200) && ($code !== 202)) {
		throw new RuntimeException('The firewall refused: ' . fleet_box_error($code, $json));
	}
	fleet_audit($who, 'states_reset', "{$box['node_id']} ({$box['label']}): state table reset");
	return 'The state table is being reset. Connections through the firewall start again.';
}
