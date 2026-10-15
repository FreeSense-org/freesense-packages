<?php
/*
 * fleet.php
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

/* System > FreeSense Fleet: settings, invitations, approvals and the box list. */

##|+PRIV
##|*IDENT=page-system-fleet-controller
##|*NAME=System: FreeSense Fleet
##|*DESCR=Manage the fleet: invite, approve and remove firewalls, and change the controller settings.
##|*MATCH=fleet/fleet.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('fleet.inc');

$pgtitle = array(gettext('System'), gettext('FreeSense Fleet'));
$s = fleet_ctl_settings();
$who = (string)($_SESSION['Username'] ?? 'admin');
$input_errors = array();
$savemsg = null;
$new_invite = null;

if ($_POST['save_settings'] ?? false) {
	$host = trim((string)($_POST['public_host'] ?? ''));
	$post = array('enable' => !empty($_POST['enable']) ? 'on' : '', 'public_host' => $host,
	    'enroll_port' => (string)($_POST['enroll_port'] ?? ''), 'wg_port' => (string)($_POST['wg_port'] ?? ''));
	$check = fleet_ctl_settings_from($post);
	if ($check['enable'] && !fleet_join_valid_authority($host)) {
		$input_errors[] = gettext('Enter the host name or IP address boxes use to reach this controller.');
	}
	if ((string)$check['enroll_port'] !== $post['enroll_port'] || (string)$check['wg_port'] !== $post['wg_port']) {
		$input_errors[] = gettext('Ports are numbers from 1 to 65535.');
	}
	if (empty($input_errors)) {
		config_set_path('installedpackages/fleet/config/0', $post);
		write_config(gettext('FreeSense Fleet settings saved.'));
		$problems = fleet_sync_config();
		$s = fleet_ctl_settings();
		if (empty($problems)) {
			$savemsg = $s['enable'] ? gettext('FreeSense Fleet is running.') : gettext('FreeSense Fleet is stopped.');
		} else {
			$input_errors = array_merge($input_errors, $problems);
		}
	}
} elseif (($_POST['invite'] ?? false) && $s['enable']) {
	try {
		$new_invite = fleet_invite_create((string)($_POST['role'] ?? 'monitor'), trim((string)($_POST['label'] ?? '')),
		    3600 * max(1, (int)($_POST['hours'] ?? 24)), $who, fleet_hostport($s['public_host'], $s['enroll_port']), time());
	} catch (InvalidArgumentException $e) {
		$input_errors[] = $e->getMessage();
	}
} elseif (isset($_POST['decide'], $_POST['enrollment']) && $s['enable']) {
	if (fleet_enroll_decide((string)$_POST['enrollment'], $_POST['decide'] === 'approve', $who, time())) {
		$savemsg = ($_POST['decide'] === 'approve') ? gettext('Approved. The box finishes joining by itself.') : gettext('Rejected.');
	}
} elseif (isset($_POST['revoke']) && $s['enable']) {
	fleet_invite_revoke((string)$_POST['revoke'], $who);
}

$ready = $s['enable'] && is_file(FLEET_DATA . '/fleet.db');
$pending = $ready ? fleet_db()->query("SELECT e.*, i.label, i.role FROM enrollments e JOIN invitations i ON i.token_id = e.token_id WHERE e.state = 'pending' ORDER BY e.created")->fetchAll() : array();
$invites = $ready ? fleet_db()->query("SELECT * FROM invitations WHERE state = 'open' AND expires > " . time() . " ORDER BY created DESC")->fetchAll() : array();
$boxes = $ready ? fleet_db()->query('SELECT * FROM boxes ORDER BY label')->fetchAll() : array();

include('head.inc');
if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box(htmlspecialchars($savemsg), 'success');
}
if ($new_invite !== null) {
	list($link, $key, $tid, $expires) = $new_invite;
	print_info_box('<strong>' . gettext('Invitation created. This is the only time the join key is shown.') . '</strong><br/>' .
	    gettext('Join link') . ': <code class="fs-mono user-select-all">' . htmlspecialchars($link) . '</code><br/>' .
	    gettext('Join key (send it by another channel)') . ': <code class="fs-mono user-select-all">' . htmlspecialchars($key) . '</code><br/>' .
	    sprintf(gettext('On the new firewall: console option 17, or %s'), '<code>freesense-join join \'&lt;link&gt;\'</code>') .
	    '. ' . sprintf(gettext('Valid until %s.'), date('Y-m-d H:i', $expires)), 'info');
}
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Controller settings')?></h2></div>
	<div class="panel-body">
	<form method="post" class="row g-3">
		<div class="col-12"><label class="form-check-label"><input class="form-check-input" type="checkbox" name="enable" <?=$s['enable'] ? 'checked' : ''?>/> <?=gettext('Run this firewall as a FreeSense Fleet controller')?></label></div>
		<div class="col-md-6"><label class="form-label" for="public_host"><?=gettext('Address boxes use to reach this controller')?></label>
			<input class="form-control" id="public_host" name="public_host" value="<?=htmlspecialchars($s['public_host'])?>" placeholder="fleet.example.net"/></div>
		<div class="col-md-3"><label class="form-label" for="enroll_port"><?=gettext('Enrollment port (TCP)')?></label>
			<input class="form-control" id="enroll_port" name="enroll_port" value="<?=(int)$s['enroll_port']?>"/></div>
		<div class="col-md-3"><label class="form-label" for="wg_port"><?=gettext('Tunnel port (UDP)')?></label>
			<input class="form-control" id="wg_port" name="wg_port" value="<?=(int)$s['wg_port']?>"/></div>
		<div class="col-12 fs-muted small"><?=gettext('Works only if boxes can reach this address on both ports. Boxes may be behind NAT; they start the connection.')?>
<?php if ($ready && !fleet_data_on_zfs()): ?>
			<br/><span class="text-warning"><?=gettext('This controller runs on UFS. Fleet works, but a failed update of this controller cannot roll back automatically. ZFS is recommended for the controller.')?></span>
<?php endif; ?></div>
		<div class="col-12"><button class="btn btn-primary" type="submit" name="save_settings" value="1"><i class="fa-solid fa-save icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button></div>
	</form>
	</div>
</div>
<?php if ($ready): ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Add a firewall')?></h2></div>
	<div class="panel-body">
	<form method="post" class="row g-3 align-items-end">
		<div class="col-md-5"><label class="form-label" for="label"><?=gettext('Label')?></label><input class="form-control" id="label" name="label" placeholder="Copenhagen office" required maxlength="80"/></div>
		<div class="col-md-3"><label class="form-label" for="role"><?=gettext('Role')?></label>
			<select class="form-select" id="role" name="role"><option value="monitor"><?=gettext('Monitor only')?></option><option value="managed"><?=gettext('Managed')?></option></select></div>
		<div class="col-md-2"><label class="form-label" for="hours"><?=gettext('Valid (hours)')?></label><input class="form-control" id="hours" name="hours" value="24"/></div>
		<div class="col-md-2"><button class="btn btn-primary w-100" type="submit" name="invite" value="1"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Invite')?></button></div>
	</form>
	</div>
</div>
<?php if (!empty($pending)): ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Waiting for approval')?> <span class="fs-count"><?=count($pending)?></span></h2></div>
	<div class="panel-body table-responsive"><table class="table">
		<thead><tr><th><?=gettext('Label')?></th><th><?=gettext('Firewall')?></th><th><?=gettext('Code')?></th><th><?=gettext('From')?></th><th></th></tr></thead>
		<tbody>
<?php foreach ($pending as $e): $inv = json_decode($e['inventory'], true) ?: array(); ?>
		<tr><td><?=htmlspecialchars($e['label'])?> <span class="fs-muted">(<?=htmlspecialchars($e['role'])?>)</span></td>
			<td><?=htmlspecialchars(($inv['hostname'] ?? '') . ' ' . ($inv['version'] ?? ''))?><div class="fs-muted small"><?=htmlspecialchars($inv['serial'] ?? '')?></div></td>
			<td class="fs-mono fs-6"><strong><?=htmlspecialchars(substr($e['code'], 0, 3) . ' ' . substr($e['code'], 3))?></strong></td>
			<td class="fs-mono"><?=htmlspecialchars($e['source_ip'])?></td>
			<td><form method="post" class="d-inline"><input type="hidden" name="enrollment" value="<?=htmlspecialchars($e['id'])?>"/>
				<button class="btn btn-sm btn-success" name="decide" value="approve" title="<?=gettext('Only when the box shows the same code')?>"><?=gettext('Approve')?></button>
				<button class="btn btn-sm btn-outline-danger" name="decide" value="reject"><?=gettext('Reject')?></button></form></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
</div>
<?php endif; ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Firewalls')?> <span class="fs-count"><?=count($boxes)?></span></h2></div>
	<div class="panel-body table-responsive"><table class="table table-hover">
		<thead><tr><th><?=gettext('Status')?></th><th><?=gettext('Label')?></th><th><?=gettext('Firewall')?></th><th><?=gettext('Version')?></th><th><?=gettext('Overlay')?></th><th><?=gettext('Role')?></th><th><?=gettext('Last seen')?></th></tr></thead>
		<tbody>
<?php if (empty($boxes)): ?>
		<tr><td colspan="7" class="fs-muted"><?=gettext('No firewalls yet. Invite one above.')?></td></tr>
<?php endif; ?>
<?php foreach ($boxes as $b): $st = json_decode((string)$b['status'], true) ?: array(); ?>
		<tr><td><?=fs_badge(array('online' => 'online', 'degraded' => 'degraded', 'offline' => 'offline')[$b['state']] ?? 'pending', ucfirst($b['state']), (string)$b['error'])?></td>
			<td><?=htmlspecialchars($b['label'])?></td>
			<td><?=htmlspecialchars($st['hostname'] ?? $b['name'])?></td>
			<td><?=htmlspecialchars($st['version'] ?? '')?><?php if (isset($st['rollback_protection']) && !$st['rollback_protection']): ?> <?=fs_badge('warn', gettext('No rollback'), gettext('UFS: a failed update cannot roll back by itself'))?><?php endif; ?></td>
			<td class="fs-mono"><?=htmlspecialchars($b['overlay'])?></td>
			<td><?=htmlspecialchars($b['role'])?></td>
			<td><?=$b['last_seen'] ? htmlspecialchars(date('Y-m-d H:i:s', (int)$b['last_seen'])) : '<span class="fs-muted">' . gettext('never') . '</span>'?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
</div>
<?php if (!empty($invites)): ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Open invitations')?></h2></div>
	<div class="panel-body table-responsive"><table class="table">
		<thead><tr><th><?=gettext('Label')?></th><th><?=gettext('Role')?></th><th><?=gettext('Valid until')?></th><th><?=gettext('Wrong keys')?></th><th></th></tr></thead><tbody>
<?php foreach ($invites as $i): ?>
		<tr><td><?=htmlspecialchars($i['label'])?></td><td><?=htmlspecialchars($i['role'])?></td><td><?=htmlspecialchars(date('Y-m-d H:i', (int)$i['expires']))?></td>
			<td><?=(int)$i['failures']?> / <?=FLEET_INVITE_MAX_FAILURES?></td>
			<td><form method="post"><button class="btn btn-sm btn-outline-danger" name="revoke" value="<?=htmlspecialchars($i['token_id'])?>"><?=gettext('Revoke')?></button></form></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
</div>
<?php endif; ?>
<?php endif; ?>
<?php include('foot.inc');
