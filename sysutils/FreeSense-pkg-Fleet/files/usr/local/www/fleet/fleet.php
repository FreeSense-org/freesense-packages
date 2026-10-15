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

/*
 * System > FreeSense Fleet: add firewalls, approve them, and the controller
 * settings. The state of the fleet is on fleet_dashboard.php.
 */

##|+PRIV
##|*IDENT=page-system-fleet-controller
##|*NAME=System: FreeSense Fleet
##|*DESCR=Manage the fleet: invite, approve and remove firewalls, and change the controller settings.
##|*MATCH=fleet/fleet.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('fleet.inc');

$pgtitle = array(gettext('System'), gettext('FreeSense Fleet'));
$tab = (($_REQUEST['tab'] ?? '') === 'settings') ? 'settings' : 'firewalls';
$s = fleet_ctl_settings();
$who = (string)($_SESSION['Username'] ?? 'admin');
$input_errors = array();
$savemsg = null;
$new_invite = null;

if ($_POST['save_settings'] ?? false) {
	$tab = 'settings';
	$host = trim((string)($_POST['public_host'] ?? ''));
	$post = array('enable' => !empty($_POST['enable']) ? 'on' : '', 'public_host' => $host,
	    'enroll_port' => (string)($_POST['enroll_port'] ?? ''), 'wg_port' => (string)($_POST['wg_port'] ?? ''));
	$check = fleet_ctl_settings_from($post);
	if ($check['enable'] && !fleet_join_valid_authority($host)) {
		$input_errors[] = gettext('Enter the host name or IP address firewalls use to reach this controller.');
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
			$savemsg = $s['enable'] ? gettext('Saved. FreeSense Fleet is running.') : gettext('Saved. FreeSense Fleet is stopped.');
		} else {
			$input_errors = array_merge($input_errors, $problems);
		}
	}
} elseif (($_POST['invite'] ?? false) && $s['enable']) {
	try {
		$new_invite = fleet_invite_create((string)($_POST['role'] ?? 'monitor'), trim((string)($_POST['label'] ?? '')),
		    3600 * max(1, min(168, (int)($_POST['hours'] ?? 24))), $who, fleet_hostport($s['public_host'], $s['enroll_port']), time());
	} catch (InvalidArgumentException $e) {
		$input_errors[] = $e->getMessage();
	}
} elseif (isset($_POST['decide'], $_POST['enrollment']) && $s['enable']) {
	if (fleet_enroll_decide((string)$_POST['enrollment'], $_POST['decide'] === 'approve', $who, time())) {
		$savemsg = ($_POST['decide'] === 'approve') ?
		    gettext('Approved. The firewall finishes joining by itself and appears on the dashboard.') :
		    gettext('Rejected. The firewall was told to stop.');
	}
} elseif (isset($_POST['revoke']) && $s['enable']) {
	fleet_invite_revoke((string)$_POST['revoke'], $who);
	$savemsg = gettext('Invitation revoked. Its link and key no longer work.');
}

$ready = $s['enable'] && is_file(FLEET_DATA . '/fleet.db');
if (!$ready) {
	$tab = 'settings';
}
$pending = $ready ? fleet_db()->query("SELECT e.*, i.label, i.role FROM enrollments e JOIN invitations i ON i.token_id = e.token_id WHERE e.state = 'pending' ORDER BY e.created")->fetchAll() : array();
$invites = $ready ? fleet_db()->query("SELECT * FROM invitations WHERE state = 'open' AND expires > " . time() . " ORDER BY created DESC")->fetchAll() : array();
$asset = function ($f) {
	return '/fleet/assets/' . $f . '?v=' . (int)@filemtime('/usr/local/www/fleet/assets/' . $f);
};
$role_name = function ($r) {
	return ($r === 'managed') ? gettext('Managed') : gettext('Monitor only');
};

include('head.inc');
?>
<link rel="stylesheet" href="<?=$asset('fleet.css')?>">
<?php
$tab_array = array(
	array(gettext('Dashboard'), false, '/fleet/fleet_dashboard.php'),
	array(gettext('Firewalls'), $tab === 'firewalls', '/fleet/fleet.php'),
	array(gettext('Settings'), $tab === 'settings', '/fleet/fleet.php?tab=settings'),
);
display_top_tabs($tab_array);
if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box(htmlspecialchars($savemsg), 'success');
}
?>

<?php if ($tab === 'firewalls'): ?>

<?php if ($new_invite !== null): list($link, $key, $tid, $expires) = $new_invite; ?>
<section class="fs-fleet-block fs-fleet-invite" aria-labelledby="invite-title">
	<h2 id="invite-title" class="fs-fleet-section-title"><?=sprintf(gettext('Invitation for %s'), htmlspecialchars(trim((string)($_POST['label'] ?? ''))))?></h2>
	<p class="fs-fleet-lead"><?=sprintf(gettext('Valid until %s. The join key is shown only now: copy it, and send it by a different channel than the link.'), htmlspecialchars(date('Y-m-d H:i', $expires)))?></p>
	<div class="fs-fleet-secret">
		<span class="fs-fleet-secret-label"><?=gettext('Join link')?></span>
		<code id="fleet-link" class="fs-fleet-secret-value"><?=htmlspecialchars($link)?></code>
		<button type="button" class="btn btn-sm btn-outline-secondary" data-fs-copy="#fleet-link"><i class="fa-regular fa-clone icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy link')?></button>
	</div>
	<div class="fs-fleet-secret">
		<span class="fs-fleet-secret-label"><?=gettext('Join key')?></span>
		<code id="fleet-key" class="fs-fleet-secret-value fs-fleet-key"><?=htmlspecialchars($key)?></code>
		<button type="button" class="btn btn-sm btn-outline-secondary" data-fs-copy="#fleet-key"><i class="fa-regular fa-clone icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy key')?></button>
	</div>
	<ol class="fs-fleet-steps">
		<li><?=sprintf(gettext('On the new firewall, open the console and choose option 17, or run %s.'), '<code>freesense-join join \'&lt;link&gt;\'</code>')?></li>
		<li><?=gettext('Paste the link, then type the join key when asked.')?></li>
		<li><?=gettext('The firewall shows a 6-digit code. Approve it below when the same code appears here.')?></li>
	</ol>
</section>
<?php endif; ?>

<?php if (!empty($pending)): ?>
<section class="fs-fleet-block" aria-labelledby="pending-title">
	<h2 id="pending-title" class="fs-fleet-section-title"><?=gettext('Waiting for approval')?> <span class="fs-count"><?=count($pending)?></span></h2>
	<p class="fs-fleet-lead"><?=gettext('Approve a firewall only when its screen shows the same code. A different code means someone else is using the invitation.')?></p>
	<ul class="fs-fleet-approvals">
<?php foreach ($pending as $e): $inv = json_decode($e['inventory'], true) ?: array(); ?>
		<li class="fs-fleet-approval">
			<div class="fs-fleet-code" aria-label="<?=gettext('Code')?> <?=htmlspecialchars(implode(' ', str_split($e['code'])))?>"><?=htmlspecialchars(substr($e['code'], 0, 3))?> <?=htmlspecialchars(substr($e['code'], 3))?></div>
			<div class="fs-fleet-approval-who">
				<strong><?=htmlspecialchars($e['label'])?></strong>
				<span class="fs-muted"><?=htmlspecialchars(trim(($inv['hostname'] ?? '') . ' ' . ($inv['version'] ?? '')))?></span>
				<span class="fs-muted"><?=sprintf(gettext('%1$s, from %2$s'), htmlspecialchars($role_name($e['role'])), '<span class="fs-mono">' . htmlspecialchars($e['source_ip']) . '</span>')?></span>
			</div>
			<form method="post" class="fs-fleet-approval-actions">
				<input type="hidden" name="enrollment" value="<?=htmlspecialchars($e['id'])?>"/>
				<button class="btn btn-primary" name="decide" value="approve"><i class="fa-solid fa-check icon-embed-btn" aria-hidden="true"></i><?=gettext('Approve')?></button>
				<button class="btn btn-outline-secondary" name="decide" value="reject"><?=gettext('Reject')?></button>
			</form>
		</li>
<?php endforeach; ?>
	</ul>
</section>
<?php endif; ?>

<section class="fs-fleet-block" aria-labelledby="add-title">
	<h2 id="add-title" class="fs-fleet-section-title"><?=gettext('Add a firewall')?></h2>
	<p class="fs-fleet-lead"><?=gettext('Creates a join link and key for one firewall. It must be able to reach this controller on the enrollment and tunnel ports.')?></p>
	<form method="post" class="fs-fleet-form">
		<div class="fs-fleet-field fs-fleet-field--wide"><label class="form-label" for="label"><?=gettext('Name')?></label>
			<input class="form-control" id="label" name="label" placeholder="<?=gettext('Copenhagen office')?>" required maxlength="80"/></div>
		<div class="fs-fleet-field"><label class="form-label" for="role"><?=gettext('Access')?></label>
			<select class="form-select" id="role" name="role" aria-describedby="role-help">
				<option value="monitor"><?=gettext('Monitor only')?></option>
				<option value="managed"><?=gettext('Managed')?></option>
			</select></div>
		<div class="fs-fleet-field"><label class="form-label" for="hours"><?=gettext('Valid for')?></label>
			<select class="form-select" id="hours" name="hours">
				<option value="1"><?=gettext('1 hour')?></option>
				<option value="24" selected><?=gettext('24 hours')?></option>
				<option value="168"><?=gettext('7 days')?></option>
			</select></div>
		<div class="fs-fleet-field fs-fleet-field--button">
			<button class="btn btn-primary" type="submit" name="invite" value="1"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Create invitation')?></button>
		</div>
	</form>
	<p id="role-help" class="fs-fleet-hint"><?=gettext('Monitor only: this controller reads status and backups. Managed: it may also change the configuration.')?></p>
</section>

<?php if (!empty($invites)): ?>
<section class="fs-fleet-block" aria-labelledby="open-title">
	<h2 id="open-title" class="fs-fleet-section-title"><?=gettext('Open invitations')?> <span class="fs-count"><?=count($invites)?></span></h2>
	<div class="table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Name')?></th><th><?=gettext('Access')?></th><th><?=gettext('Valid until')?></th><th><?=gettext('Wrong keys')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php foreach ($invites as $i): ?>
		<tr><td><?=htmlspecialchars($i['label'])?></td><td><?=htmlspecialchars($role_name($i['role']))?></td>
			<td><?=htmlspecialchars(date('Y-m-d H:i', (int)$i['expires']))?></td>
			<td><?=((int)$i['failures'] > 0) ? fs_badge('warn', (int)$i['failures'] . ' / ' . FLEET_INVITE_MAX_FAILURES) : '<span class="fs-muted">0</span>'?></td>
			<td class="text-end"><form method="post"><button class="btn btn-sm btn-outline-secondary" name="revoke" value="<?=htmlspecialchars($i['token_id'])?>"><?=gettext('Revoke')?></button></form></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
</section>
<?php endif; ?>

<?php else: ?>

<section class="fs-fleet-block" aria-labelledby="settings-title">
	<h2 id="settings-title" class="fs-fleet-section-title"><?=gettext('Controller')?></h2>
	<p class="fs-fleet-lead"><?=gettext('Firewalls connect to this controller. They may be behind NAT: they start the connection, so only this controller needs to be reachable.')?></p>
	<form method="post" class="fs-fleet-settings">
		<div class="form-check form-switch">
			<input class="form-check-input" type="checkbox" role="switch" id="enable" name="enable" <?=$s['enable'] ? 'checked' : ''?>/>
			<label class="form-check-label" for="enable"><?=gettext('Run this firewall as a FreeSense Fleet controller')?></label>
		</div>
		<div class="fs-fleet-field"><label class="form-label" for="public_host"><?=gettext('Address firewalls use to reach this controller')?></label>
			<input class="form-control" id="public_host" name="public_host" value="<?=htmlspecialchars($s['public_host'])?>" placeholder="fleet.example.net" aria-describedby="host-help"/>
			<div id="host-help" class="fs-fleet-hint"><?=gettext('A public IP address or DNS name, or the address of a port forward to this firewall.')?></div></div>
		<div class="fs-fleet-ports">
			<div class="fs-fleet-field"><label class="form-label" for="enroll_port"><?=gettext('Enrollment port (TCP)')?></label>
				<input class="form-control" id="enroll_port" name="enroll_port" inputmode="numeric" value="<?=(int)$s['enroll_port']?>"/></div>
			<div class="fs-fleet-field"><label class="form-label" for="wg_port"><?=gettext('Tunnel port (UDP)')?></label>
				<input class="form-control" id="wg_port" name="wg_port" inputmode="numeric" value="<?=(int)$s['wg_port']?>"/></div>
		</div>
<?php if ($ready && !fleet_data_on_zfs()): ?>
		<div class="fs-fleet-note"><?=fs_badge('warn', gettext('No rollback'))?> <?=gettext('This controller runs on UFS. Fleet works, but a failed update of this controller cannot roll back automatically. ZFS is recommended for the controller.')?></div>
<?php endif; ?>
		<div><button class="btn btn-primary" type="submit" name="save_settings" value="1"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button></div>
	</form>
</section>

<?php endif; ?>
<?php include('foot.inc');
