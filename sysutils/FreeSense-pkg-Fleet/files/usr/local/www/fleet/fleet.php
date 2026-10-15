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

if (isset($_POST['save_section']) && array_key_exists((string)$_POST['save_section'], FLEET_SETTINGS_SECTIONS) && ($_POST['save_section'] !== 'controller')) {
	/* A settings section other than Controller: only its values change, everything else is kept. */
	$tab = 'settings';
	$section = (string)$_POST['save_section'];
	$stored = (array)config_get_path('installedpackages/fleet/config/0', array());
	foreach (FLEET_TUNABLES as $key => list($sec, $unit, $default, $min, $max, $label)) {
		if ($sec !== $section) {
			continue;
		}
		if ($unit === 'bool') {
			$stored[$key] = !empty($_POST[$key]) ? 'on' : 'off';
			continue;
		}
		$v = trim((string)($_POST[$key] ?? ''));
		if (fleet_tunables_from(array($key => $v))[$key] !== (int)$v || !ctype_digit($v)) {
			$input_errors[] = ($unit === 'choice') ? sprintf(gettext('%s: choose one of the values offered.'), gettext($label))
			    : sprintf(gettext('%1$s: a whole number from %2$d to %3$d.'), gettext($label), $min, $max);
			continue;
		}
		$stored[$key] = $v;
	}
	if (empty($input_errors)) {
		config_set_path('installedpackages/fleet/config/0', $stored);
		write_config(sprintf(gettext('FreeSense Fleet settings saved (%s).'), gettext(FLEET_SETTINGS_SECTIONS[$section])));
		$s = fleet_ctl_settings();
		$savemsg = gettext('Saved.');
	}
} elseif ($_POST['save_settings'] ?? false) {
	$tab = 'settings';
	$host = trim((string)($_POST['public_host'] ?? ''));
	/* Controller: kept with every other stored value (Monitoring, Backups...). */
	$post = array_merge((array)config_get_path('installedpackages/fleet/config/0', array()), array('enable' => !empty($_POST['enable']) ? 'on' : '',
	    'public_host' => $host, 'enroll_port' => (string)($_POST['enroll_port'] ?? ''), 'wg_port' => (string)($_POST['wg_port'] ?? '')));
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
		    3600 * max(1, min(720, (int)($_POST['hours'] ?? fleet_opt('invite_hours')))), $who, fleet_hostport($s['public_host'], $s['enroll_port']), time());
	} catch (InvalidArgumentException $e) {
		$input_errors[] = $e->getMessage();
	}
} elseif (isset($_POST['decide'], $_POST['enrollment']) && $s['enable']) {
	if (fleet_enroll_decide((string)$_POST['enrollment'], $_POST['decide'] === 'approve', $who, time())) {
		$savemsg = ($_POST['decide'] === 'approve') ?
		    gettext('Approved. The firewall finishes joining by itself and appears on the dashboard.') :
		    gettext('Rejected. The firewall was told to stop.');
	}
} elseif (($_POST['backup_all'] ?? false) && $s['enable']) {
	/* In the background: many boxes take a while, and the page must not wait. */
	$group = (int)($_POST['group'] ?? 0);
	mwexec_bg('/usr/local/bin/php /usr/local/sbin/freesense-fleet-backup all ' . escapeshellarg($who) . ' ' . $group);
	/* The dashboard shows its progress; back on the same group. */
	header('Location: /fleet/fleet_dashboard.php' . ($group > 0 ? '?group=' . $group : ''));
	exit;
} elseif (isset($_POST['group_save']) && $s['enable']) {
	$edit_id = ((int)($_POST['group_id'] ?? 0) > 0) ? (int)$_POST['group_id'] : null;
	try {
		$gid = fleet_group_save($edit_id, (string)($_POST['group_name'] ?? ''), (string)($_POST['group_description'] ?? ''),
		    (string)($_POST['group_color'] ?? ''), $who);
		$win = (int)($_POST['group_window'] ?? 0);
		fleet_group_set_window($gid, (fleet_window_get($win) !== null) ? $win : null, $who);
		$savemsg = ($edit_id === null) ? gettext('Group created. Add firewalls to it on each firewall\'s Overview.') : gettext('Group saved.');
	} catch (InvalidArgumentException $e) {
		$input_errors[] = $e->getMessage();
		$_GET['edit'] = $edit_id;
	}
} elseif (isset($_POST['group_delete']) && $s['enable']) {
	try {
		fleet_group_delete((int)$_POST['group_delete'], $who);
		$savemsg = gettext('Group deleted. Its firewalls were not changed.');
	} catch (RuntimeException $e) {
		$input_errors[] = $e->getMessage();
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
	array(gettext('Activity'), false, '/fleet/fleet_activity.php'),
	array(gettext('Updates'), false, '/fleet/fleet_updates.php'),
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

<?php if ($tab === 'firewalls'):
	$fw_view = fs_view_param(array('invite', 'groups'), (isset($_POST['group_save']) || isset($_POST['group_delete'])) ? 'groups' : 'invite');
	fs_view_switch(array('invite' => gettext('Add and approve'), 'groups' => gettext('Groups')), $fw_view);
?>
<?php if ($fw_view === 'groups'):
	$groups = fleet_groups_all();
	$editing = isset($_GET['edit']) ? fleet_group_get((int)$_GET['edit']) : null;
	/* After an error the form keeps what was typed; after a save it is empty again. */
	$typed = (isset($_POST['group_save']) && !empty($input_errors)) ? $_POST : array();
	$form = array('id' => $editing['id'] ?? 0, 'name' => (string)($typed['group_name'] ?? ($editing['name'] ?? '')),
	    'description' => (string)($typed['group_description'] ?? ($editing['description'] ?? '')),
	    'color' => fleet_group_color((string)($typed['group_color'] ?? ($editing['color'] ?? (string)((count($groups) % 8) + 1)))));
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Groups')?> <span class="fs-count"><?=count($groups)?></span></h2></div>
<?php if (empty($groups)): ?>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=gettext('No groups yet. Group firewalls by place, customer or role, for example Denmark, Retail or Canary. Policies, backups and updates can then target a group.')?></p></div>
<?php else: ?>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Name')?></th><th><?=gettext('Description')?></th><th><?=gettext('Window')?></th><th><?=gettext('Firewalls')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php foreach ($groups as $grp): ?>
		<tr><td><span class="fs-fleet-group" style="--fs-fleet-group: var(--fs-series-<?=htmlspecialchars(fleet_group_color((string)$grp['color']))?>)"><?=htmlspecialchars($grp['name'])?></span></td>
			<td><?=($grp['description'] !== '') ? htmlspecialchars($grp['description']) : '<span class="fs-muted">-</span>'?></td>
			<td><?php $gw = fleet_window_get((int)($grp['window_id'] ?? 0)); ?><?=($gw === null) ? '<span class="fs-muted">-</span>' : htmlspecialchars($gw['name'])?></td>
			<td><a class="fs-fleet-inline-link" href="/fleet/fleet_dashboard.php?group=<?=(int)$grp['id']?>"><?=(int)$grp['members']?></a></td>
			<td class="text-end text-nowrap">
				<a class="btn btn-sm btn-link" href="?view=groups&amp;edit=<?=(int)$grp['id']?>"><?=gettext('Change')?></a>
				<form method="post" action="?view=groups" class="d-inline"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="group_delete" value="<?=(int)$grp['id']?>" title="<?=gettext('Its firewalls stay in the fleet')?>"><?=gettext('Delete')?></button></form>
			</td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php endif; ?>
	<div class="panel-footer small fs-muted"><?=gettext('A firewall can be in several groups. Deleting a group never changes its firewalls; a group that a policy, backup set or update ring uses cannot be deleted.')?></div>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=($editing !== null) ? sprintf(gettext('Change %s'), htmlspecialchars($editing['name'])) : gettext('Add a group')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<form method="post" action="?view=groups" class="fs-fleet-form">
			<input type="hidden" name="group_id" value="<?=(int)$form['id']?>"/>
			<div class="fs-fleet-field"><label class="form-label" for="group_name"><?=gettext('Name')?></label>
				<input class="form-control" id="group_name" name="group_name" maxlength="40" required value="<?=htmlspecialchars($form['name'])?>" placeholder="<?=gettext('Retail')?>"/></div>
			<div class="fs-fleet-field fs-fleet-field--wide"><label class="form-label" for="group_description"><?=gettext('Description')?></label>
				<input class="form-control" id="group_description" name="group_description" maxlength="200" value="<?=htmlspecialchars($form['description'])?>" placeholder="<?=gettext('Shops and pop-up stores')?>"/></div>
<?php $all_windows = fleet_windows_all(); $cur_window = (int)($editing['window_id'] ?? 0); ?>
			<div class="fs-fleet-field"><label class="form-label" for="group_window"><?=gettext('Maintenance window')?></label>
				<select class="form-select" id="group_window" name="group_window">
					<option value="0"><?=gettext('None (any time)')?></option>
<?php foreach ($all_windows as $w): ?>
					<option value="<?=(int)$w['id']?>"<?=($cur_window === $w['id']) ? ' selected' : ''?>><?=htmlspecialchars($w['name'] . ' (' . fleet_window_text($w) . ')')?></option>
<?php endforeach; ?>
				</select>
				<div class="fs-fleet-hint"><a href="/fleet/fleet_updates.php?view=windows"><?=gettext('Manage windows')?></a></div></div>
			<fieldset class="fs-fleet-field">
				<legend class="form-label"><?=gettext('Colour')?></legend>
				<div class="fs-fleet-swatches">
<?php foreach (FLEET_GROUP_COLORS as $c): ?>
					<label class="fs-fleet-swatch" style="--fs-fleet-group: var(--fs-series-<?=$c?>)"><input type="radio" name="group_color" value="<?=$c?>"<?=($form['color'] === $c) ? ' checked' : ''?>/><span class="visually-hidden"><?=sprintf(gettext('Colour %s'), $c)?></span></label>
<?php endforeach; ?>
				</div>
			</fieldset>
			<div class="fs-fleet-field fs-fleet-field--button">
				<button class="btn btn-primary" type="submit" name="group_save" value="1"><i class="fa-solid <?=($editing !== null) ? 'fa-floppy-disk' : 'fa-plus'?> icon-embed-btn" aria-hidden="true"></i><?=($editing !== null) ? gettext('Save') : gettext('Add group')?></button>
<?php if ($editing !== null): ?>
				<a class="btn btn-outline-secondary" href="?view=groups"><?=gettext('Cancel')?></a>
<?php endif; ?>
			</div>
		</form>
	</div>
</div>
<?php else: ?>

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
<?php
	$ttl_choices = array(1 => gettext('1 hour'), 24 => gettext('24 hours'), 168 => gettext('7 days'), 720 => gettext('30 days'));
	$ttl_default = fleet_opt('invite_hours');
	if (!isset($ttl_choices[$ttl_default])) {
		$ttl_choices[$ttl_default] = sprintf(gettext('%d hours'), $ttl_default);
		ksort($ttl_choices);
	}
	foreach ($ttl_choices as $h => $text):
?>
				<option value="<?=(int)$h?>"<?=($h === $ttl_default) ? ' selected' : ''?>><?=htmlspecialchars($text)?></option>
<?php endforeach; ?>
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
			<td><?=((int)$i['failures'] > 0) ? fs_badge('warn', (int)$i['failures'] . ' / ' . fleet_opt('invite_failures')) : '<span class="fs-muted">0</span>'?></td>
			<td class="text-end"><form method="post"><button class="btn btn-sm btn-outline-secondary" name="revoke" value="<?=htmlspecialchars($i['token_id'])?>"><?=gettext('Revoke')?></button></form></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
</section>
<?php endif; ?>

<?php endif; ?>
<?php else:
	$set_view = fs_view_param(array_keys(FLEET_SETTINGS_SECTIONS), (string)($_POST['save_section'] ?? (isset($_POST['save_settings']) ? 'controller' : 'controller')));
	$set_labels = array_map('gettext', FLEET_SETTINGS_SECTIONS);
	fs_view_switch($set_labels, $set_view);
	$set_leads = array(
		'controller' => gettext('Firewalls connect to this controller. They may be behind NAT: they start the connection, so only this controller needs to be reachable.'),
		'monitoring' => gettext('How often the controller asks each firewall for its status, and when a silent firewall counts as degraded or offline.'),
		'actions' => gettext('Reboots, backups and restores started from Fleet: how long results stay visible and when you are told.'),
		'backups' => gettext('Central backups of each firewall\'s configuration, taken every night and when it changes.'),
		'advanced' => gettext('Values you rarely need to change. The defaults suit most fleets.'),
	);
?>
<?php if ($set_view !== 'controller'): ?>
<form method="post" action="?tab=settings&amp;view=<?=htmlspecialchars($set_view)?>">
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars($set_labels[$set_view])?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=htmlspecialchars($set_leads[$set_view])?></p>
		<div class="fs-fleet-settings">
<?php foreach (FLEET_TUNABLES as $key => list($sec, $unit, $default, $min, $max, $label, $help)):
	if ($sec !== $set_view) {
		continue;
	}
	$units = array('min' => gettext('minutes'), 's' => gettext('seconds'), 'h' => gettext('hours'), 'count' => '');
	$value = $s[$key];
?>
<?php if ($unit === 'bool'): ?>
			<div class="form-check form-switch">
				<input class="form-check-input" type="checkbox" role="switch" id="<?=$key?>" name="<?=$key?>" aria-describedby="<?=$key?>-help"<?=$value ? ' checked' : ''?>/>
				<label class="form-check-label" for="<?=$key?>"><?=htmlspecialchars(gettext($label))?></label>
				<div id="<?=$key?>-help" class="fs-fleet-hint"><?=htmlspecialchars(gettext($help))?></div>
			</div>
<?php elseif ($unit === 'choice'): ?>
			<div class="fs-fleet-field"><label class="form-label" for="<?=$key?>"><?=htmlspecialchars(gettext($label))?></label>
				<select class="form-select fs-fleet-narrow" id="<?=$key?>" name="<?=$key?>" aria-describedby="<?=$key?>-help">
<?php foreach ($min as $opt): ?>
					<option value="<?=(int)$opt?>"<?=($value === $opt) ? ' selected' : ''?>><?=($key === 'poll_interval') ? sprintf(gettext('%d seconds'), $opt) : (int)$opt?><?=($opt === $default) ? ' ' . gettext('(default)') : ''?></option>
<?php endforeach; ?>
				</select>
				<div id="<?=$key?>-help" class="fs-fleet-hint"><?=htmlspecialchars(gettext($help))?></div></div>
<?php else: ?>
			<div class="fs-fleet-field"><label class="form-label" for="<?=$key?>"><?=htmlspecialchars(gettext($label))?></label>
				<div class="input-group fs-fleet-narrow">
					<input class="form-control" type="number" id="<?=$key?>" name="<?=$key?>" min="<?=(int)$min?>" max="<?=(int)$max?>" step="1" value="<?=(int)$value?>" aria-describedby="<?=$key?>-help" required/>
<?php if ($units[$unit] !== ''): ?>
					<span class="input-group-text"><?=htmlspecialchars($units[$unit])?></span>
<?php endif; ?>
				</div>
				<div id="<?=$key?>-help" class="fs-fleet-hint"><?=htmlspecialchars(gettext($help))?> <?=sprintf(gettext('%1$d to %2$d, default %3$d.'), $min, $max, $default)?></div></div>
<?php endif; ?>
<?php endforeach; ?>
		</div>
	</div>
	<div class="panel-footer">
		<button class="btn btn-primary" type="submit" name="save_section" value="<?=htmlspecialchars($set_view)?>"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
	</div>
</div>
</form>
<?php else: ?>
<form method="post" action="?tab=settings&amp;view=controller">
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Controller')?></h2></div>
	<div class="panel-body fs-fleet-pad">
	<p class="fs-fleet-lead"><?=htmlspecialchars($set_leads['controller'])?></p>
	<div class="fs-fleet-settings">
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
	</div>
	</div>
	<div class="panel-footer">
		<button class="btn btn-primary" type="submit" name="save_settings" value="1"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
	</div>
</div>
</form>
<?php endif; ?>

<?php endif; ?>
<?php include('foot.inc');
