<?php
/*
 * fleet_users.php
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
 * Fleet users: people (Users), what they may do and where (Groups), and
 * getting it onto the firewalls (Sync: a preview per firewall, then an
 * operation). Add and change in modals. The logic is fleet_users.inc.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Users'));
$who = (string)($_SESSION['Username'] ?? 'admin');
$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$manage = isAllowedPage('fleet/fleet.php');
$input_errors = array();
$savemsg = null;
$view = fs_view_param(array('users', 'groups', 'sync'), 'users');
$reopen_user = null;
$reopen_group = null;

if ($ready && $manage && ($_SERVER['REQUEST_METHOD'] === 'POST')) {
	try {
		if (isset($_POST['user_save'])) {
			$view = 'users';
			fleet_fuser_save(((int)($_POST['id'] ?? 0) > 0) ? (int)$_POST['id'] : null, $_POST, $who);
			$savemsg = gettext('User saved. Sync to put the change on the firewalls.');
			$ug = fleet_ugroups_all();
			$gp = array_map(function ($gid) use ($ug) { return (array)($ug[$gid]['privs'] ?? array()); }, array_map('intval', (array)($_POST['groups'] ?? array())));
			if (fleet_users_keys_without_shell((string)($_POST['ssh_keys'] ?? ''), $gp)) {
				$savemsg .= ' ' . gettext('Note: none of the user\'s groups has the privilege "User - System: Shell account access", so SSH with these keys is refused.');
			}
		} elseif (isset($_POST['user_delete'])) {
			$view = 'users';
			fleet_fuser_delete((int)$_POST['user_delete'], $who);
			$savemsg = gettext('User deleted. The next sync removes the account from the firewalls.');
		} elseif (isset($_POST['group_save'])) {
			$view = 'groups';
			fleet_ugroup_save(((int)($_POST['id'] ?? 0) > 0) ? (int)$_POST['id'] : null, $_POST, $who);
			$savemsg = gettext('Group saved. Sync to put the change on the firewalls.');
		} elseif (isset($_POST['group_delete'])) {
			$view = 'groups';
			fleet_ugroup_delete((int)$_POST['group_delete'], $who);
			$savemsg = gettext('Group deleted. The next sync removes it from the firewalls.');
		} elseif (isset($_POST['users_lock'])) {
			$view = 'sync';
			fleet_users_lock_set(!empty($_POST['lock']), $who);
			$savemsg = fleet_users_locked() ? gettext('Fleet users are locked: the firewalls refuse local edits to them.') : gettext('Fleet users are no longer locked.');
		} elseif (isset($_POST['drift_adopt'])) {
			$view = 'sync';
			$n = fleet_users_drift_adopt((string)$_POST['drift_adopt'], $who);
			$savemsg = sprintf(ngettext('%d user taken over as changed on the firewall. Sync to give the other firewalls the same.', '%d users taken over as changed on the firewall. Sync to give the other firewalls the same.', $n), $n);
		} elseif (isset($_POST['drift_ignore'])) {
			$view = 'sync';
			fleet_users_drift_ignore((string)$_POST['drift_ignore'], $who);
			$savemsg = gettext('Ignored until the firewall changes again.');
		} elseif (isset($_POST['sync'])) {
			$op = fleet_users_launch($who, isset($_POST['node']) ? array((string)$_POST['node']) : null);
			header('Location: /fleet/fleet_activity.php?op=' . (int)$op);
			exit;
		}
	} catch (InvalidArgumentException | RuntimeException $e) {
		$input_errors[] = $e->getMessage();
		/* Typed passwords are never sent back to the page. */
		$typed = array_diff_key($_POST, array_flip(array('password', 'password_again', '__csrf_magic')));
		if (isset($_POST['user_save'])) {
			$reopen_user = $typed;
		} elseif (isset($_POST['group_save'])) {
			$reopen_group = $typed;
		}
	}
}
if ($ready && $manage && ($view === 'users')) {
	fs_page_action(gettext('Add user'), '#', 'fa-user-plus', 'primary', array('data-fs-modal' => '#user-modal', 'data-fs-modal-title' => gettext('Add a user'),
	    'data-fs-fill' => json_encode(array('id' => ''))));
}
if ($ready && $manage && ($view === 'groups')) {
	fs_page_action(gettext('Add group'), '#', 'fa-plus', 'primary', array('data-fs-modal' => '#group-modal', 'data-fs-modal-title' => gettext('Add a user group'),
	    'data-fs-fill' => json_encode(array('id' => '', 'targets[]' => array('all')))));
}

include('head.inc');
if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if ($savemsg !== null) {
	print_info_box(htmlspecialchars($savemsg), 'success');
}
?>
<link rel="stylesheet" href="/fleet/assets/fleet.css?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet.css')?>">
<?php
if ($manage) {
	$tab_array = array(
		array(gettext('Dashboard'), false, '/fleet/fleet_dashboard.php'),
		array(gettext('Activity'), false, '/fleet/fleet_activity.php'),
		array(gettext('Updates'), false, '/fleet/fleet_updates.php'),
		array(gettext('Schedules'), false, '/fleet/fleet_schedules.php'),
		array(gettext('Backups'), false, '/fleet/fleet_backups.php'),
		array(gettext('Policies'), false, '/fleet/fleet_policies.php'),
		array(gettext('Templates'), false, '/fleet/fleet_templates.php'),
		array(gettext('Users'), true, '/fleet/fleet_users.php'),
		array(gettext('Firewalls'), false, '/fleet/fleet.php'),
		array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
	);
	display_top_tabs($tab_array);
}
if (!$ready): ?>
<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller')?></strong></div>
<?php include('foot.inc'); exit; endif;

$users = fleet_fusers_all();
$ugroups = fleet_ugroups_all();
$names = fleet_target_names();
$labels = fleet_db()->query('SELECT node_id, label FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll(PDO::FETCH_KEY_PAIR);
$fgroups = fleet_groups_all();
$catalog = fleet_users_catalog();
$vcats = fleet_users_version_catalogs();
fs_view_switch(array('users' => gettext('Users'), 'groups' => gettext('Groups'), 'sync' => gettext('Sync')), $view);
$initials = function (string $name, string $full) {
	$src = ($full !== '') ? $full : $name;
	$parts = preg_split('/[\s._-]+/', $src);
	return strtoupper(mb_substr($parts[0], 0, 1) . (isset($parts[1]) ? mb_substr($parts[1], 0, 1) : mb_substr($parts[0], 1, 1)));
};
$targets_select = function (string $id, array $chosen = array()) use ($fgroups, $labels) {
	ob_start(); ?>
	<select class="form-select" id="<?=$id?>" name="targets[]" multiple size="8" data-fs-multiselect data-fs-exclusive="all"
	    data-fs-text-search="<?=gettext('Search groups and firewalls…')?>" data-fs-text-none="<?=gettext('Choose firewalls…')?>" data-fs-text-more="<?=gettext('+%d more')?>">
		<option value="all"><?=gettext('All firewalls')?></option>
<?php if (!empty($fgroups)): ?>
		<optgroup label="<?=gettext('Firewall groups')?>">
<?php foreach ($fgroups as $grp): ?>
			<option value="g:<?=(int)$grp['id']?>"><?=htmlspecialchars($grp['name'])?></option>
<?php endforeach; ?>
		</optgroup>
<?php endif; ?>
		<optgroup label="<?=gettext('Firewalls')?>">
<?php foreach ($labels as $node => $label): ?>
			<option value="n:<?=htmlspecialchars($node)?>"><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
		</optgroup>
	</select>
<?php	return ob_get_clean();
};
?>

<?php if ($view === 'users'):
	$q = trim((string)($_GET['q'] ?? ''));
	$fg = (int)($_GET['group'] ?? 0);
	$shown = array_filter($users, function ($u) use ($q, $fg, $ugroups) {
		$gn = implode(' ', array_map(function ($ugr) use ($ugroups) { return $ugroups[$ugr]['name'] ?? ''; }, $u['groups']));
		return (($q === '') || (stripos($u['name'] . ' ' . $u['fullname'] . ' ' . $gn, $q) !== false)) && (($fg === 0) || in_array($fg, $u['groups'], true));
	});
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Users')?> <span class="fs-count"><?=count($users)?></span></h2></div>
<?php if (empty($users)): ?>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=gettext('Users you add here get an account on the firewalls their groups are for, with the same password and SSH keys everywhere. Local accounts on the firewalls (admin and any made there) are never changed.')?></p>
<?php if (empty($ugroups)): ?>
		<p class="fs-fleet-hint"><?=gettext('Start with a group: it says what its members may do and on which firewalls.')?> <a href="?view=groups"><?=gettext('Groups')?></a></p>
<?php endif; ?>
	</div>
<?php else: ?>
	<div class="panel-body fs-fleet-pad">
		<form method="get" class="fs-fleet-filterbar" role="search" data-fleet-filters><script src="/fleet/assets/fleet-list.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-list.js')?>" defer></script>
			<input type="hidden" name="view" value="users"/>
			<input class="form-control form-control-sm" type="search" name="q" value="<?=htmlspecialchars($q)?>" placeholder="<?=gettext('Search name or group')?>" aria-label="<?=gettext('Search users')?>"/>
			<select class="form-select form-select-sm" name="group" aria-label="<?=gettext('Group')?>">
				<option value=""><?=gettext('Any group')?></option>
<?php foreach ($ugroups as $gid => $ugr): ?>
				<option value="<?=$gid?>"<?=($fg === $gid) ? ' selected' : ''?>><?=htmlspecialchars($ugr['name'])?></option>
<?php endforeach; ?>
			</select>
			<button class="btn btn-sm btn-outline-secondary" type="submit"><?=gettext('Filter')?></button>
<?php if (($q !== '') || ($fg > 0)): ?>
			<a class="btn btn-sm btn-link" href="?view=users"><?=gettext('Clear')?></a>
			<span class="fs-muted small ms-auto"><?=sprintf(gettext('%1$d of %2$d'), count($shown), count($users))?></span>
<?php endif; ?>
		</form>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('User')?></th><th><?=gettext('Groups')?></th><th><?=gettext('Sign-in')?></th><th><?=gettext('Firewalls')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($shown)): ?>
		<tr><td colspan="5" class="fs-muted"><?=gettext('No user matches.')?> <a href="?view=users"><?=gettext('Clear the filters')?></a></td></tr>
<?php endif; ?>
<?php $for = fleet_users_for_boxes($ugroups); foreach ($shown as $uid => $u):
	$reach = 0;
	foreach ($for as $node => $gids) {
		$reach += empty(array_intersect($gids, $u['groups'])) ? 0 : 1;
	}
	$nkeys = count(array_filter(explode("\n", $u['ssh_keys']), 'strlen')); ?>
		<tr<?=$u['disabled'] ? ' class="fs-muted"' : ''?>><td><div class="fs-fleet-person"><span class="fs-fleet-avatar" aria-hidden="true"><?=htmlspecialchars($initials($u['name'], $u['fullname']))?></span>
				<div><strong><?=htmlspecialchars($u['name'])?></strong><?=($u['fullname'] !== '') ? '<div class="small fs-muted">' . htmlspecialchars($u['fullname']) . '</div>' : ''?></div></div></td>
			<td><?php foreach ($u['groups'] as $ugr): ?><span class="fs-fleet-chip"><?=htmlspecialchars($ugroups[$ugr]['name'] ?? '?')?></span> <?php endforeach; ?>
				<?=empty($u['groups']) ? '<span class="fs-muted small">' . gettext('None: no firewall access') . '</span>' : ''?></td>
			<td class="small"><?=($nkeys > 0) ? '<i class="fa-solid fa-key" aria-hidden="true"></i> ' . sprintf(ngettext('%d SSH key', '%d SSH keys', $nkeys), $nkeys) : ''?>
				<?=$u['disabled'] ? fs_badge('neutral', gettext('Disabled')) : ''?>
				<?=($u['expires'] !== '') ? '<div class="fs-muted">' . htmlspecialchars(sprintf(gettext('Ends %s'), $u['expires'])) . '</div>' : ''?></td>
			<td><?=$reach?></td>
			<td class="text-end text-nowrap">
<?php if ($manage): ?>
				<button type="button" class="btn btn-sm btn-link" data-fs-modal="#user-modal" data-fs-modal-title="<?=htmlspecialchars(sprintf(gettext('Change %s'), $u['name']))?>"
				    data-fs-fill="<?=htmlspecialchars(json_encode(array('id' => (string)$uid, 'name' => $u['name'], 'fullname' => $u['fullname'], 'groups[]' => array_map('strval', $u['groups']),
				    'ssh_keys' => $u['ssh_keys'], 'expires' => $u['expires'], 'disabled' => (bool)$u['disabled'], 'password' => '', 'password_again' => '')))?>"><?=gettext('Change')?></button>
				<form method="post" class="d-inline"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="user_delete" value="<?=$uid?>"><?=gettext('Delete')?></button></form>
<?php endif; ?>
			</td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php endif; ?>
</div>

<?php elseif ($view === 'groups'):
	$q = trim((string)($_GET['q'] ?? ''));
	$count_of = array();
	foreach ($users as $u) {
		foreach ($u['groups'] as $ugr) {
			$count_of[$ugr] = ($count_of[$ugr] ?? 0) + 1;
		}
	}
	$shown = array_filter($ugroups, function ($ugr) use ($q, $names) {
		return ($q === '') || (stripos($ugr['name'] . ' ' . $ugr['description'] . ' ' . fleet_targets_text($ugr['targets'], $names) . ' ' . implode(' ', $ugr['privs']), $q) !== false);
	});
?>
<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-users" aria-hidden="true"></i></span>
		<div><h2><?=gettext('User groups')?></h2><p><?=gettext('A group holds privileges (which pages and actions its members get) and says which firewalls it is for. A user reaches a firewall through a group that is for it.')?></p></div></header>
<?php if (!empty($ugroups)): ?>
	<form method="get" class="fs-fleet-filterbar mb-3" role="search">
		<input type="hidden" name="view" value="groups"/>
		<input class="form-control form-control-sm" type="search" name="q" value="<?=htmlspecialchars($q)?>" placeholder="<?=gettext('Search group, firewall or privilege')?>" aria-label="<?=gettext('Search groups')?>"/>
		<button class="btn btn-sm btn-outline-secondary" type="submit"><?=gettext('Search')?></button>
<?php if ($q !== ''): ?>
		<a class="btn btn-sm btn-link" href="?view=groups"><?=gettext('Clear')?></a>
<?php endif; ?>
	</form>
<?php endif; ?>
	<div class="fs-fleet-rule-grid">
<?php if (empty($ugroups)): ?>
		<p class="fs-fleet-hint"><?=gettext('No user groups yet. For example "shop-support" with the status pages, for the Retail firewalls; or "network-team" with everything, for all firewalls.')?></p>
<?php elseif (empty($shown)): ?>
		<p class="fs-fleet-hint"><?=gettext('No group matches.')?> <a href="?view=groups"><?=gettext('Clear the search')?></a></p>
<?php endif; ?>
<?php foreach ($shown as $gid => $ugr):
	$full = in_array('page-all', $ugr['privs'], true);
	$missing = array();
	foreach ($vcats as $ver => $known) {
		$miss = array_diff($ugr['privs'], $known);
		if (!empty($miss)) {
			$missing[$ver] = count($miss);
		}
	} ?>
		<article class="fs-fleet-rcard is-on">
			<div class="fs-fleet-rcard-head">
				<span class="fs-fleet-rcard-icon <?=$full ? 'fs-fleet-sev-high' : 'fs-fleet-sev-low'?>"><i class="fa-solid <?=$full ? 'fa-user-shield' : 'fa-users'?>" aria-hidden="true"></i></span>
				<div class="fs-fleet-rcard-title"><strong><?=htmlspecialchars($ugr['name'])?></strong>
					<span class="fs-muted small"><?=sprintf(ngettext('%d member', '%d members', $count_of[$gid] ?? 0), $count_of[$gid] ?? 0)?> &middot; <?=$full ? gettext('Full administrator') : sprintf(ngettext('%d privilege', '%d privileges', count($ugr['privs'])), count($ugr['privs']))?></span></div>
<?php if ($manage): ?>
				<button type="button" class="btn btn-sm btn-link" data-fs-modal="#group-modal" data-fs-modal-title="<?=htmlspecialchars(sprintf(gettext('Change %s'), $ugr['name']))?>"
				    data-fs-fill="<?=htmlspecialchars(json_encode(array('id' => (string)$gid, 'name' => $ugr['name'], 'description' => $ugr['description'], 'targets[]' => $ugr['targets'], 'privs[]' => $ugr['privs'])))?>"><?=gettext('Change')?></button>
<?php endif; ?>
			</div>
			<?=($ugr['description'] !== '') ? '<p class="fs-fleet-rcard-help">' . htmlspecialchars($ugr['description']) . '</p>' : ''?>
			<div class="small"><i class="fa-solid fa-shield-halved fs-muted" aria-hidden="true"></i> <?=htmlspecialchars(sprintf(gettext('For %s'), fleet_targets_text($ugr['targets'], $names)))?></div>
			<div class="fs-fleet-priv-list"><?php foreach (array_slice($ugr['privs'], 0, 6) as $p): ?><span class="fs-fleet-chip" title="<?=htmlspecialchars($p)?>"><?=htmlspecialchars($catalog[$p] ?? $p)?></span> <?php endforeach; ?>
				<?=(count($ugr['privs']) > 6) ? '<span class="fs-muted small">' . sprintf(gettext('+%d more'), count($ugr['privs']) - 6) . '</span>' : ''?></div>
<?php foreach ($missing as $ver => $n): ?>
			<div class="small fs-fleet-problem"><?=htmlspecialchars(sprintf(ngettext('%1$d privilege is not on %2$s firewalls (left out there).', '%1$d privileges are not on %2$s firewalls (left out there).', $n), $n, $ver))?></div>
<?php endforeach; ?>
<?php if ($manage): ?>
			<form method="post" class="text-end"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="group_delete" value="<?=$gid?>"><?=gettext('Delete')?></button></form>
<?php endif; ?>
		</article>
<?php endforeach; ?>
	</div>
</section>

<?php else: /* sync */
	$for = fleet_users_for_boxes($ugroups);
	$states = fleet_users_states();
	$nodes = array_values(array_unique(array_merge(array_keys($for), array_keys($states))));
	$live = isset($_GET['check']) && $manage;
?>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Sync to the firewalls')?></h2>
<?php if ($manage && !$live && !empty($nodes)): ?>
		<a class="btn btn-sm btn-link" href="?view=sync&amp;check=1"><?=gettext('Check what would change')?></a>
<?php endif; ?></div>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-lead"><?=gettext('Each firewall gets the users of the groups that are for it. Privileges a firewall\'s version does not have are left out there and listed; a name the firewall already uses for its own account is skipped. A firewall that updates is synced again by itself.')?></p>
<?php if ($manage): ?>
		<form method="post" class="fs-fleet-lockrow">
			<div class="form-check form-switch m-0"><input class="form-check-input" type="checkbox" role="switch" id="ulock" name="lock" value="1"<?=fleet_users_locked() ? ' checked' : ''?> onchange="this.form.requestSubmit()"/>
				<label class="form-check-label" for="ulock"><i class="fa-solid fa-lock" aria-hidden="true"></i> <strong><?=gettext('Lock Fleet users on the firewalls')?></strong></label></div>
			<input type="hidden" name="users_lock" value="1"/>
			<noscript><button class="btn btn-sm btn-outline-secondary"><?=gettext('Save')?></button></noscript>
			<span class="fs-muted small"><?=gettext('The firewalls refuse local edits to accounts Fleet manages (also while the controller is offline). Local accounts stay free; a console administrator can suspend it with break-glass.')?></span>
		</form>
<?php endif; ?>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Firewall')?></th><th><?=gettext('Gets')?></th><th><?=$live ? gettext('Would change') : gettext('Last sync')?></th><th><?=gettext('Drift')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($nodes)): ?>
		<tr><td colspan="5" class="fs-muted"><?=gettext('No user group is for any firewall yet.')?></td></tr>
<?php endif; ?>
<?php foreach ($nodes as $node): $box = fleet_box_get($node); if ($box === null) { continue; } $d = fleet_users_desired_for($node); $st = $states[$node] ?? null; ?>
		<tr><td><a href="/fleet/fleet_box.php?id=<?=urlencode($node)?>"><?=htmlspecialchars($labels[$node] ?? $node)?></a> <?=($box['state'] !== 'online') ? fs_badge('neutral', ucfirst($box['state'])) : ''?></td>
			<td class="small"><?=sprintf(ngettext('%d user', '%d users', count($d['users'])), count($d['users']))?>, <?=htmlspecialchars(implode(', ', array_column($d['groups'], 'name')) ?: gettext('no groups'))?></td>
			<td class="small">
<?php if ($live && ($box['state'] === 'online')):
	try {
		$plan = fleet_users_preview_box($box);
		$c = fleet_users_plan_counts($plan);
		if ($c['create'] + $c['update'] + $c['delete'] === 0) {
			echo fs_badge('pass', gettext('In sync'));
		} else {
			echo ($c['create'] ? fs_badge('pass', sprintf(gettext('Add %d'), $c['create'])) . ' ' : '') . ($c['update'] ? fs_badge('info', sprintf(gettext('Change %d'), $c['update'])) . ' ' : '') .
			    ($c['delete'] ? fs_badge('warn', sprintf(gettext('Remove %d'), $c['delete'])) : '');
			echo '<div class="fs-muted">' . htmlspecialchars(implode(', ', array_map(function ($n, $a) { return "{$a} {$n}"; }, array_keys(array_filter(array_merge($plan['users'], $plan['groups']), function ($a) { return $a !== 'same'; })),
			    array_filter(array_merge($plan['users'], $plan['groups']), function ($a) { return $a !== 'same'; })))) . '</div>';
		}
		if ($c['clashes'] > 0) {
			echo '<div class="fs-fleet-problem">' . htmlspecialchars('FLEET-E441: ' . sprintf(gettext('skipped %s (the firewall has its own)'), implode(', ', $plan['clashes']))) . '</div>';
		}
		foreach ((array)$plan['skipped_privs'] as $ugr => $privs) {
			echo '<div class="fs-fleet-problem">' . htmlspecialchars('FLEET-E442: ' . sprintf(gettext('%1$s: %2$s not on this version'), $ugr, implode(', ', $privs))) . '</div>';
		}
	} catch (RuntimeException $e) {
		echo '<span class="fs-fleet-problem">' . htmlspecialchars($e->getMessage()) . '</span>';
	}
elseif ($st !== null): ?>
				<?=htmlspecialchars(date('Y-m-d H:i', (int)$st['time']))?> <?=($st['result'] === 'done') ? '' : fs_badge('block', gettext('Failed'))?><div class="fs-muted"><?=htmlspecialchars($st['detail'])?></div>
<?php else: ?>
				<span class="fs-muted"><?=gettext('Never')?></span>
<?php endif; ?>
			</td>
<?php $drift = fleet_users_drift($node); ?>
			<td class="small">
<?php if ($drift === null): ?>
				<span class="fs-muted"><?=gettext('Not known')?></span>
<?php elseif (empty($drift)): ?>
				<span class="fs-muted"><?=gettext('None')?></span>
<?php elseif (!empty($drift['pending'])): ?>
				<?=fs_badge('info', ($st === null) ? gettext('Waiting for the first sync') : gettext('Waiting for sync'))?>
				<div class="fs-muted"><?=htmlspecialchars(implode(', ', array_keys($drift['changes'])))?></div>
<?php else: ?>
				<?=fs_badge('warn', sprintf(ngettext('%d changed on the firewall', '%d changed on the firewall', count($drift['changes'])), count($drift['changes'])))?>
				<div class="fs-muted"><?=htmlspecialchars(implode(', ', array_keys($drift['changes'])))?></div>
<?php if ($manage): ?>
				<form method="post" class="d-inline"><button class="btn btn-sm btn-link p-0 me-2" name="drift_adopt" value="<?=htmlspecialchars($node)?>" title="<?=gettext('Take the firewall\'s changes into Fleet')?>"><?=gettext('Adopt')?></button>
					<button class="btn btn-sm btn-link p-0" name="drift_ignore" value="<?=htmlspecialchars($node)?>"><?=gettext('Ignore')?></button></form>
<?php endif; ?>
<?php endif; ?>
			</td>
			<td class="text-end"><?php if ($manage && ($box['state'] === 'online') && fleet_manage_allowed($box)): ?><form method="post" class="d-inline"><input type="hidden" name="node" value="<?=htmlspecialchars($node)?>"/><button class="btn btn-sm btn-link" name="sync" value="1"><?=(empty($drift) || !empty($drift['pending'])) ? gettext('Sync here') : gettext('Revert (sync here)')?></button></form><?php endif; ?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php if ($manage && !empty($nodes)): ?>
	<div class="panel-footer fs-fleet-review-actions fs-fleet-policy-actions">
		<form method="post"><button class="btn btn-primary" name="sync" value="1"><i class="fa-solid fa-rotate icon-embed-btn" aria-hidden="true"></i><?=sprintf(ngettext('Sync %d firewall', 'Sync %d firewalls', count($nodes)), count($nodes))?></button></form>
		<p class="fs-fleet-policy-note"><?=gettext('Each firewall gets a safety backup first. Only accounts Fleet made are changed or removed.')?></p>
	</div>
<?php endif; ?>
</div>
<?php endif; ?>

<?php if ($manage && ($view === 'users')):
	fs_modal_form_begin('user-modal', gettext('Add a user'), '?view=users', array('id' => ''), $reopen_user);
?>
	<div class="row g-3">
		<div class="col-sm-6"><label class="form-label" for="uname"><?=gettext('User name')?></label>
			<input class="form-control fs-mono" id="uname" name="name" maxlength="32" required autocomplete="off"/></div>
		<div class="col-sm-6"><label class="form-label" for="ufull"><?=gettext('Full name')?></label>
			<input class="form-control" id="ufull" name="fullname" maxlength="100" autocomplete="off"/></div>
		<div class="col-12"><label class="form-label" for="ugroups"><?=gettext('Groups')?></label>
			<select class="form-select" id="ugroups" name="groups[]" multiple size="5" data-fs-multiselect
			    data-fs-text-search="<?=gettext('Search groups…')?>" data-fs-text-none="<?=gettext('No groups: no firewall access')?>" data-fs-text-more="<?=gettext('+%d more')?>">
<?php foreach ($ugroups as $gid => $ugr): ?>
				<option value="<?=$gid?>"><?=htmlspecialchars($ugr['name'])?></option>
<?php endforeach; ?>
			</select></div>
		<div class="col-sm-6"><label class="form-label" for="upw"><?=gettext('Password')?></label>
			<input class="form-control" type="password" id="upw" name="password" minlength="10" autocomplete="new-password"/>
			<div class="form-text"><?=gettext('Leave empty for SSH keys only, or to keep the current password.')?></div></div>
		<div class="col-sm-6"><label class="form-label" for="upw2"><?=gettext('Password again')?></label>
			<input class="form-control" type="password" id="upw2" name="password_again" autocomplete="new-password"/></div>
		<div class="col-12"><label class="form-label" for="ukeys"><?=gettext('SSH public keys')?></label>
			<textarea class="form-control fs-mono" id="ukeys" name="ssh_keys" rows="3" placeholder="ssh-ed25519 AAAA... name@laptop" aria-describedby="ukeys-help"></textarea>
			<div class="form-text" id="ukeys-help"><?=gettext('SSH needs a group with the privilege "User - System: Shell account access".')?></div></div>
		<div class="col-sm-6"><label class="form-label" for="uexp"><?=gettext('Account ends')?></label>
			<input class="form-control" type="date" id="uexp" name="expires"/></div>
		<div class="col-sm-6 d-flex align-items-end"><label class="form-check"><input class="form-check-input" type="checkbox" name="disabled" value="1"/> <span class="form-check-label"><?=gettext('Disabled everywhere')?></span></label></div>
	</div>
<?php
	fs_modal_form_end(gettext('Save user'), 'user_save', '1', 'fa-floppy-disk');
endif;
if ($manage && ($view === 'groups')):
	fs_modal_form_begin('group-modal', gettext('Add a user group'), '?view=groups', array('id' => ''), $reopen_group);
?>
	<div class="row g-3">
		<div class="col-sm-6"><label class="form-label" for="gname"><?=gettext('Name')?></label>
			<input class="form-control fs-mono" id="gname" name="name" maxlength="32" required placeholder="shop-support"/></div>
		<div class="col-sm-6"><label class="form-label" for="gdesc"><?=gettext('Description')?></label>
			<input class="form-control" id="gdesc" name="description" maxlength="200"/></div>
		<div class="col-12"><label class="form-label" for="gtargets"><?=gettext('For')?></label><?=$targets_select('gtargets')?></div>
		<div class="col-12"><label class="form-label" for="gprivs"><?=gettext('Privileges')?></label>
			<select class="form-select" id="gprivs" name="privs[]" multiple size="10" data-fs-multiselect
			    data-fs-text-search="<?=gettext('Search privileges: dashboard, firewall rules, diagnostics…')?>" data-fs-text-none="<?=gettext('Choose privileges…')?>" data-fs-text-more="<?=gettext('+%d more')?>">
<?php foreach ($catalog as $p => $label): ?>
				<option value="<?=htmlspecialchars($p)?>"><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
			</select>
			<div class="form-text"><?=gettext('"WebCfg - All pages" makes the members full administrators.')?></div></div>
	</div>
<?php
	fs_modal_form_end(gettext('Save group'), 'group_save', '1', 'fa-floppy-disk');
endif; ?>
<?php include('foot.inc');
