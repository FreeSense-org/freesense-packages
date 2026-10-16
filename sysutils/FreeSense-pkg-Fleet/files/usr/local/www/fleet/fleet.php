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
$new_ts_key = null;
$new_name = null;
$standby_code = null;

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
		$via = ((string)($_POST['via'] ?? '') === 'tailscale') ? 'tailscale' : '';
		$ttl = 3600 * max(1, min(720, (int)($_POST['hours'] ?? fleet_opt('invite_hours'))));
		$authority = fleet_hostport($s['public_host'], $s['enroll_port']);
		if ($via === 'tailscale') {
			list($ts_problems, $ts_address) = fleet_ts_join_ready();
			if (!empty($ts_problems)) {
				throw new InvalidArgumentException(implode(' ', $ts_problems));
			}
			$authority = fleet_hostport($ts_address, $s['enroll_port']);
		}
		$new_invite = fleet_invite_create((string)($_POST['role'] ?? 'monitor'), trim((string)($_POST['label'] ?? '')), $ttl, $who, $authority, time(), $via);
		if ($via === 'tailscale') {
			try {
				$new_ts_key = fleet_ts_authkey_mint(trim((string)($_POST['label'] ?? '')), $ttl, $who, $new_invite[2]);
			} catch (RuntimeException $e) {
				fleet_invite_revoke($new_invite[2], $who);
				$new_invite = null;
				throw new InvalidArgumentException($e->getMessage());
			}
		}
		try {
			$new_name = fleet_invite_set_name($new_invite[2], (int)($_POST['naming_group'] ?? 0), (string)($_POST['site'] ?? ''), (string)($_POST['fw_role'] ?? ''),
			    (string)($_POST['hostname'] ?? ''), $who);
		} catch (InvalidArgumentException $e) {
			fleet_invite_revoke($new_invite[2], $who);
			$new_invite = null;
			throw $e;
		}
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
		$problem = fleet_naming_pattern_problem(strtolower(trim((string)($_POST['naming_pattern'] ?? ''))));
		if ($problem !== null) {
			throw new InvalidArgumentException($problem);
		}
		if (!fleet_naming_domain_ok(strtolower(trim((string)($_POST['naming_domain'] ?? ''))))) {
			throw new InvalidArgumentException(gettext('The domain is a name like shops.example.local.'));
		}
		$gid = fleet_group_save($edit_id, (string)($_POST['group_name'] ?? ''), (string)($_POST['group_description'] ?? ''),
		    (string)($_POST['group_color'] ?? ''), $who);
		fleet_naming_set($gid, (string)($_POST['naming_pattern'] ?? ''), (string)($_POST['naming_domain'] ?? ''), $who);
		$win = (int)($_POST['group_window'] ?? 0);
		fleet_group_set_window($gid, (fleet_window_get($win) !== null) ? $win : null, $who);
		$savemsg = ($edit_id === null) ? gettext('Group created. Add firewalls to it on each firewall\'s Overview.') : gettext('Group saved.');
	} catch (InvalidArgumentException $e) {
		$input_errors[] = $e->getMessage();
	}
} elseif (isset($_POST['group_delete']) && $s['enable']) {
	try {
		fleet_group_delete((int)$_POST['group_delete'], $who);
		$savemsg = gettext('Group deleted. Its firewalls were not changed.');
	} catch (RuntimeException $e) {
		$input_errors[] = $e->getMessage();
	}
} elseif (isset($_POST['standby_action'])) {
	/* Standby server: pairing and settings on the primary; joining, fetching, promoting and leaving on the standby. */
	$tab = 'settings';
	try {
		switch ((string)$_POST['standby_action']) {
		case 'pair':
			if ($s['enable']) {
				$standby_code = fleet_standby_pair_new((string)($_POST['takeover'] ?? 'manual'), (int)($_POST['interval'] ?? 5), (int)($_POST['auto_minutes'] ?? 15), $who);
			}
			break;
		case 'save':
			if ($s['enable']) {
				fleet_standby_settings_save((string)($_POST['takeover'] ?? 'manual'), (int)($_POST['interval'] ?? 5), (int)($_POST['auto_minutes'] ?? 15));
				$savemsg = gettext('Saved. The standby picks the settings up on its next fetch.');
			}
			break;
		case 'remove':
			if ($s['enable']) {
				fleet_standby_remove($who);
				$savemsg = gettext('The standby was removed. Firewalls are told to use only this controller within a minute.');
			}
			break;
		case 'join':
			$problem = fleet_standby_join((string)($_POST['code'] ?? ''), trim((string)($_POST['own_addr'] ?? '')), $who);
			if ($problem !== null) {
				$input_errors[] = $problem;
			} else {
				$savemsg = gettext('This server is now the standby. It fetches a copy every minute.');
			}
			break;
		case 'pull':
			$problem = fleet_standby_pull(time());
			if ($problem !== null) {
				$input_errors[] = $problem;
			} else {
				$savemsg = gettext('The copy is up to date.');
			}
			break;
		case 'promote':
			if (empty($_POST['confirm_down'])) {
				$input_errors[] = gettext('Confirm that the primary controller is down or switched off.');
				break;
			}
			fleet_standby_promote($who, 'by hand');
			$s = fleet_ctl_settings();
			$savemsg = gettext('This server is now the Fleet controller. Firewalls move here by themselves within a few minutes.');
			break;
		case 'leave':
			fleet_standby_leave($who);
			$savemsg = gettext('This server is no longer the standby; its copy was deleted.');
			break;
		}
	} catch (Throwable $e) {
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
	array(gettext('Schedules'), false, '/fleet/fleet_schedules.php'),
	array(gettext('Backups'), false, '/fleet/fleet_backups.php'),
	array(gettext('Policies'), false, '/fleet/fleet_policies.php'),
	array(gettext('Templates'), false, '/fleet/fleet_templates.php'),
	array(gettext('Users'), false, '/fleet/fleet_users.php'),
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
	$fw_default = (isset($_POST['group_save']) || isset($_POST['group_delete'])) ? 'groups' : (($_SERVER['REQUEST_METHOD'] === 'POST') || ($new_invite !== null) ? 'invite' : 'list');
	$fw_view = fs_view_param(array('list', 'invite', 'groups'), $fw_default);
	$fw_ready = $s['enable'] && is_file(FLEET_DATA . '/fleet.db');
	echo fleet_firewalls_nav($fw_view, $fw_ready ? (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn() : 0);
?>
<?php if ($fw_view === 'list'):
	if (!$fw_ready): ?>
<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller yet')?></strong> <a href="?tab=settings"><?=gettext('Turn it on in Settings')?></a></div>
<?php else:
	$all = fleet_dashboard_data(
	    fleet_db()->query('SELECT node_id, name, label, overlay, role, state, last_seen, error, status, update_info, (SELECT MAX(time) FROM backups b WHERE b.node_id = boxes.node_id) AS last_backup FROM boxes')->fetchAll(),
	    0, time(), fleet_groups_by_box())['boxes'];
	$fgroups = array();
	foreach (fleet_groups_all() as $fg) {
		$fgroups[(string)$fg['id']] = $fg['name'];
	}
	$fversions = fleet_firewalls_versions($all);
	$f = fleet_list_filters($_GET, array('q' => null, 'state' => FLEET_FW_STATES, 'group' => $fgroups, 'version' => $fversions,
	    'problem' => array('attention' => 1, 'unprotected' => 1, 'policy' => 1, 'update' => 1, 'waiting' => 1), 'sort' => FLEET_FW_SORTS));
	$fbase = array();
	$shown = fleet_firewalls_filter($all, $f);
	$fpg = fleet_list_page(count($shown), (int)($_GET['page'] ?? 1));
	$rows = array_slice($shown, $fpg['offset'], $fpg['per']);
	/* On their way in, and the controller itself: shown above the firewalls when no other filter narrows the list. */
	$plain = !isset($f['state']) && !isset($f['group']) && !isset($f['version']) && in_array($f['problem'] ?? '', array('', 'waiting'), true);
	$waiting = fleet_waiting_list($f['q'] ?? null);
	$ctl_row = ($plain && !isset($f['problem']) && ($fpg['page'] ?? 1) == 1 && (!isset($f['q']) || (stripos(fleet_controller_row()['label'], $f['q']) !== false))) ? fleet_controller_row() : null;
	$quick = array('' => array(gettext('All'), count($all)),
	    'waiting' => array(gettext('Waiting to join'), count(fleet_waiting_list())),
	    'attention' => array(gettext('Need attention'), count(fleet_firewalls_filter($all, array('problem' => 'attention')))),
	    'update' => array(gettext('Update available'), count(fleet_firewalls_filter($all, array('problem' => 'update')))),
	    'policy' => array(gettext('Policy problems'), count(fleet_firewalls_filter($all, array('problem' => 'policy')))),
	    'unprotected' => array(gettext('No rollback'), count(fleet_firewalls_filter($all, array('problem' => 'unprotected')))));
	$ago = function ($t) {
		if ($t === null) {
			return gettext('never');
		}
		$d = max(0, time() - (int)$t);
		if ($d < 90) {
			return gettext('just now');
		}
		if ($d < 5400) {
			return sprintf(gettext('%d min ago'), round($d / 60));
		}
		return ($d < 129600) ? sprintf(gettext('%d h ago'), round($d / 3600)) : sprintf(gettext('%d days ago'), round($d / 86400));
	};
	$sbadge = array('online' => array('pass', gettext('Online')), 'degraded' => array('warn', gettext('Degraded')), 'offline' => array('block', gettext('Offline')),
	    'new' => array('neutral', gettext('Not seen yet')));
	$keep = isset($f['problem']) ? array('problem' => $f['problem']) : array();
?>
<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-server" aria-hidden="true"></i></span>
		<div><h2><?=gettext('All firewalls')?></h2><p><?=gettext('Every firewall in the fleet. Search by name, address or version, narrow by state or group, and open one to manage it.')?></p></div>
		<span class="fs-fleet-area-actions"><a class="btn btn-sm btn-primary" href="?view=invite"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add firewall')?></a>
			<a class="btn btn-sm btn-outline-secondary" href="/fleet/fleet_factory.php?view=new"><i class="fa-solid fa-industry icon-embed-btn" aria-hidden="true"></i><?=gettext('Add many')?></a></span></header>
	<nav class="fs-fleet-quick" aria-label="<?=gettext('Quick filters')?>">
<?php foreach ($quick as $k => list($label, $n)): ?>
		<a href="<?=htmlspecialchars(fleet_list_url($fbase, $f, array('problem' => ($k === '') ? null : $k)))?>"<?=(($f['problem'] ?? '') === $k) ? ' aria-current="true"' : ''?>><?=htmlspecialchars($label)?> <span class="fs-fleet-count"><?=$n?></span></a>
<?php endforeach; ?>
	</nav>
</section>
<div class="panel panel-default">
	<div class="panel-heading"><?=fleet_list_filterbar($keep, $f, array('state' => array(gettext('Any state'), FLEET_FW_STATES), 'group' => array(gettext('Any group'), $fgroups),
	    'version' => array(gettext('Any version'), $fversions), 'sort' => array(gettext('Needs attention first'), array_slice(FLEET_FW_SORTS, 1, null, true))),
	    gettext('Search firewalls'), gettext('Name, address or version'))?></div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Firewall')?></th><th><?=gettext('State')?></th><th><?=gettext('Version')?></th><th><?=gettext('Groups')?></th><th><?=gettext('Last seen')?></th><th><?=gettext('Last backup')?></th><th class="text-end"><?=gettext('Notes')?></th></tr></thead>
		<tbody>
<?php if (empty($rows) && ((($f['problem'] ?? '') !== 'waiting') || empty($waiting)) && ($ctl_row === null || !empty($f['q']))): ?>
		<tr><td colspan="7" class="fs-muted"><?=(($f['problem'] ?? '') === 'waiting') ? gettext('Nothing is waiting to join.') : (empty($all) ? gettext('No firewalls yet. Add one, or many at once with the Deployment Factory.') : gettext('No firewall matches these filters.'))?></td></tr>
<?php endif; ?>
<?php if ($ctl_row !== null): $up = $ctl_row['uptime']; ?>
		<tr class="fs-fleet-row-controller"><td><a href="?tab=settings"><strong><?=htmlspecialchars($ctl_row['label'])?></strong></a> <?=fs_badge('info', gettext('Fleet server'))?>
				<div class="fs-muted small"><?=gettext('This controller. It runs Fleet and is not managed by it.')?></div></td>
			<td><?=fs_badge('pass', gettext('Online'))?><?=($up !== null) ? '<div class="fs-muted small">' . htmlspecialchars(sprintf(gettext('Up %s'), fleet_uptime_text($up))) . '</div>' : ''?></td>
			<td class="small"><?=htmlspecialchars($ctl_row['version'])?></td>
			<td><span class="fs-muted">-</span></td>
			<td class="small"><?=gettext('now')?></td>
			<td class="small"><a href="/fleet/fleet_backups.php"><?=gettext('Self-backup')?></a></td>
			<td class="text-end small"><span class="fs-muted"><?=gettext('Read only')?></span></td></tr>
<?php endif; ?>
<?php $sbo = ($ctl_row !== null) ? fleet_standby_overview() : null;
	if (($sbo !== null) && ($sbo['role'] === 'primary') && ($sbo['addr'] !== '')): $sb_late = (time() - $sbo['seen']) > FLEET_STANDBY_LATE; ?>
		<tr class="fs-fleet-row-controller"><td><a href="?tab=settings&amp;view=standby"><strong><?=htmlspecialchars($sbo['addr'])?></strong></a> <?=fs_badge('neutral', gettext('Standby server'))?>
				<div class="fs-muted small"><?=gettext('Keeps a copy of this controller and can take over.')?></div></td>
			<td><?=$sb_late ? fs_badge('warn', gettext('Late')) : fs_badge('pass', gettext('Up to date'))?></td>
			<td class="small"><?=htmlspecialchars($sbo['version'])?></td>
			<td><span class="fs-muted">-</span></td>
			<td class="small"><?=htmlspecialchars($ago($sbo['seen']))?></td>
			<td class="small"><?=htmlspecialchars(sprintf(gettext('%1$d of %2$d firewalls know it'), $sbo['known'], $sbo['total']))?></td>
			<td class="text-end small"><span class="fs-muted"><?=gettext('Read only')?></span></td></tr>
<?php endif; ?>
<?php if ($plain && (($fpg['page'] ?? 1) == 1)): foreach ($waiting as $w): ?>
		<tr class="fs-fleet-row-waiting"><td><a href="<?=htmlspecialchars($w['url'])?>"><strong><?=htmlspecialchars($w['label'])?></strong></a>
				<div class="fs-muted small"><?=htmlspecialchars($w['detail'])?></div></td>
			<td><?=($w['kind'] === 'approval') ? fs_badge('warn', gettext('Waiting for approval')) : fs_badge('neutral', ($w['kind'] === 'factory') ? gettext('Waiting to be deployed') : gettext('Invited'))?></td>
			<td class="small fs-muted">-</td><td><span class="fs-muted">-</span></td>
			<td class="small"><?=htmlspecialchars(sprintf(($w['kind'] === 'approval') ? gettext('joined %s') : gettext('invited %s'), $ago($w['time'])))?></td><td class="small fs-muted">-</td>
			<td class="text-end small"><a href="<?=htmlspecialchars($w['url'])?>"><?=($w['kind'] === 'approval') ? gettext('Approve...') : gettext('Open')?></a></td></tr>
<?php endforeach; endif; ?>
<?php foreach ($rows as $b): list($bs, $bl) = $sbadge[$b['state']]; ?>
		<tr><td><a href="/fleet/fleet_box.php?id=<?=urlencode($b['id'])?>"><strong><?=htmlspecialchars($b['label'])?></strong></a>
				<div class="fs-muted small fs-mono"><?=htmlspecialchars($b['host'] . ' ' . $b['overlay'])?></div></td>
			<td><?=fs_badge($bs, $bl)?><?=($b['problem'] !== '') ? '<div class="fs-muted small">' . htmlspecialchars(mb_strimwidth($b['problem'], 0, 60, '...')) . '</div>' : ''?></td>
			<td class="small"><?=htmlspecialchars(($b['version'] !== '') ? $b['version'] : '-')?><?=($b['update'] !== null) ? '<div>' . fs_badge($b['update'][0], gettext($b['update'][1])) . '</div>' : ''?></td>
			<td><?php foreach ($b['groups'] as $g1): ?><a class="fs-fleet-chip" href="<?=htmlspecialchars(fleet_list_url($fbase, $f, array('group' => (string)$g1['id'])))?>"><?=htmlspecialchars($g1['name'])?></a> <?php endforeach; ?><?=empty($b['groups']) ? '<span class="fs-muted">-</span>' : ''?></td>
			<td class="small"><?=htmlspecialchars($ago($b['seen']))?></td>
			<td class="small"><?=htmlspecialchars($ago($b['backup']))?></td>
			<td class="text-end small"><?php
				$notes = array();
				if ($b['policy'] > 0) {
					$notes[] = '<span class="fs-fleet-problem">' . htmlspecialchars(sprintf(ngettext('%d policy rule fails', '%d policy rules fail', $b['policy']), $b['policy'])) . '</span>';
				}
				if ($b['breakglass']) {
					$notes[] = '<span class="fs-fleet-problem">' . gettext('Lock suspended') . '</span>';
				}
				if ($b['rollback'] === false) {
					$notes[] = '<span class="fs-muted">' . gettext('No rollback (UFS)') . '</span>';
				}
				if (!$b['managed']) {
					$notes[] = '<span class="fs-muted">' . gettext('Monitor only') . '</span>';
				}
				echo implode('<br>', $notes); ?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
	<div class="panel-footer"><?=fleet_list_pager($fpg, $keep, $f)?></div>
</div>
<?php endif; ?>
<?php elseif ($fw_view === 'groups'):
	$groups = fleet_groups_all();
	$all_windows = fleet_windows_all();
	$win_names = array_column($all_windows, 'name', 'id');
	/* Search lives in the URL like every list. */
	$gq = trim((string)($_GET['q'] ?? ''));
	$shown = array_values(array_filter($groups, function ($one) use ($gq) {
		return ($gq === '') || (stripos($one['name'] . ' ' . $one['description'], $gq) !== false);
	}));
	/* After an error the modal opens again with what was typed. */
	$reopen = (isset($_POST['group_save']) && !empty($input_errors)) ? array('group_id' => (string)($_POST['group_id'] ?? ''),
	    'group_name' => (string)($_POST['group_name'] ?? ''), 'group_description' => (string)($_POST['group_description'] ?? ''),
	    'group_window' => (string)($_POST['group_window'] ?? '0'), 'group_color' => (string)($_POST['group_color'] ?? '1'),
	    'naming_pattern' => (string)($_POST['naming_pattern'] ?? ''), 'naming_domain' => (string)($_POST['naming_domain'] ?? '')) : null;
	$new_fill = array('group_window' => '0', 'group_color' => fleet_group_color((string)((count($groups) % 8) + 1)));
?>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Groups')?> <span class="fs-count"><?=count($groups)?></span></h2>
		<button type="button" class="btn btn-sm btn-primary" data-fs-modal="#group-modal" data-fs-modal-title="<?=gettext('Add a group')?>" data-fs-fill="<?=htmlspecialchars(json_encode($new_fill))?>"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add group')?></button></div>
<?php if (empty($groups)): ?>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=gettext('No groups yet. Group firewalls by place, customer or role, for example Denmark, Retail or Canary. Policies, backups and updates can then target a group.')?></p></div>
<?php else: ?>
	<div class="panel-body fs-fleet-pad">
		<form method="get" class="fs-fleet-filterbar" role="search">
			<input type="hidden" name="view" value="groups"/>
			<input class="form-control form-control-sm" type="search" name="q" value="<?=htmlspecialchars($gq)?>" placeholder="<?=gettext('Search name or description')?>" aria-label="<?=gettext('Search groups')?>"/>
			<button class="btn btn-sm btn-outline-secondary" type="submit"><?=gettext('Search')?></button>
<?php if ($gq !== ''): ?>
			<a class="btn btn-sm btn-link" href="?view=groups"><?=gettext('Clear')?></a>
			<span class="fs-muted small ms-auto"><?=sprintf(gettext('%1$d of %2$d'), count($shown), count($groups))?></span>
<?php endif; ?>
		</form>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Name')?></th><th><?=gettext('Description')?></th><th><?=gettext('Window')?></th><th><?=gettext('Naming')?></th><th><?=gettext('Firewalls')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($shown)): ?>
		<tr><td colspan="5" class="fs-muted"><?=gettext('No group matches.')?> <a href="?view=groups"><?=gettext('Clear the search')?></a></td></tr>
<?php endif; ?>
<?php foreach ($shown as $grp): ?>
		<tr><td><span class="fs-fleet-group" style="--fs-fleet-group: var(--fs-series-<?=htmlspecialchars(fleet_group_color((string)$grp['color']))?>)"><?=htmlspecialchars($grp['name'])?></span></td>
			<td><?=($grp['description'] !== '') ? htmlspecialchars($grp['description']) : '<span class="fs-muted">-</span>'?></td>
			<td><?=isset($win_names[(int)$grp['window_id']]) ? htmlspecialchars($win_names[(int)$grp['window_id']]) : '<span class="fs-muted">-</span>'?></td>
			<td class="fs-mono small"><?=((($grp['naming_pattern'] ?? '') . ($grp['naming_domain'] ?? '')) === '') ? '<span class="fs-muted">-</span>' :
			    htmlspecialchars((($grp['naming_pattern'] !== '') ? $grp['naming_pattern'] : '*') . (($grp['naming_domain'] !== '') ? '.' . $grp['naming_domain'] : ''))?></td>
			<td><a class="fs-fleet-inline-link" href="/fleet/fleet_dashboard.php?group=<?=(int)$grp['id']?>"><?=(int)$grp['members']?></a></td>
			<td class="text-end text-nowrap">
				<button type="button" class="btn btn-sm btn-link" data-fs-modal="#group-modal" data-fs-modal-title="<?=htmlspecialchars(sprintf(gettext('Change %s'), $grp['name']))?>"
				    data-fs-fill="<?=htmlspecialchars(json_encode(array('group_id' => (string)$grp['id'], 'group_name' => $grp['name'], 'group_description' => $grp['description'],
				    'group_window' => (string)(int)$grp['window_id'], 'group_color' => fleet_group_color((string)$grp['color']),
				    'naming_pattern' => (string)($grp['naming_pattern'] ?? ''), 'naming_domain' => (string)($grp['naming_domain'] ?? ''))))?>"><?=gettext('Change')?></button>
				<form method="post" action="?view=groups" class="d-inline"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="group_delete" value="<?=(int)$grp['id']?>" title="<?=gettext('Its firewalls stay in the fleet')?>"><?=gettext('Delete')?></button></form>
			</td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php endif; ?>
	<div class="panel-footer small fs-muted"><?=gettext('A firewall can be in several groups. Deleting a group never changes its firewalls; a group that a policy, backup set or update ring uses cannot be deleted.')?></div>
</div>
<?php
	fs_modal_form_begin('group-modal', gettext('Add a group'), '?view=groups', array('group_id' => ''), $reopen);
?>
	<div class="mb-3"><label class="form-label" for="group_name"><?=gettext('Name')?></label>
		<input class="form-control" id="group_name" name="group_name" maxlength="40" required placeholder="<?=gettext('Retail')?>"/></div>
	<div class="mb-3"><label class="form-label" for="group_description"><?=gettext('Description')?></label>
		<input class="form-control" id="group_description" name="group_description" maxlength="200" placeholder="<?=gettext('Shops and pop-up stores')?>"/></div>
	<div class="mb-3"><label class="form-label" for="group_window"><?=gettext('Maintenance window')?></label>
		<select class="form-select" id="group_window" name="group_window">
			<option value="0"><?=gettext('None (any time)')?></option>
<?php foreach ($all_windows as $w): ?>
			<option value="<?=(int)$w['id']?>"><?=htmlspecialchars($w['name'] . ' (' . fleet_window_text($w) . ')')?></option>
<?php endforeach; ?>
		</select>
		<div class="form-text"><?=gettext('Rollouts update this group only inside its window.')?> <a href="/fleet/fleet_updates.php?view=windows"><?=gettext('Manage windows')?></a></div></div>
	<fieldset class="mb-3 fs-fleet-naming" data-fleet-naming><legend class="form-label"><i class="fa-solid fa-tag" aria-hidden="true"></i> <?=gettext('Naming')?></legend>
		<div class="row g-2">
			<div class="col-sm-6"><label class="form-label small" for="naming_pattern"><?=gettext('Hostname pattern')?></label>
				<input class="form-control fs-mono" id="naming_pattern" name="naming_pattern" maxlength="63" placeholder="{site}-fw{nn}" data-naming-pattern/></div>
			<div class="col-sm-6"><label class="form-label small" for="naming_domain"><?=gettext('Domain')?></label>
				<input class="form-control fs-mono" id="naming_domain" name="naming_domain" maxlength="253" placeholder="shops.example.local" data-naming-domain/></div>
		</div>
		<div class="form-text"><?=gettext('New firewalls in this group are named by it when they join. Tokens: {site} {role} {group} {nn} {nnn}; numbers are never used twice.')?>
			<span class="fs-fleet-naming-preview" aria-live="polite" data-naming-preview></span></div>
	</fieldset>
	<fieldset class="mb-1"><legend class="form-label"><?=gettext('Colour')?></legend>
		<div class="fs-fleet-swatches">
<?php foreach (FLEET_GROUP_COLORS as $c): ?>
			<label class="fs-fleet-swatch" style="--fs-fleet-group: var(--fs-series-<?=$c?>)"><input type="radio" name="group_color" value="<?=$c?>"<?=($c === '1') ? ' checked' : ''?>/><span class="visually-hidden"><?=sprintf(gettext('Colour %s'), $c)?></span></label>
<?php endforeach; ?>
		</div></fieldset>
<?php
	fs_modal_form_end(gettext('Save group'), 'group_save', '1', 'fa-floppy-disk');
?>
<?php else: ?>

<?php if ($new_invite !== null): list($link, $key, $tid, $expires) = $new_invite; ?>
<section class="fs-fleet-block fs-fleet-invite" aria-labelledby="invite-title">
	<h2 id="invite-title" class="fs-fleet-section-title"><?=sprintf(gettext('Invitation for %s'), htmlspecialchars(trim((string)($_POST['label'] ?? ''))))?></h2>
	<p class="fs-fleet-lead"><?=sprintf(gettext('Valid until %s. The join key is shown only now: copy it, and send it by a different channel than the link.'), htmlspecialchars(date('Y-m-d H:i', $expires)))?></p>
<?php if (!empty($new_name[0]) || !empty($new_name[1])): ?>
	<p><i class="fa-solid fa-tag" aria-hidden="true"></i> <?=gettext('It will be named')?> <strong class="fs-mono"><?=htmlspecialchars(trim(($new_name[0] ?: '*') . (($new_name[1] !== '') ? '.' . $new_name[1] : '')))?></strong> <?=gettext('when it joins.')?></p>
<?php endif; ?>
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
<?php if ($new_ts_key !== null): ?>
	<div class="fs-fleet-secret">
		<span class="fs-fleet-secret-label"><?=gettext('Tailscale key')?></span>
		<code id="fleet-tskey" class="fs-fleet-secret-value fs-fleet-key"><?=htmlspecialchars($new_ts_key)?></code>
		<button type="button" class="btn btn-sm btn-outline-secondary" data-fs-copy="#fleet-tskey"><i class="fa-regular fa-clone icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy key')?></button>
	</div>
	<p class="fs-fleet-hint"><?=gettext('A one-time, pre-approved Tailscale key for this firewall only. It is shown only now; it expires with the invitation.')?></p>
	<h3 class="h6 mt-3"><?=gettext('On the new firewall')?></h3>
	<ol class="fs-fleet-steps">
		<li><?=gettext('Install Tailscale: System > Package Manager > Available Packages > Tailscale.')?></li>
		<li><?=gettext('VPN > Tailscale > Authentication: paste the Tailscale key, save; then enable Tailscale on its Settings tab. Or at the console:')?>
			<code class="d-block mt-1">tailscale up --auth-key='&lt;Tailscale key&gt;'</code></li>
		<li><?=sprintf(gettext('Join the fleet: console option 17, or %s, and type the join key when asked. The link uses this controller\'s tailnet address, so no public port is needed.'), '<code>freesense-join join \'&lt;link&gt;\'</code>')?></li>
		<li><?=gettext('Approve it below when the codes match. Fleet then moves its management onto the Tailscale path by itself; the Fleet tunnel (also over the tailnet) stays as the fallback.')?></li>
	</ol>
<?php else: ?>
	<ol class="fs-fleet-steps">
		<li><?=sprintf(gettext('On the new firewall, open the console and choose option 17, or run %s.'), '<code>freesense-join join \'&lt;link&gt;\'</code>')?></li>
		<li><?=gettext('Paste the link, then type the join key when asked.')?></li>
		<li><?=gettext('The firewall shows a 6-digit code. Approve it below when the same code appears here.')?></li>
	</ol>
<?php endif; ?>
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
<?php list($ts_join_problems, $ts_join_address) = fleet_ts_join_ready(); ?>
		<fieldset class="fs-fleet-field fs-fleet-field--full"><legend class="form-label"><?=gettext('The new firewall reaches this controller')?></legend>
			<label class="form-check"><input class="form-check-input" type="radio" name="via" value="" checked/> <span class="form-check-label"><?=gettext('Over the internet (the Fleet tunnel: needs the public address and ports in Settings)')?></span></label>
			<label class="form-check"><input class="form-check-input" type="radio" name="via" value="tailscale"<?=empty($ts_join_problems) ? '' : ' disabled'?>/> <span class="form-check-label"><?=gettext('Over Tailscale (no public port: Fleet creates a one-time Tailscale key)')?></span></label>
<?php if (!empty($ts_join_problems)): ?>
			<div class="form-text"><?=htmlspecialchars(implode(' ', array_map('gettext', $ts_join_problems)))?></div>
<?php else: ?>
			<div class="form-text"><?=htmlspecialchars(sprintf(gettext('Ready: this controller is %s in the tailnet and the API token works.'), $ts_join_address))?></div>
<?php endif; ?>
		</fieldset>
		<div class="fs-fleet-field fs-fleet-field--wide"><label class="form-label" for="label"><?=gettext('Name')?></label>
			<input class="form-control" id="label" name="label" placeholder="<?=gettext('Copenhagen office')?>" required maxlength="80"/></div>
		<div class="fs-fleet-field"><label class="form-label" for="role"><?=gettext('Access')?></label>
			<select class="form-select" id="role" name="role" aria-describedby="role-help">
				<option value="monitor"><?=gettext('Monitor only')?></option>
				<option value="managed"><?=gettext('Managed')?></option>
			</select></div>
<?php $name_groups = fleet_groups_all(); if (!empty($name_groups)): ?>
		<div class="fs-fleet-field"><label class="form-label" for="naming_group"><?=gettext('Group')?></label>
			<select class="form-select" id="naming_group" name="naming_group">
				<option value="0"><?=gettext('None')?></option>
<?php foreach ($name_groups as $ng): ?>
				<option value="<?=(int)$ng['id']?>" data-pattern="<?=htmlspecialchars((string)($ng['naming_pattern'] ?? ''))?>" data-domain="<?=htmlspecialchars((string)($ng['naming_domain'] ?? ''))?>"
				    data-next="<?=htmlspecialchars((string)fleet_naming_peek((int)$ng['id'], array()))?>"><?=htmlspecialchars($ng['name'] . ((($ng['naming_pattern'] ?? '') !== '') ? ' (' . $ng['naming_pattern'] . ')' : ''))?></option>
<?php endforeach; ?>
			</select></div>
		<div class="fs-fleet-field"><label class="form-label" for="site"><?=gettext('Site')?></label>
			<input class="form-control" id="site" name="site" maxlength="40" placeholder="cph"/></div>
		<div class="fs-fleet-field"><label class="form-label" for="hostname"><?=gettext('Hostname')?></label>
			<input class="form-control fs-mono" id="hostname" name="hostname" maxlength="63" placeholder="<?=gettext('From the group')?>"/></div>
<?php endif; ?>
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
		<tr><td><?=htmlspecialchars($i['label'])?><?=(($i['via'] ?? '') === 'tailscale') ? ' ' . fs_badge('neutral', gettext('Over Tailscale')) : ''?></td><td><?=htmlspecialchars($role_name($i['role']))?></td>
			<td><?=htmlspecialchars(date('Y-m-d H:i', (int)$i['expires']))?></td>
			<td><?=((int)$i['failures'] > 0) ? fs_badge('warn', (int)$i['failures'] . ' / ' . fleet_opt('invite_failures')) : '<span class="fs-muted">0</span>'?></td>
			<td class="text-end"><form method="post"><button class="btn btn-sm btn-outline-secondary" name="revoke" value="<?=htmlspecialchars($i['token_id'])?>"><?=gettext('Revoke')?></button></form></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
</section>
<?php endif; ?>

<?php endif; ?>
<?php else:
	$set_view = fs_view_param(array_keys(FLEET_SETTINGS_SECTIONS), (string)($_POST['save_section'] ?? ((isset($_POST['standby_action']) || (!$ready && (fleet_standby_role() === 'standby'))) ? 'standby' : 'controller')));
	$set_labels = array_map('gettext', FLEET_SETTINGS_SECTIONS);
	fs_view_switch($set_labels, $set_view);
	$set_leads = array(
		'controller' => gettext('Firewalls connect to this controller. They may be behind NAT: they start the connection, so only this controller needs to be reachable.'),
		'monitoring' => gettext('How often the controller asks each firewall for its status, and when a silent firewall counts as degraded or offline.'),
		'actions' => gettext('Reboots, backups and restores started from Fleet: how long results stay visible and when you are told.'),
		'backups' => gettext('Central backups of each firewall\'s configuration, taken every night and when it changes.'),
		'advanced' => gettext('Values you rarely need to change. The defaults suit most fleets.'),
		'standby' => gettext('A second FreeSense with the Fleet package keeps a verified, encrypted copy of this controller and can take over. Firewalls learn its address automatically, also ones that join later, and move to it by themselves when it takes over.'),
	);
?>
<?php if ($set_view === 'standby'):
	$sb_role = fleet_standby_role();
	$sb_ago = function (int $t): string {
		if ($t <= 0) {
			return gettext('never');
		}
		$d = max(0, time() - $t);
		return ($d < 90) ? gettext('just now') : (($d < 5400) ? sprintf(gettext('%d min ago'), round($d / 60)) : sprintf(gettext('%d h ago'), round($d / 3600)));
	};
	$sb_select = function (string $name, string $label, array $options, $value, string $help) {
		echo '<div class="fs-fleet-field"><label class="form-label" for="sb-' . $name . '">' . htmlspecialchars($label) . '</label><select class="form-select fs-fleet-narrow" id="sb-' . $name .
		    '" name="' . $name . '" aria-describedby="sb-' . $name . '-help">';
		foreach ($options as $k => $l) {
			echo '<option value="' . htmlspecialchars((string)$k) . '"' . (((string)$k === (string)$value) ? ' selected' : '') . '>' . htmlspecialchars($l) . '</option>';
		}
		echo '</select><div id="sb-' . $name . '-help" class="fs-fleet-hint">' . htmlspecialchars($help) . '</div></div>';
	};
?>
<?php if ($ready): $ov = fleet_standby_overview(); $late = ($ov['seen'] > 0) && ((time() - $ov['seen']) > FLEET_STANDBY_LATE); ?>
<form method="post" action="?tab=settings&amp;view=standby">
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Standby server')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=htmlspecialchars($set_leads['standby'])?></p>
<?php if ($standby_code !== null): ?>
		<div class="fs-fleet-review mb-3">
			<h3 class="fs-fleet-subtitle"><?=gettext('Pairing code')?></h3>
			<p class="fs-fleet-hint"><?=gettext('Shown once. On the standby server, open Fleet > Settings > Standby server and paste it with the standby\'s own address. Anyone with this code can fetch a full copy of this controller: treat it like a password.')?></p>
			<textarea class="form-control fs-mono" rows="3" readonly onclick="this.select()"><?=htmlspecialchars($standby_code)?></textarea>
		</div>
<?php endif; ?>
<?php if ($ov['role'] === 'primary'): ?>
		<dl class="fs-fleet-facts mb-3">
			<dt><?=gettext('Standby')?></dt><dd><?=($ov['addr'] !== '') ? htmlspecialchars($ov['addr']) . ($ov['version'] !== '' ? ' <span class="fs-muted small">' . htmlspecialchars($ov['version']) . '</span>' : '') : '<span class="fs-muted">' . gettext('Waiting for the standby to connect with the pairing code') . '</span>'?></dd>
			<dt><?=gettext('Last copy fetched')?></dt><dd><?=($ov['seen'] > 0) ? fs_badge($late ? 'warn' : 'pass', $late ? gettext('Late') : gettext('Up to date')) . ' ' . htmlspecialchars($sb_ago($ov['seen'])) : '<span class="fs-muted">' . gettext('never') . '</span>'?></dd>
			<dt><?=gettext('Firewalls that know it')?></dt><dd><?=($ov['addr'] !== '') ? htmlspecialchars(sprintf(gettext('%1$d of %2$d'), $ov['known'], $ov['total'])) . ' <span class="fs-muted small">' . gettext('(firewalls on System API level 13 learn it within a minute, also ones that join later)') . '</span>' : '<span class="fs-muted">-</span>'?></dd>
		</dl>
<?php endif; ?>
		<div class="fs-fleet-settings">
<?php
	$sb_select('takeover', gettext('Take over'), array_map('gettext', FLEET_STANDBY_TAKEOVER), $ov['takeover'],
	    gettext('By hand: you promote the standby when this controller is gone. Automatically: the standby promotes itself when this controller has not answered for the time below. Automatic is faster, but if only the link between the two servers breaks, both run for a while until one sees the other; the firewalls then follow the newer one.'));
	$sb_select('auto_minutes', gettext('Automatic takeover after'), array_combine(FLEET_STANDBY_AUTO_MINUTES, array_map(function ($m) { return sprintf(gettext('%d minutes'), $m); }, FLEET_STANDBY_AUTO_MINUTES)), $ov['auto_minutes'],
	    gettext('How long this controller must be silent before the standby takes over (only with automatic takeover).'));
	$sb_select('interval', gettext('New copy every'), array_combine(FLEET_STANDBY_INTERVALS, array_map(function ($m) { return sprintf(gettext('%d minutes'), $m); }, FLEET_STANDBY_INTERVALS)), $ov['interval'],
	    gettext('At most this much recent history (activity, status) is missing after a takeover. Firewalls, groups and settings are in every copy.'));
?>
		</div>
	</div>
	<div class="panel-footer d-flex gap-2 flex-wrap">
<?php if ($ov['role'] === 'primary'): ?>
		<button class="btn btn-primary" type="submit" name="standby_action" value="save"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
		<button class="btn btn-outline-secondary" type="submit" name="standby_action" value="pair"><i class="fa-solid fa-key icon-embed-btn" aria-hidden="true"></i><?=gettext('New pairing code')?></button>
		<button class="btn btn-outline-danger ms-auto" type="submit" name="standby_action" value="remove"><i class="fa-solid fa-link-slash icon-embed-btn" aria-hidden="true"></i><?=gettext('Remove the standby')?></button>
<?php else: ?>
		<button class="btn btn-primary" type="submit" name="standby_action" value="pair"><i class="fa-solid fa-key icon-embed-btn" aria-hidden="true"></i><?=gettext('Turn on and make a pairing code')?></button>
<?php endif; ?>
	</div>
</div>
</form>
<?php elseif ($sb_role === 'standby'): $sp = fleet_standby_pairing(); $ss = fleet_standby_state(); $snap = (array)($ss['snapshot'] ?? array()); ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('This server is the standby')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=gettext('It keeps a verified, encrypted copy of the Fleet controller and can take over. It does not manage firewalls while it is the standby.')?></p>
		<dl class="fs-fleet-facts mb-3">
			<dt><?=gettext('Primary controller')?></dt><dd><?=htmlspecialchars(fleet_standby_url_host($sp['url']))?></dd>
			<dt><?=gettext('Last fetch')?></dt><dd><?=empty($ss['last_error']) ? fs_badge('pass', gettext('Up to date')) . ' ' . htmlspecialchars($sb_ago((int)($ss['last_ok'] ?? 0))) :
			    fs_badge('warn', gettext('Failing')) . ' <span class="fs-fleet-problem">' . htmlspecialchars($ss['last_error']) . '</span> <span class="fs-muted small">' . htmlspecialchars(sprintf(gettext('last good %s'), $sb_ago((int)($ss['last_ok'] ?? 0)))) . '</span>'?></dd>
			<dt><?=gettext('Copy')?></dt><dd><?=!empty($snap) ? htmlspecialchars(sprintf(gettext('Controller as of %1$s: %2$d firewalls, %3$d groups'), date('Y-m-d H:i', (int)$snap['created']), (int)($snap['boxes'] ?? 0), (int)($snap['groups'] ?? 0))) : '<span class="fs-muted">' . gettext('none yet') . '</span>'?></dd>
			<dt><?=gettext('Take over')?></dt><dd><?=(($ss['takeover'] ?? 'manual') === 'auto') ? htmlspecialchars(sprintf(gettext('Automatically, after %d minutes without the primary'), (int)($ss['auto_minutes'] ?? 15))) : gettext('By hand (below)')?> <span class="fs-muted small"><?=gettext('(set on the primary)')?></span></dd>
			<dt><?=gettext('This server\'s address')?></dt><dd><?=htmlspecialchars((string)$sp['own_addr'])?></dd>
		</dl>
		<form method="post" action="?tab=settings&amp;view=standby" class="d-flex gap-2 flex-wrap">
			<button class="btn btn-outline-secondary" type="submit" name="standby_action" value="pull"><i class="fa-solid fa-rotate icon-embed-btn" aria-hidden="true"></i><?=gettext('Fetch now')?></button>
			<button class="btn btn-outline-secondary" type="submit" name="standby_action" value="leave"><i class="fa-solid fa-link-slash icon-embed-btn" aria-hidden="true"></i><?=gettext('Stop being the standby')?></button>
		</form>
	</div>
</div>
<?php if (!empty($snap)): ?>
<form method="post" action="?tab=settings&amp;view=standby">
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Promote to controller')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=gettext('This server becomes the Fleet controller from the copy: same keys and tunnel, its own address. Firewalls move here by themselves within a few minutes. If the old primary comes back, it sees it was replaced and becomes the standby.')?></p>
		<label class="form-check"><input class="form-check-input" type="checkbox" name="confirm_down" value="1" required/> <span class="form-check-label"><?=gettext('The primary controller is down or switched off.')?></span></label>
	</div>
	<div class="panel-footer"><button class="btn btn-danger" type="submit" name="standby_action" value="promote"><i class="fa-solid fa-crown icon-embed-btn" aria-hidden="true"></i><?=gettext('Promote to controller')?></button></div>
</div>
</form>
<?php endif; ?>
<?php else: ?>
<form method="post" action="?tab=settings&amp;view=standby">
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Make this server the standby')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=gettext('A standby keeps a copy of an existing Fleet controller and can take over. Make a pairing code on the controller (Fleet > Settings > Standby server) and paste it here. To run this server as a controller of its own instead, use the Controller section.')?></p>
		<div class="fs-fleet-settings">
			<div class="fs-fleet-field"><label class="form-label" for="sb-code"><?=gettext('Pairing code')?></label>
				<textarea class="form-control fs-mono" id="sb-code" name="code" rows="3" required placeholder="FSB1-..."><?=htmlspecialchars((string)($_POST['code'] ?? ''))?></textarea></div>
			<div class="fs-fleet-field"><label class="form-label" for="sb-addr"><?=gettext('Address firewalls use to reach this server')?></label>
				<input class="form-control" id="sb-addr" name="own_addr" required value="<?=htmlspecialchars((string)($_POST['own_addr'] ?? ''))?>" placeholder="fleet2.example.net" aria-describedby="sb-addr-help"/>
				<div id="sb-addr-help" class="fs-fleet-hint"><?=gettext('A public IP address or DNS name. Firewalls are told about it now and use it if this server takes over; it needs the same tunnel and enrollment ports open as the controller.')?></div></div>
		</div>
	</div>
	<div class="panel-footer"><button class="btn btn-primary" type="submit" name="standby_action" value="join"><i class="fa-solid fa-clone icon-embed-btn" aria-hidden="true"></i><?=gettext('Become the standby')?></button></div>
</div>
</form>
<?php endif; ?>
<?php elseif ($set_view !== 'controller'): ?>
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
<script src="/fleet/assets/fleet-naming.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-naming.js')?>"></script>
<?php include('foot.inc');
