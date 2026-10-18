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

$tab = (($_REQUEST['tab'] ?? '') === 'settings') ? 'settings' : 'firewalls';
/* Same trail as the other Fleet pages. */
$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), ($tab === 'settings') ? gettext('Settings') : gettext('Firewalls'));
$s = fleet_ctl_settings();
$who = (string)($_SESSION['Username'] ?? 'admin');
$input_errors = array();
$savemsg = null;
$new_invite = null;
$inv_steps = array('who' => gettext('Name and access'), 'how' => gettext('How it connects'), 'valid' => gettext('Validity'), 'review' => gettext('Review'));
$new_name = null;
$standby_code = null;
$setup_done = false;

/* New key: revoke an open invitation and make it again with the same settings (the key is shown only once). */
if (isset($_POST['reissue']) && $s['enable']) {
	$old = fleet_db()->prepare("SELECT * FROM invitations WHERE token_id = ? AND state = 'open'");
	$old->execute(array((string)$_POST['reissue']));
	$old = $old->fetch();
	if ($old) {
		fleet_invite_revoke((string)$old['token_id'], $who);
		$_POST = array('invite' => '1', 'role' => (string)$old['role'], 'label' => (string)$old['label'], 'via' => (string)($old['via'] ?? 'tunnel'), 'via_iface' => (string)($old['via_iface'] ?? ''),
		    'naming_group' => (string)(int)($old['group_id'] ?? 0), 'hostname' => (string)($old['hostname'] ?? ''),
		    'hours' => (string)max(1, (int)round(((int)$old['expires'] - (int)$old['created']) / 3600)));
	}
}

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
	/* The connection points: interface, enrollment port and (optional) the address firewalls use there. */
	$points = array();
	foreach ((array)($_POST['points'] ?? array()) as $pi => $pp) {
		$pif = (string)($pp['iface'] ?? '');
		if (($pif === '') || ((string)($_POST['point_remove'] ?? '') === (string)$pi)) {
			continue;
		}
		$pport = trim((string)($pp['port'] ?? ''));
		$paddr = trim((string)($pp['address'] ?? ''));
		if (($pif !== 'tailscale') && !fleet_conn_iface_ok($pif)) {
			$input_errors[] = gettext('Choose an interface for each connection point.');
		} elseif (isset($points[$pif])) {
			$input_errors[] = sprintf(gettext('%s is used twice: one connection point per interface.'), $pif);
		} elseif (!ctype_digit($pport) || ((int)$pport < 1) || ((int)$pport > 65535)) {
			$input_errors[] = gettext('Ports are numbers from 1 to 65535.');
		} elseif (($paddr !== '') && !fleet_ctl_address_ok($paddr)) {
			$input_errors[] = sprintf(gettext('"%s" is not a host name or IP address (the port has its own field).'), $paddr);
		} else {
			$points[$pif] = array('iface' => $pif, 'port' => (int)$pport, 'address' => $paddr);
		}
	}
	/* The first-run guide's "also over Tailscale". */
	if (!empty($_POST['ts_point']) && !isset($points['tailscale'])) {
		$points['tailscale'] = array('iface' => 'tailscale', 'port' => 8443, 'address' => '');
	}
	$post = array_merge(array_diff_key((array)config_get_path('installedpackages/fleet/config/0', array()), array('points' => 1)), array(
	    'enable' => !empty($_POST['enable']) ? 'on' : '', 'points' => json_encode(array_values($points)), 'wg_port' => (string)($_POST['wg_port'] ?? ''),
	    'rules_manual' => !empty($_POST['rules_manual']) ? 'on' : ''));
	$check = fleet_ctl_settings_from($post);
	$setup_first = !empty($_POST['setup_guide']);
	if ($check['enable'] && empty($points)) {
		$input_errors[] = gettext('Add at least one connection point: where firewalls reach this controller.');
	}
	if ((string)$check['wg_port'] !== $post['wg_port']) {
		$input_errors[] = gettext('Ports are numbers from 1 to 65535.');
	}
	if (empty($input_errors)) {
		config_set_path('installedpackages/fleet/config/0', $post);
		write_config(gettext('FreeSense Fleet settings saved.'));
		$problems = fleet_sync_config();
		$s = fleet_ctl_settings();
		if (empty($problems)) {
			$savemsg = $s['enable'] ? gettext('Saved. FreeSense Fleet is running.') : gettext('Saved. FreeSense Fleet is stopped.');
			$setup_done = $setup_first && $s['enable'];
			/* The guide's "set up Tailscale here": install, log in, then add the tailnet as a connection point. */
			if ($s['enable'] && !empty($_POST['ts_setup'])) {
				try {
					$ts_addr = fleet_ts_controller_setup((string)($_POST['ts_api_token'] ?? ''), $who);
					if (!isset($points['tailscale'])) {
						$points['tailscale'] = array('iface' => 'tailscale', 'port' => 8443, 'address' => '');
						$post['points'] = json_encode(array_values($points));
						config_set_path('installedpackages/fleet/config/0', $post);
						write_config(gettext('FreeSense Fleet: Tailscale added as a connection point.'));
					}
					$problems = fleet_sync_config();
					$s = fleet_ctl_settings();
					$savemsg .= ' ' . sprintf(gettext('This controller is in the tailnet at %s.'), $ts_addr);
					$input_errors = array_merge($input_errors, $problems);
				} catch (RuntimeException $e) {
					$input_errors[] = gettext('Fleet runs, but Tailscale was not set up: ') . $e->getMessage();
				}
			}
		} else {
			$input_errors = array_merge($input_errors, $problems);
		}
	}
} elseif (isset($_POST['selfcheck_fix']) && $s['enable']) {
	$tab = 'settings';
	$_GET['view'] = 'selfcheck';
	if ($_POST['selfcheck_fix'] === 'rules') {
		fleet_access_reload();
		$savemsg = gettext('Fleet\'s firewall rules and aliases were written again and the filter reloaded.');
	} elseif ($_POST['selfcheck_fix'] === 'restart') {
		$problems = fleet_sync_config();
		$savemsg = empty($problems) ? gettext('The tunnel and the enrollment endpoint were started again.') : null;
		$input_errors = array_merge($input_errors, $problems);
	}
} elseif (($_POST['invite'] ?? false) && $s['enable']) {
	try {
		$via = (string)($_POST['via'] ?? 'tunnel');
		$via_iface = (string)($_POST['via_iface'] ?? '');
		$ttl = 3600 * max(1, min(720, (int)($_POST['hours'] ?? fleet_opt('invite_hours'))));
		$authority = fleet_invite_authority($s, $via, $via_iface);
		$invite_ip = trim((string)($_POST['public_ip'] ?? ''));
		if (($invite_ip !== '') && (fleet_access_cidr($invite_ip) === null)) {
			throw new InvalidArgumentException(gettext('The firewall\'s public address must be an IP address or network.'));
		}
		$inv_label = trim((string)($_POST['label'] ?? ''));
		$new_invite = fleet_invite_create((string)($_POST['role'] ?? 'monitor'), $inv_label, $ttl, $who, $authority, time(), $via,
		    function (string $tid) use ($inv_label, $ttl, $who) { return fleet_ts_authkey_mint($inv_label, $ttl, $who, $tid); }, $via_iface);
		if ($invite_ip !== '') {
			fleet_access_invite_ip($new_invite[2], $invite_ip, $inv_label, $new_invite[3]);
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
} elseif (isset($_POST['access_action']) && $s['enable']) {
	/* Settings > Access: who may reach the public ports, the allowed list, blocks and the reachability check. */
	$tab = 'settings';
	$acc = fleet_access();
	switch ((string)$_POST['access_action']) {
	case 'save':
		$acc = array('enroll' => (string)($_POST['enroll'] ?? 'any'), 'tunnel' => (string)($_POST['tunnel'] ?? 'any'), 'firewalls' => !empty($_POST['firewalls']),
		    'block' => !empty($_POST['block']), 'block_after' => (int)($_POST['block_after'] ?? 5), 'block_minutes' => (int)($_POST['block_minutes'] ?? 60)) + $acc;
		fleet_access_save($acc, $who, sprintf('Access: enrollment %s, tunnel %s', $acc['enroll'] === 'list' ? 'allowed list' : 'anyone', $acc['tunnel'] === 'list' ? 'allowed list' : 'anyone'));
		$savemsg = gettext('Saved. The rules are in place within a few seconds.');
		break;
	case 'add':
		$c = fleet_access_cidr((string)($_POST['cidr'] ?? ''));
		if ($c === null) {
			$input_errors[] = gettext('Enter an IP address or a network (like 203.0.113.0/24).');
			break;
		}
		$acc['entries'][] = array('cidr' => $c, 'note' => trim((string)($_POST['note'] ?? '')), 'added' => time());
		fleet_access_save($acc, $who, "Access: {$c} allowed");
		$savemsg = sprintf(gettext('%s is allowed.'), $c);
		break;
	case 'remove':
		$c = (string)($_POST['cidr'] ?? '');
		$acc['entries'] = array_values(array_filter($acc['entries'], function ($e) use ($c) { return $e['cidr'] !== $c; }));
		fleet_access_save($acc, $who, "Access: {$c} removed from the allowed list");
		$savemsg = sprintf(gettext('%s was removed from the allowed list.'), $c);
		break;
	case 'open':
		$m = in_array((int)($_POST['open_minutes'] ?? 60), FLEET_ACCESS_OPEN_MINUTES, true) ? (int)$_POST['open_minutes'] : 60;
		$acc['open_until'] = time() + 60 * $m;
		fleet_access_save($acc, $who, "Access: the enrollment port is open to anyone for {$m} minutes");
		$savemsg = sprintf(gettext('The enrollment port is open to anyone for %d minutes; it closes by itself.'), $m);
		break;
	case 'close':
		$acc['open_until'] = 0;
		fleet_access_save($acc, $who, 'Access: open for joining was closed');
		$savemsg = gettext('Closed: only the allowed list reaches the enrollment port.');
		break;
	case 'unblock':
		fleet_access_unblock((string)($_POST['ip'] ?? ''), $who);
		$savemsg = sprintf(gettext('%s is unblocked.'), (string)($_POST['ip'] ?? ''));
		break;
	case 'check':
		fleet_access_check(time());
		break;
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
		<span class="fs-fleet-area-actions"><a class="btn btn-sm btn-primary" href="?view=invite&amp;add=1"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add firewall')?></a>
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
<?php
	/* Internet connectivity (an option): state and quality over 24 hours under the firewall's state. */
	$inet_rows = fleet_inet_now();
	$inet_q = empty($inet_rows) ? array() : fleet_inet_stats(86400, time());
	$inet_badge = array('degraded' => 'warn', 'down' => 'block');
	foreach ($rows as $b): list($bs, $bl) = $sbadge[$b['state']]; ?>
		<tr><td><a href="/fleet/fleet_box.php?id=<?=urlencode($b['id'])?>"><strong><?=htmlspecialchars($b['label'])?></strong></a>
				<div class="fs-muted small fs-mono"><?=htmlspecialchars($b['host'] . ' ' . $b['overlay'])?></div></td>
			<td><?=fs_badge($bs, $bl)?><?=($b['problem'] !== '') ? '<div class="fs-muted small">' . htmlspecialchars(mb_strimwidth($b['problem'], 0, 60, '...')) . '</div>' : ''?>
<?php if (isset($inet_rows[$b['id']])): $ir = $inet_rows[$b['id']]; $iq = $inet_q[$b['id']]['score'] ?? null; ?>
				<div class="small fs-fleet-inet-cell"><a href="/fleet/fleet_box.php?id=<?=urlencode($b['id'])?>&amp;view=stats&amp;section=internet" title="<?=gettext('Internet: quality over 24 hours, then loss and latency now')?>"><i class="fa-solid fa-globe" aria-hidden="true"></i></a>
					<?=isset($inet_badge[$ir['state']]) ? fs_badge($inet_badge[$ir['state']], gettext(FLEET_INET_STATES[$ir['state']])) : ''?> <?=fleet_inet_score_badge($iq)?>
					<span class="fs-muted"><?=htmlspecialchars(fleet_inet_text($ir))?></span></div>
<?php endif; ?></td>
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
	/* "Change the group" in the dashboard menu links here with ?edit=<id>: open that group's modal. */
	if (($reopen === null) && isset($_GET['edit'])) {
		foreach ($groups as $grp) {
			if ((int)$grp['id'] === (int)$_GET['edit']) {
				$reopen = array('group_id' => (string)$grp['id'], 'group_name' => $grp['name'], 'group_description' => $grp['description'],
				    'group_window' => (string)(int)$grp['window_id'], 'group_color' => fleet_group_color((string)$grp['color']),
				    'naming_pattern' => (string)($grp['naming_pattern'] ?? ''), 'naming_domain' => (string)($grp['naming_domain'] ?? ''));
				break;
			}
		}
	}
	$new_fill = array('group_window' => '0', 'group_color' => fleet_group_color((string)((count($groups) % 8) + 1)));
?>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Groups')?> <span class="fs-count"><?=count($groups)?></span></h2>
		<button type="button" class="btn btn-sm btn-primary" data-fs-modal="#group-modal" data-fs-modal-title="<?=gettext('Add a group')?>" data-fs-fill="<?=htmlspecialchars(json_encode($new_fill))?>"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add group')?></button></div>
<?php if (empty($groups)): ?>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=gettext('No groups yet. Group firewalls by place, customer or role, for example Denmark, Retail or Canary. Policies, backups and updates can then target a group.')?></p></div>
<?php else: ?>
	<div class="panel-body fs-fleet-pad">
		<form method="get" class="fs-fleet-filterbar" role="search" data-fleet-filters><script src="/fleet/assets/fleet-list.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-list.js')?>" defer></script>
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
		<tr><td colspan="6" class="fs-muted"><?=gettext('No group matches.')?> <a href="?view=groups"><?=gettext('Clear the search')?></a></td></tr>
<?php endif; ?>
<?php foreach ($shown as $grp): ?>
		<tr><td><span class="fs-fleet-group fs-fleet-group-name" style="--fs-fleet-group: var(--fs-series-<?=htmlspecialchars(fleet_group_color((string)$grp['color']))?>)"><?=htmlspecialchars($grp['name'])?></span></td>
			<td><?=($grp['description'] !== '') ? htmlspecialchars($grp['description']) : '<span class="fs-muted">-</span>'?></td>
			<td><?=isset($win_names[(int)$grp['window_id']]) ? htmlspecialchars($win_names[(int)$grp['window_id']]) : '<span class="fs-muted">-</span>'?></td>
			<td class="fs-mono small"><?=((($grp['naming_pattern'] ?? '') . ($grp['naming_domain'] ?? '')) === '') ? '<span class="fs-muted">-</span>' :
			    htmlspecialchars((($grp['naming_pattern'] !== '') ? $grp['naming_pattern'] : '*') . (($grp['naming_domain'] !== '') ? '.' . $grp['naming_domain'] : ''))?></td>
			<td><?=((int)$grp['members'] === 0) ? '<span class="fs-muted">0</span>' : '<a class="fs-fleet-inline-link" href="/fleet/fleet_dashboard.php?group=' . (int)$grp['id'] . '">' . (int)$grp['members'] . '</a>'?></td>
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
	<div class="panel-footer small fs-muted"><?=gettext('A firewall can be in several groups. Deleting a group never changes its firewalls; a group that a policy, backup set or update ring uses cannot be deleted. The controller itself is not managed by Fleet and is in no group.')?></div>
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

<?php if ($new_invite !== null): list($link, $key, $tid, $expires, $inv_tskey) = $new_invite; $inv_method = fleet_invite_link_parse($link)['method'] ?? 'tunnel';
	fs_modal_form_begin('invite-done', sprintf(gettext('Invitation for %s'), trim((string)($_POST['label'] ?? ''))), '', array(), array());
	fs_stepper($inv_steps + array('done' => gettext('Copy')), 'done', array(), gettext('Add a firewall'));
?>
	<p class="fs-fleet-lead"><?=sprintf(gettext('Valid until %s. This is shown only now: copy it and give it to whoever sets up the firewall. It holds the join key, so send it the way you would send a password.'), htmlspecialchars(date('Y-m-d H:i', $expires)))?></p>
<?php if (!empty($new_name[0]) || !empty($new_name[1])): ?>
	<p><i class="fa-solid fa-tag" aria-hidden="true"></i> <?=gettext('It will be named')?> <strong class="fs-mono"><?=htmlspecialchars(trim(($new_name[0] ?: '*') . (($new_name[1] !== '') ? '.' . $new_name[1] : '')))?></strong> <?=gettext('when it joins.')?></p>
<?php endif; ?>
	<div class="fs-fleet-paste">
		<span class="fs-fleet-secret-label"><?=gettext('Copy for the firewall')?></span>
		<pre id="fleet-paste" class="fs-fleet-paste-text"><?=htmlspecialchars(fleet_invite_paste($link, $key))?></pre>
		<button type="button" class="btn btn-primary" data-fs-copy="#fleet-paste"><i class="fa-regular fa-clone icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy')?></button>
	</div>
	<p class="fs-fleet-hint"><?=htmlspecialchars(array(
		'tunnel' => gettext('It connects over the Fleet tunnel (WireGuard), which the firewall sets up by itself.'),
		'tailscale' => gettext('It connects over Tailscale: the text holds a one-time, pre-approved Tailscale key, sealed with the join key. The firewall installs Tailscale and logs in by itself; no public port is needed.'),
		'direct' => gettext('It joins over the Fleet tunnel, then the controller reaches it directly on the internal network; the tunnel stays as the fallback.'),
	)[$inv_method] ?? '')?></p>
	<h3 class="h6 mt-3"><?=gettext('On the new firewall')?></h3>
	<ol class="fs-fleet-steps">
		<li><?=gettext('Open System > Central Management > Add to fleet and paste the text.')?></li>
		<li><?=gettext('It checks this controller, connects and shows a 6-digit code. Approve it on this page when the same code appears under Waiting for approval.')?></li>
	</ol>
	<details class="fs-fleet-manual"><summary><?=gettext('Without the web interface')?></summary>
		<p class="mb-1"><?=sprintf(gettext('At the console choose option 17, or run %s, and type the join key when asked:'), '<code>freesense-join join \'&lt;link&gt;\'</code>')?></p>
		<div class="fs-fleet-secret"><span class="fs-fleet-secret-label"><?=gettext('Join link')?></span><code id="fleet-link" class="fs-fleet-secret-value"><?=htmlspecialchars($link)?></code>
			<button type="button" class="btn btn-sm btn-outline-secondary" data-fs-copy="#fleet-link"><i class="fa-regular fa-clone icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy link')?></button></div>
		<div class="fs-fleet-secret"><span class="fs-fleet-secret-label"><?=gettext('Join key')?></span><code id="fleet-key" class="fs-fleet-secret-value fs-fleet-key"><?=htmlspecialchars($key)?></code>
			<button type="button" class="btn btn-sm btn-outline-secondary" data-fs-copy="#fleet-key"><i class="fa-regular fa-clone icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy key')?></button></div>
	</details>
<?php
	/* Nothing to send: the invitation exists; this only closes the window. */
	echo '</div><div class="modal-footer"><button type="button" class="btn btn-primary" data-bs-dismiss="modal">' . gettext('Done') . '</button></div></form></div></div></div>';
endif;
?>

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
	<p class="fs-fleet-lead"><?=gettext('A short guide makes a one-time invitation: who it is for, how it connects and how long it is valid. You then paste it on the new firewall.')?></p>
	<p><button type="button" class="btn btn-primary" data-fs-modal="#invite-modal"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add a firewall')?></button></p>
</section>
<?php
	list($ts_join_problems, $ts_join_address) = fleet_ts_join_ready();
	$all_ifaces = get_configured_interface_with_descr();
	$inv_ifaces = array();
	foreach ($s['points'] as $ip) {
		if (!in_array($ip['iface'], array('wan', 'tailscale'), true) && isset($all_ifaces[$ip['iface']])) {
			$inv_ifaces[$ip['iface']] = $all_ifaces[$ip['iface']];
		}
	}
	$ts_point = fleet_ctl_point($s, 'tailscale');
	$net_point = ($s['primary'] !== '') && ($s['primary'] !== 'tailscale');
	$ts_ok = ($ts_point !== null) && empty($ts_join_problems);
	$inv_rec = fleet_invite_recommend($ts_ok, $net_point && ($s['public_host'] !== ''), !empty($inv_ifaces));
	$inv_ways = array(
		'tunnel' => array(gettext('Fleet tunnel (WireGuard)'), $net_point ? sprintf(gettext('Over the internet, through the WAN connection point: the firewall reaches this controller at %s, then keeps a WireGuard tunnel to it.'), fleet_hostport($s['public_host'], $s['enroll_port'])) :
		    gettext('Add a connection point firewalls reach over the internet (Settings > Controller).'), $net_point),
		'tailscale' => array(gettext('Tailscale'), ($ts_point === null) ? gettext('Add a Tailscale connection point (Settings > Controller).') : (empty($ts_join_problems) ?
		    sprintf(gettext('No public port: the firewall installs Tailscale and joins this controller at %s in the tailnet.'), $ts_join_address) : implode(' ', array_map('gettext', $ts_join_problems))), $ts_ok),
		'direct' => array(gettext('Direct'), empty($inv_ifaces) ? gettext('Only for a network shared with the firewall (LAN, MPLS, VPN), not for WAN: a WAN connection point is the Fleet tunnel above. Add an internal connection point in Settings > Controller.') :
		    gettext('The firewall and this controller share an internal network (LAN, MPLS, VPN): it joins there, no internet port needed.'), !empty($inv_ifaces)),
	);
	if (!$inv_ways[$inv_rec][2]) {
		$inv_rec = (string)(array_keys(array_filter($inv_ways, function ($w) { return $w[2]; }))[0] ?? $inv_rec);
	}
?>
<?php
	/* After an error the guide opens again on its review, with what was typed. */
	$inv_reopen = (isset($_POST['invite']) && ($new_invite === null) && !empty($input_errors)) ? array_intersect_key($_POST, array_flip(array('label', 'role', 'naming_group', 'site', 'hostname', 'via', 'via_iface', 'public_ip', 'hours'))) :
	    ((($_GET['add'] ?? '') === '1') ? array() : null);
	fs_modal_form_begin('invite-modal', gettext('Add a firewall'), '?view=invite', array('invite' => '1'), $inv_reopen);
	fs_steps_begin($inv_steps, ($inv_reopen !== null && !empty($inv_reopen)) ? 'review' : null, gettext('Add a firewall'));
	$inv_acc = fleet_access();
	$name_groups = fleet_groups_all();
	fs_step_begin('who', gettext('A name you will recognise, and what this controller may do on the firewall.'));
?>
	<div class="mb-3"><label class="form-label" for="label"><?=gettext('Name')?></label>
		<input class="form-control" id="label" name="label" placeholder="<?=gettext('Copenhagen office')?>" required maxlength="80" data-review="label"/></div>
	<fieldset class="mb-3"><legend class="form-label"><?=gettext('Access')?></legend>
		<label class="form-check"><input class="form-check-input" type="radio" name="role" value="monitor" checked data-review="role" data-review-text="<?=gettext('Monitor only')?>"/>
			<span class="form-check-label"><strong><?=gettext('Monitor only')?></strong> <span class="fs-fleet-hint d-block"><?=gettext('This controller reads status and backups.')?></span></span></label>
		<label class="form-check"><input class="form-check-input" type="radio" name="role" value="managed" data-review="role" data-review-text="<?=gettext('Managed')?>"/>
			<span class="form-check-label"><strong><?=gettext('Managed')?></strong> <span class="fs-fleet-hint d-block"><?=gettext('It may also change the configuration: templates, users, updates.')?></span></span></label>
	</fieldset>
<?php if (!empty($name_groups)): ?>
	<div class="row g-2">
		<div class="col-sm-5"><label class="form-label" for="naming_group"><?=gettext('Group')?></label>
			<select class="form-select" id="naming_group" name="naming_group" data-review="naming_group">
				<option value="0"><?=gettext('None')?></option>
<?php foreach ($name_groups as $ng): ?>
				<option value="<?=(int)$ng['id']?>" data-pattern="<?=htmlspecialchars((string)($ng['naming_pattern'] ?? ''))?>" data-domain="<?=htmlspecialchars((string)($ng['naming_domain'] ?? ''))?>"
				    data-next="<?=htmlspecialchars((string)fleet_naming_peek((int)$ng['id'], array()))?>"><?=htmlspecialchars($ng['name'] . ((($ng['naming_pattern'] ?? '') !== '') ? ' (' . $ng['naming_pattern'] . ')' : ''))?></option>
<?php endforeach; ?>
			</select></div>
		<div class="col-sm-3"><label class="form-label" for="site"><?=gettext('Site')?></label>
			<input class="form-control" id="site" name="site" maxlength="40" placeholder="cph" data-review="site"/></div>
		<div class="col-sm-4"><label class="form-label" for="hostname"><?=gettext('Hostname')?></label>
			<input class="form-control fs-mono" id="hostname" name="hostname" maxlength="63" placeholder="<?=gettext('From the group')?>" data-review="hostname"/></div>
		<div class="col-12 form-text"><?=gettext('The firewall joins this group and is named by it. All optional.')?></div>
	</div>
<?php endif; ?>
<?php
	fs_step_end();
	fs_step_begin('how', gettext('How the new firewall reaches this controller. Methods without a connection point are greyed out.'));
?>
	<fieldset class="fs-fleet-ways"><legend class="visually-hidden"><?=gettext('How the new firewall connects')?></legend>
<?php foreach ($inv_ways as $wk => list($wt, $wh, $wok)): ?>
		<label class="fs-fleet-way<?=$wok ? '' : ' is-off'?>"><input class="form-check-input" type="radio" name="via" value="<?=$wk?>"<?=($wk === $inv_rec) ? ' checked' : ''?><?=$wok ? '' : ' disabled'?> required
		    data-review="via" data-review-text="<?=htmlspecialchars($wt)?>"/>
			<span><strong><?=htmlspecialchars($wt)?></strong><?=($wk === $inv_rec) ? ' ' . fs_badge('pass', gettext('Recommended')) : ''?><span class="fs-fleet-hint d-block"><?=htmlspecialchars($wh)?></span></span></label>
<?php endforeach; ?>
<?php if (!empty($inv_ifaces)): ?>
		<div class="mt-2" data-fleet-direct><label class="form-label" for="via_iface"><?=gettext('Internal network (direct)')?></label>
			<select class="form-select" id="via_iface" name="via_iface" data-review="via_iface">
<?php foreach ($inv_ifaces as $ik => $idescr): ?>
				<option value="<?=htmlspecialchars($ik)?>"><?=htmlspecialchars($idescr . ' (' . (fleet_ctl_point_address(fleet_ctl_point($s, $ik)) ?: gettext('no address')) . ')')?></option>
<?php endforeach; ?>
			</select></div>
<?php endif; ?>
	</fieldset>
<?php
	fs_step_end();
	fs_step_begin('valid', gettext('An invitation works once, and only until it expires.'));
	$ttl_choices = array(1 => gettext('1 hour'), 24 => gettext('24 hours'), 168 => gettext('7 days'), 720 => gettext('30 days'));
	$ttl_default = fleet_opt('invite_hours');
	if (!isset($ttl_choices[$ttl_default])) {
		$ttl_choices[$ttl_default] = sprintf(gettext('%d hours'), $ttl_default);
		ksort($ttl_choices);
	}
?>
	<div class="mb-3"><label class="form-label" for="hours"><?=gettext('Valid for')?></label>
		<select class="form-select" id="hours" name="hours" data-review="hours">
<?php foreach ($ttl_choices as $h => $text): ?>
			<option value="<?=(int)$h?>"<?=($h === $ttl_default) ? ' selected' : ''?>><?=htmlspecialchars($text)?></option>
<?php endforeach; ?>
		</select></div>
	<div class="mb-3" data-fleet-public-ip><label class="form-label" for="public_ip"><?=gettext('Its public address')?> <span class="fs-muted small"><?=gettext('(optional)')?></span></label>
		<input class="form-control fs-mono" id="public_ip" name="public_ip" maxlength="45" placeholder="203.0.113.10" aria-describedby="public_ip-help" data-review="public_ip"/>
		<div id="public_ip-help" class="form-text"><?=($inv_acc['enroll'] === 'list') ? gettext('The enrollment port takes only the allowed list: this address is allowed until the invitation expires. Without it, open for joining in Settings > Access.') :
		    gettext('Allowed until the invitation expires, when the enrollment port takes only the allowed list (Settings > Access).')?></div></div>
<?php
	fs_step_end();
	fs_step_begin('review', gettext('Nothing is made until you select Create invitation.'));
?>
	<dl class="fs-fleet-tset" data-invite-review>
		<dt><?=gettext('Name')?></dt><dd data-show="label">-</dd>
		<dt><?=gettext('Access')?></dt><dd data-show="role">-</dd>
		<dt><?=gettext('Group')?></dt><dd data-show="naming_group"><?=gettext('None')?></dd>
		<dt><?=gettext('Site and hostname')?></dt><dd data-show="site_host">-</dd>
		<dt><?=gettext('Connects by')?></dt><dd data-show="via">-</dd>
		<dt><?=gettext('Valid for')?></dt><dd data-show="hours">-</dd>
		<dt data-review-public-ip><?=gettext('Its public address')?></dt><dd data-show="public_ip" data-review-public-ip>-</dd>
	</dl>
	<p class="fs-fleet-hint mb-0"><?=gettext('You get one text to paste on the new firewall. It is shown once.')?></p>
<?php
	fs_step_end();
	fs_steps_end();
	fs_modal_form_end(gettext('Create invitation'), '', '', 'fa-plus');
?>

<?php if (!empty($invites)): ?>
<section class="fs-fleet-block" aria-labelledby="open-title">
	<h2 id="open-title" class="fs-fleet-section-title"><?=gettext('Open invitations')?> <span class="fs-count"><?=count($invites)?></span></h2>
	<div class="table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Name')?></th><th><?=gettext('Access')?></th><th><?=gettext('Valid until')?></th><th><?=gettext('Wrong keys')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php foreach ($invites as $i): ?>
		<tr><td><?=htmlspecialchars($i['label'])?><?=' ' . fs_badge('neutral', array('tunnel' => gettext('Fleet tunnel'), 'tailscale' => gettext('Tailscale'), 'direct' => gettext('Direct'))[$i['via'] ?? 'tunnel'] ?? gettext('Fleet tunnel'))?></td><td><?=htmlspecialchars($role_name($i['role']))?></td>
			<td><?=htmlspecialchars(date('Y-m-d H:i', (int)$i['expires']))?></td>
			<td><?=((int)$i['failures'] > 0) ? fs_badge('warn', (int)$i['failures'] . ' / ' . fleet_opt('invite_failures')) : '<span class="fs-muted">0</span>'?></td>
			<td class="text-end text-nowrap"><form method="post" class="d-inline"><button class="btn btn-sm btn-link" name="reissue" value="<?=htmlspecialchars($i['token_id'])?>"
			    title="<?=gettext('Revoke this invitation and make a new link and key with the same settings')?>"><?=gettext('New key')?></button>
			    <button class="btn btn-sm btn-outline-secondary" name="revoke" value="<?=htmlspecialchars($i['token_id'])?>"><?=gettext('Revoke')?></button></form></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
</section>
<?php endif; ?>

<?php endif; ?>
<?php else:
	$set_view = fs_view_param(array_keys(FLEET_SETTINGS_SECTIONS), (string)($_POST['save_section'] ?? ((isset($_POST['access_action']) ? 'access' : ((isset($_POST['standby_action']) || (!$ready && (fleet_standby_role() === 'standby'))) ? 'standby' : 'controller')))));
	$set_labels = array_map('gettext', FLEET_SETTINGS_SECTIONS);
	/* Each section's heading carries its icon, like the other Fleet areas. */
	$set_icons = array('controller' => 'fa-server', 'monitoring' => 'fa-heart-pulse', 'actions' => 'fa-bell', 'backups' => 'fa-box-archive', 'updates' => 'fa-download',
	    'schedules' => 'fa-calendar-days', 'access' => 'fa-shield-halved', 'standby' => 'fa-clone', 'selfcheck' => 'fa-stethoscope', 'advanced' => 'fa-sliders');
	$stitle = function (string $text, string $view) use ($set_icons) {
		return '<i class="fa-solid ' . $set_icons[$view] . ' fs-fleet-title-icon" aria-hidden="true"></i>' . htmlspecialchars($text);
	};
	fs_view_switch($set_labels, $set_view);
	$set_leads = array(
		'controller' => gettext('Firewalls connect to this controller. They may be behind NAT: they start the connection, so only this controller needs to be reachable.'),
		'monitoring' => gettext('How often the controller asks each firewall for its status, and when a silent firewall counts as degraded or offline.'),
		'actions' => gettext('Reboots, backups and restores started from Fleet: how long results stay visible and when you are told.'),
		'backups' => gettext('Central backups of each firewall\'s configuration, taken every night and when it changes.'),
		'advanced' => gettext('Values you rarely need to change. The defaults suit most fleets.'),
		'selfcheck' => gettext('Everything firewalls need to reach and trust this controller, checked now. Where Fleet can repair something safely, there is a button.'),
		'access' => gettext('Firewalls reach this controller on two public ports. Fleet checks they answer from outside, and lets in anyone or only the allowed list.'),
		'standby' => gettext('A second FreeSense with the Fleet package keeps a verified, encrypted copy of this controller and can take over. Firewalls learn its address automatically, also ones that join later, and move to it by themselves when it takes over.'),
	);
?>
<?php if (($set_view === 'access') && $ready):
	$acc = fleet_access();
	$chk = json_decode((string)fleet_setting('access_check', '{}'), true) ?: array();
	$allowed = fleet_access_allowed_now(time());
	$blocked = array_filter(fleet_access_json('access_blocked'), function ($u) { return (int)$u > time(); });
	$manual = array_column($acc['entries'], 'cidr');
	$aq = trim((string)($_GET['aq'] ?? ''));
	$shown_allowed = array_filter($allowed, function ($why, $c) use ($aq) { return ($aq === '') || (stripos($c . ' ' . $why, $aq) !== false); }, ARRAY_FILTER_USE_BOTH);
	$open_left = $acc['open_until'] - time();
	$acc_sec = fs_view_param(array('exposure', 'allowed'), in_array((string)($_POST['access_action'] ?? ''), array('add', 'remove', 'unblock'), true) ? 'allowed' : 'exposure', 'section');
	echo '<div class="fs-fleet-subswitch">';
	fs_view_switch(array('exposure' => gettext('Exposure'), 'allowed' => sprintf(gettext('Allowed list (%d)'), count($allowed)) .
	    (empty($blocked) ? '' : ' · ' . sprintf(gettext('%d blocked'), count($blocked)))), $acc_sec, 'section');
	echo '</div>';
?>
<?php if ($acc_sec === 'exposure'): ?>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Can firewalls reach this controller?')?></h2>
		<form method="post" action="?tab=settings&amp;view=access&amp;section=exposure" class="ms-auto"><button class="btn btn-sm btn-outline-secondary" type="submit" name="access_action" value="check"><i class="fa-solid fa-satellite-dish icon-embed-btn" aria-hidden="true"></i><?=gettext('Check now')?></button></form></div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=htmlspecialchars($set_leads['access'])?></p>
<?php if (empty($chk)): ?>
		<p class="fs-muted"><?=gettext('Not checked yet. Check now: a firewall in the fleet tries the enrollment port from outside.')?></p>
<?php else:
	$probe = $chk['probe'] ?? null; ?>
		<dl class="fs-fleet-facts mb-3">
			<dt><?=gettext('Firewalls connect to')?></dt><dd class="fs-mono"><?=htmlspecialchars(fleet_hostport($chk['host'], (int)$chk['enroll_port']))?> <span class="fs-muted"><?=gettext('(enrollment, TCP)')?></span>, <?=htmlspecialchars(fleet_hostport($chk['host'], (int)$chk['wg_port']))?> <span class="fs-muted"><?=gettext('(tunnel, UDP)')?></span></dd>
			<dt><?=gettext('Public address')?></dt><dd><?php if ($chk['kind'] === 'local'): ?><?=fs_badge('pass', gettext('On this controller'))?> <?=gettext('Fleet opens the ports itself (the rules below).')?>
<?php elseif ($chk['kind'] === 'forward'): ?><?=fs_badge('info', gettext('Port forward'))?> <?=htmlspecialchars(sprintf(gettext('%1$s points to %2$s, which is not on this controller: a router in front forwards to it.'), $chk['host'], implode(', ', $chk['resolved'])))?>
<?php else: ?><?=fs_badge('warn', gettext('Does not resolve'))?> <?=htmlspecialchars(sprintf(gettext('%s has no address. Check the name in the Controller section.'), $chk['host']))?><?php endif; ?></dd>
			<dt><?=gettext('Enrollment port from outside')?></dt><dd><?php if ($probe === null): ?><span class="fs-muted"><?=gettext('No firewall could check it (it needs one online with System API level 14).')?></span>
<?php elseif (!empty($probe['open'])): ?><?=fs_badge('pass', gettext('Open'))?> <?=htmlspecialchars(sprintf(gettext('checked from %1$s%2$s, %3$d ms'), $probe['from'], ($probe['from_addr'] ?? '') !== '' ? ' (' . $probe['from_addr'] . ')' : '', (int)$probe['ms']))?>
<?php else: ?><?=fs_badge('block', gettext('Closed'))?> <?=htmlspecialchars(sprintf(gettext('from %1$s: %2$s'), $probe['from'], $probe['error']))?><?php endif; ?></dd>
			<dt><?=gettext('Tunnel port')?></dt><dd><?=($chk['tunnel_recent'] > 0) ? fs_badge('pass', gettext('In use')) . ' ' . htmlspecialchars(sprintf(gettext('%d firewalls connected in the last 5 minutes'), $chk['tunnel_recent'])) : '<span class="fs-muted">' . gettext('No firewall connected in the last 5 minutes (UDP cannot be probed; a joined firewall proves it).') . '</span>'?></dd>
			<dt><?=gettext('Checked')?></dt><dd class="small"><?=htmlspecialchars(date('Y-m-d H:i', (int)$chk['checked']))?></dd>
		</dl>
<?php if (($chk['kind'] === 'forward') || (($probe !== null) && empty($probe['open']))): ?>
		<div class="fs-fleet-review">
			<h3 class="fs-fleet-subtitle"><?=gettext('Open the ports on the router in front')?></h3>
			<ol class="mb-0">
				<li><?=htmlspecialchars(sprintf(gettext('On the router that owns %s, add two port forwards to this controller (%s):'), implode(', ', $chk['resolved'] ?: array($chk['host'])), implode(', ', array_slice($chk['local'], 0, 2))))?>
					<span class="fs-mono">TCP <?=(int)$chk['enroll_port']?></span> <?=gettext('and')?> <span class="fs-mono">UDP <?=(int)$chk['wg_port']?></span>.</li>
				<li><?=gettext('Keep the source as narrow as you can: the same allowed list as below, or the networks your firewalls are in.')?></li>
				<li><?=gettext('If that router is a FreeSense in this fleet, a NAT template does it: Templates > Port forwards.')?></li>
				<li><?=gettext('Check now again. The tunnel port is proven when a firewall joins.')?></li>
			</ol>
		</div>
<?php endif; ?>
<?php endif; ?>
	</div>
</div>

<form method="post" action="?tab=settings&amp;view=access&amp;section=exposure">
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=$stitle(gettext('Who may connect'), 'access')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<div class="fs-fleet-settings fs-fleet-settings--wide">
			<div class="fs-fleet-ports">
<?php foreach (array('enroll' => array(gettext('Enrollment port'), sprintf('TCP %d', $s['enroll_port']), gettext('New firewalls join here, and the standby controller fetches its copies.')),
	    'tunnel' => array(gettext('Tunnel port'), sprintf('UDP %d', $s['wg_port']), gettext('Joined firewalls keep their management tunnel here. WireGuard does not answer anyone without a firewall\'s key, so this port is invisible to scans; limit it only when every firewall has a fixed address (a firewall whose address changes is cut off until you allow the new one).'))) as $k => list($label, $port, $help)): ?>
			<fieldset class="fs-fleet-field"><legend class="form-label"><?=htmlspecialchars($label)?> <span class="fs-muted fs-mono small"><?=htmlspecialchars($port)?></span></legend>
				<label class="form-check"><input class="form-check-input" type="radio" name="<?=$k?>" value="list"<?=($acc[$k] === 'list') ? ' checked' : ''?>/> <span class="form-check-label"><?=gettext('Only the allowed list')?></span></label>
				<label class="form-check"><input class="form-check-input" type="radio" name="<?=$k?>" value="any"<?=($acc[$k] === 'any') ? ' checked' : ''?>/> <span class="form-check-label"><?=gettext('Anyone')?></span></label>
<?php if ($k === 'enroll'): ?>
				<div class="fs-fleet-note mt-1"><?=fs_badge('warn', gettext('Not recommended'))?> <?=gettext('"Anyone" leaves the enrollment port open to the whole internet. Wrong keys are blocked, but the allowed list is safer: open for joining only while a firewall joins.')?></div>
<?php endif; ?>
				<div class="fs-fleet-hint"><?=htmlspecialchars($help)?></div></fieldset>
<?php endforeach; ?>
			</div>
			<div class="form-check form-switch">
				<input class="form-check-input" type="checkbox" role="switch" id="acc-fw" name="firewalls"<?=$acc['firewalls'] ? ' checked' : ''?>/>
				<label class="form-check-label" for="acc-fw"><?=gettext('Allow the addresses firewalls connect from')?></label>
				<div class="fs-fleet-hint"><?=gettext('Fleet adds each joined firewall\'s public address to the list by itself, also the standby controller and the address given with an invitation.')?></div>
			</div>
			<div class="form-check form-switch">
				<input class="form-check-input" type="checkbox" role="switch" id="acc-block" name="block"<?=$acc['block'] ? ' checked' : ''?>/>
				<label class="form-check-label" for="acc-block"><?=gettext('Block addresses that try wrong keys')?></label>
			</div>
			<div class="d-flex gap-3 flex-wrap">
				<div class="fs-fleet-field"><label class="form-label" for="acc-after"><?=gettext('Block after')?></label>
					<select class="form-select fs-fleet-narrow" id="acc-after" name="block_after"><?php foreach (FLEET_ACCESS_BLOCK_AFTER as $n): ?><option value="<?=$n?>"<?=($n === $acc['block_after']) ? ' selected' : ''?>><?=htmlspecialchars(sprintf(gettext('%d wrong keys in 10 minutes'), $n))?></option><?php endforeach; ?></select></div>
				<div class="fs-fleet-field"><label class="form-label" for="acc-for"><?=gettext('Block for')?></label>
					<select class="form-select fs-fleet-narrow" id="acc-for" name="block_minutes"><?php foreach (FLEET_ACCESS_BLOCK_MINUTES as $m): ?><option value="<?=$m?>"<?=($m === $acc['block_minutes']) ? ' selected' : ''?>><?=htmlspecialchars(($m < 60) ? sprintf(gettext('%d minutes'), $m) : sprintf(gettext('%d hours'), $m / 60))?></option><?php endforeach; ?></select></div>
			</div>
		</div>
	</div>
	<div class="panel-footer d-flex gap-2 flex-wrap align-items-center">
<?php if ($open_left > 0): ?>
		<span><?=fs_badge('warn', sprintf(gettext('Open for joining: %d min left'), ceil($open_left / 60)))?></span>
		<button class="btn btn-outline-secondary" type="submit" name="access_action" value="close"><?=gettext('Close now')?></button>
<?php elseif ($acc['enroll'] === 'list'): ?>
		<span class="fs-muted small"><?=gettext('A firewall whose address you do not know:')?></span>
		<select class="form-select form-select-sm w-auto" name="open_minutes" aria-label="<?=gettext('How long')?>"><?php foreach (FLEET_ACCESS_OPEN_MINUTES as $m): ?><option value="<?=$m?>"<?=($m === 60) ? ' selected' : ''?>><?=htmlspecialchars(($m < 60) ? sprintf(gettext('%d minutes'), $m) : sprintf(gettext('%d hours'), $m / 60))?></option><?php endforeach; ?></select>
		<button class="btn btn-outline-secondary" type="submit" name="access_action" value="open"><i class="fa-solid fa-door-open icon-embed-btn" aria-hidden="true"></i><?=gettext('Open for joining')?></button>
<?php endif; ?>
		<button class="btn btn-primary ms-auto" type="submit" name="access_action" value="save"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
	</div>
</div>
</form>

<?php else: ?>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Allowed list')?> <span class="fs-count"><?=count($allowed)?></span></h2>
		<form method="get" class="ms-auto d-flex gap-2" data-fleet-filters><script src="/fleet/assets/fleet-list.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-list.js')?>" defer></script><input type="hidden" name="tab" value="settings"/><input type="hidden" name="view" value="access"/><input type="hidden" name="section" value="allowed"/>
			<input class="form-control form-control-sm" type="search" name="aq" value="<?=htmlspecialchars($aq)?>" placeholder="<?=gettext('Search address or reason')?>" aria-label="<?=gettext('Search the allowed list')?>"/></form></div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Address or network')?></th><th><?=gettext('Why')?></th><th class="text-end"></th></tr></thead>
		<tbody>
<?php foreach (array_slice($shown_allowed, 0, 200, true) as $c => $why): ?>
		<tr><td class="fs-mono"><?=htmlspecialchars((string)$c)?></td><td class="small"><?=htmlspecialchars($why)?></td>
			<td class="text-end"><?php if (in_array((string)$c, $manual, true)): ?><form method="post" action="?tab=settings&amp;view=access&amp;section=allowed"><input type="hidden" name="cidr" value="<?=htmlspecialchars((string)$c)?>"/><button class="btn btn-sm btn-link text-danger" type="submit" name="access_action" value="remove"><?=gettext('Remove')?></button></form><?php else: ?><span class="fs-muted small"><?=gettext('automatic')?></span><?php endif; ?></td></tr>
<?php endforeach; ?>
<?php if (empty($shown_allowed)): ?>
		<tr><td colspan="3" class="fs-muted"><?=($aq !== '') ? gettext('Nothing matches.') : gettext('Nothing is allowed yet. With "Only the allowed list", nobody can reach that port.')?></td></tr>
<?php endif; ?>
		</tbody></table></div>
	<form method="post" action="?tab=settings&amp;view=access&amp;section=allowed" class="panel-footer d-flex gap-2 flex-wrap align-items-end">
		<div class="fs-fleet-field mb-0"><label class="form-label" for="acc-cidr"><?=gettext('Address or network')?></label><input class="form-control fs-mono" id="acc-cidr" name="cidr" required placeholder="203.0.113.0/24"/></div>
		<div class="fs-fleet-field mb-0"><label class="form-label" for="acc-note"><?=gettext('Why')?></label><input class="form-control" id="acc-note" name="note" maxlength="80" placeholder="<?=gettext('Office internet')?>"/></div>
		<button class="btn btn-outline-secondary" type="submit" name="access_action" value="add"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Allow')?></button>
	</form>
</div>

<?php if (!empty($blocked)): ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Blocked after wrong keys')?> <span class="fs-count"><?=count($blocked)?></span></h2></div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Address')?></th><th><?=gettext('Until')?></th><th class="text-end"></th></tr></thead>
		<tbody>
<?php foreach ($blocked as $ip => $until): ?>
		<tr><td class="fs-mono"><?=htmlspecialchars((string)$ip)?></td><td class="small"><?=htmlspecialchars(date('Y-m-d H:i', (int)$until))?></td>
			<td class="text-end"><form method="post" action="?tab=settings&amp;view=access&amp;section=allowed"><input type="hidden" name="ip" value="<?=htmlspecialchars((string)$ip)?>"/><button class="btn btn-sm btn-outline-secondary" type="submit" name="access_action" value="unblock"><?=gettext('Unblock')?></button></form></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
</div>
<?php endif; ?>
<?php endif; ?>
<?php elseif ($set_view === 'standby'):
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
	<div class="panel-heading"><h2 class="panel-title"><?=$stitle(gettext('Standby server'), 'standby')?></h2></div>
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
	<div class="panel-heading"><h2 class="panel-title"><?=$stitle(gettext('This server is the standby'), 'standby')?></h2></div>
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
	<div class="panel-heading"><h2 class="panel-title"><?=$stitle(gettext('Make this server the standby'), 'standby')?></h2></div>
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
<?php elseif ($set_view === 'selfcheck'):
	$sc = fleet_selfcheck($s);
	$sc_badge = array('pass' => array('pass', gettext('OK')), 'warn' => array('warn', gettext('Check')), 'block' => array('block', gettext('Problem')), 'info' => array('neutral', gettext('Not checked')));
?>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=$stitle(gettext('Self-check'), 'selfcheck')?></h2>
		<form method="post" action="?tab=settings&amp;view=access&amp;section=exposure" class="ms-auto"><button class="btn btn-sm btn-outline-secondary" type="submit" name="access_action" value="check"><i class="fa-solid fa-satellite-dish icon-embed-btn" aria-hidden="true"></i><?=gettext('Test the ports from outside')?></button></form></div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=htmlspecialchars($set_leads['selfcheck'])?></p>
		<ul class="fs-fleet-checklist">
<?php foreach ($sc as $item): list($bk, $bt) = $sc_badge[$item['state']]; ?>
			<li class="fs-fleet-check"><span class="fs-fleet-check-state"><?=fs_badge($bk, $bt)?></span>
				<span class="fs-fleet-check-body"><strong><?=htmlspecialchars($item['title'])?></strong><span class="fs-fleet-hint d-block"><?=htmlspecialchars($item['text'])?></span></span>
<?php if (($item['fix'] ?? '') !== ''): ?>
				<form method="post" action="?tab=settings&amp;view=selfcheck"><button class="btn btn-sm btn-outline-secondary" name="selfcheck_fix" value="<?=htmlspecialchars($item['fix'])?>"><?=htmlspecialchars($item['fix_label'])?></button></form>
<?php endif; ?>
			</li>
<?php endforeach; ?>
		</ul>
	</div>
</div>
<?php elseif ($set_view !== 'controller'): ?>
<form method="post" action="?tab=settings&amp;view=<?=htmlspecialchars($set_view)?>">
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=$stitle($set_labels[$set_view], $set_view)?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=htmlspecialchars($set_leads[$set_view])?></p>
<?php
	$units = array('min' => gettext('minutes'), 's' => gettext('seconds'), 'h' => gettext('hours'), 'count' => '', 'ms' => gettext('ms'), 'pct' => '%',
	    'd' => gettext('days'), 'weeks' => gettext('weeks'), 'months' => gettext('months'), 'checks' => gettext('checks'), 'perhour' => gettext('an hour'),
	    'backups' => gettext('backups'), 'firewalls' => gettext('firewalls'), 'tries' => gettext('tries'));
	/* The number field of a setting (with its unit inside the field group), or its select. */
	$control = function ($key, bool $inline = false) use ($s, $units) {
		list(, $unit, $default, $min, $max, $label) = FLEET_TUNABLES[$key];
		$value = $s[$key];
		$h = 'htmlspecialchars';
		$aria = $inline ? ' aria-label="' . $h(gettext($label)) . '"' : ' aria-describedby="' . $key . '-help"';
		if ($unit === 'choice') {
			$out = '<select class="form-select fs-fleet-ctl" id="' . $key . '" name="' . $key . '"' . $aria . '>';
			foreach ($min as $opt) {
				$out .= '<option value="' . (int)$opt . '"' . (($value === $opt) ? ' selected' : '') . '>' . (($key === 'poll_interval') ? sprintf(gettext('%d seconds'), $opt) : (int)$opt) .
				    (($opt === $default) ? ' ' . gettext('(default)') : '') . '</option>';
			}
			return $out . '</select>';
		}
		$out = '<div class="input-group fs-fleet-ctl' . ($inline ? ' fs-fleet-ctl--inline' : '') . '"><input class="form-control fs-fleet-num" type="text" inputmode="numeric" pattern="[0-9]*" id="' . $key . '" name="' . $key .
		    '" value="' . (int)$value . '"' . $aria . ' required/>';
		if ($units[$unit] !== '') {
			$out .= '<span class="input-group-text">' . $h($units[$unit]) . '</span>';
		}
		return $out . '</div>';
	};
	/* One setting as a row: label and help on the left, the control on the right. */
	$tunable = function ($key) use ($s, $control) {
		list(, $unit, $default, $min, $max, $label, $help) = FLEET_TUNABLES[$key];
		$h = 'htmlspecialchars';
		$range = in_array($unit, array('bool', 'choice'), true) ? '' : ' ' . sprintf(gettext('%1$d to %2$d, default %3$d.'), $min, $max, $default);
		$text = '<div class="fs-fleet-srow-text"><label class="fs-fleet-srow-label" for="' . $key . '">' . $h(gettext($label)) . '</label>' .
		    '<div id="' . $key . '-help" class="fs-fleet-hint">' . (($help !== '') ? $h(gettext($help)) : '') . $range . '</div></div>';
		if ($unit === 'bool') {
			return '<div class="fs-fleet-srow">' . $text . '<div class="fs-fleet-srow-ctl"><div class="form-check form-switch m-0"><input class="form-check-input" type="checkbox" role="switch" id="' . $key .
			    '" name="' . $key . '" aria-describedby="' . $key . '-help"' . ($s[$key] ? ' checked' : '') . '/></div></div></div>';
		}
		return '<div class="fs-fleet-srow">' . $text . '<div class="fs-fleet-srow-ctl">' . $control($key) . '</div></div>';
	};
	/* Backup retention reads as one sentence; its four values are one setting to people. */
	$retention = array('backup_keep_last', 'backup_keep_daily', 'backup_keep_weekly', 'backup_keep_monthly');
	$retention_html = function () use ($control) {
		$c = function ($k) use ($control) { return $control($k, true); };
		return '<fieldset class="fs-fleet-srow fs-fleet-srow--wide"><legend class="fs-fleet-srow-label">' . gettext('How long backups are kept') . '</legend>' .
		    '<div class="fs-fleet-sentence">' . sprintf(gettext('Keep the newest %1$s plus one a day for %2$s, one a week for %3$s and one a month for %4$s.'),
		    $c('backup_keep_last'), $c('backup_keep_daily'), $c('backup_keep_weekly'), $c('backup_keep_monthly')) . '</div>' .
		    '<div class="fs-fleet-hint">' . gettext('For firewalls in no backup set; backup sets (Backups > Sets) keep their own. 0 keeps none by the day, week or month. Pinned backups and each firewall\'s newest backup are never removed.') . '</div></fieldset>';
	};
	$grouped = array();
	foreach (FLEET_TUNABLE_GROUPS as $tg) {
		$grouped = array_merge($grouped, $tg['keys']);
	}
?>
		<div class="fs-fleet-srows">
<?php foreach (FLEET_TUNABLES as $key => $t):
	if (($t[0] !== $set_view) || in_array($key, $grouped, true)) {
		continue;
	}
	if (in_array($key, $retention, true)) {
		if ($key === $retention[0]) {
			echo "\t\t\t" . $retention_html() . "\n";
		}
		continue;
	}
	echo "\t\t\t" . $tunable($key) . "\n";
	foreach (FLEET_TUNABLE_GROUPS as $tg):
		if ($tg['master'] !== $key) {
			continue;
		}
?>
			<fieldset class="fs-fleet-subsection" data-fleet-requires="<?=$key?>"<?=$s[$key] ? '' : ' hidden'?>>
				<legend><?=htmlspecialchars(gettext($tg['label']))?></legend>
				<div class="fs-fleet-srows">
<?php foreach ($tg['keys'] as $gk): ?>
					<?=$tunable($gk)?>

<?php endforeach; ?>
				</div>
			</fieldset>
<?php endforeach; endforeach; ?>
		</div>
	</div>
	<div class="panel-footer">
		<button class="btn btn-primary" type="submit" name="save_section" value="<?=htmlspecialchars($set_view)?>"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
	</div>
</div>
</form>
<?php else: ?>
<form method="post" action="?tab=settings&amp;view=controller">
<input type="hidden" name="save_settings" value="1"/>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=$stitle(gettext('Controller'), 'controller')?></h2></div>
	<div class="panel-body fs-fleet-pad">
	<p class="fs-fleet-lead"><?=htmlspecialchars($set_leads['controller'])?></p>
<?php
	$ctl_ifaces = get_configured_interface_with_descr() + array('tailscale' => gettext('Tailscale (tailnet)'));
	$first_run = !$s['enable'] && empty($s['points']);
	list($ctl_ts_problems, $ctl_ts_addr) = fleet_ts_join_ready();
	$rule_ifaces = array_keys(fleet_access_ifaces($s));
	/* The rows: the points, or WAN to start with; one empty row to add a point. */
	$rows = !empty($s['points']) ? $s['points'] : array(array('iface' => 'wan', 'port' => 8443, 'address' => ''));
	$rows[] = array('iface' => '', 'port' => 8443, 'address' => '');
	$points_table = function (array $rows) use ($ctl_ifaces) {
?>
		<fieldset class="fs-fleet-points"><legend class="form-label"><?=gettext('Where firewalls connect')?></legend>
			<p class="fs-fleet-hint mt-0"><?=gettext('One row per interface firewalls reach this controller on, with the port they join on. Leave the address empty to use the interface\'s own (or its dynamic DNS name, or the tailnet address).')?></p>
			<div class="table-responsive"><table class="table fs-table">
				<thead><tr><th><?=gettext('Interface')?></th><th><?=gettext('Port (TCP)')?></th><th><?=gettext('Address firewalls use')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
				<tbody>
<?php foreach ($rows as $ri => $rp):
	$rnew = ($rp['iface'] === '');
	$rdetect = $rnew ? '' : fleet_ctl_point_address(array('iface' => $rp['iface'], 'address' => '')); ?>
				<tr<?=$rnew ? ' class="fs-fleet-point-new"' : ''?>>
					<td><select class="form-select form-select-sm" name="points[<?=$ri?>][iface]" aria-label="<?=gettext('Interface')?>">
<?php if ($rnew): ?>
						<option value=""><?=gettext('Add...')?></option>
<?php endif; ?>
<?php foreach ($ctl_ifaces as $ck => $cd): ?>
						<option value="<?=htmlspecialchars($ck)?>"<?=($ck === $rp['iface']) ? ' selected' : ''?>><?=htmlspecialchars($cd)?></option>
<?php endforeach; ?>
					</select></td>
					<td><input class="form-control form-control-sm fs-mono" name="points[<?=$ri?>][port]" inputmode="numeric" value="<?=(int)$rp['port']?>" aria-label="<?=gettext('Port (TCP)')?>"/></td>
					<td><input class="form-control form-control-sm fs-mono" name="points[<?=$ri?>][address]" value="<?=htmlspecialchars($rp['address'])?>"
					    placeholder="<?=htmlspecialchars(($rdetect !== '') ? $rdetect : ($rnew ? gettext('found by itself') : gettext('no address yet')))?>" aria-label="<?=gettext('Address firewalls use')?>"/>
<?php if (($rp['iface'] === 'wan') && ($rdetect !== '') && is_private_ip($rdetect)): ?>
						<div class="fs-fleet-hint"><?=gettext('A private address: firewalls on the internet need the public address or DNS name of the port forward to this firewall.')?></div>
<?php endif; ?></td>
					<td class="text-end"><?php if (!$rnew && (count($rows) > 2)): ?><button class="btn btn-sm btn-link fs-fleet-danger-link" type="submit" name="point_remove" value="<?=$ri?>"><?=gettext('Remove')?></button><?php endif; ?></td></tr>
<?php endforeach; ?>
				</tbody></table></div>
		</fieldset>
<?php
	};
	/* ?setup=guide runs the guide again on a running controller, filled in with its current settings. */
	$setup_again = $s['enable'] && (($_GET['setup'] ?? '') === 'guide');
?>
<?php if ($first_run || $setup_again || $setup_done) { include('/usr/local/pkg/fleet/fleet_setup_view.inc'); } else { ?>
	<div class="fs-fleet-settings">
		<p class="fs-fleet-hint mt-0"><?=gettext('Prefer to be taken through it?')?> <a href="?tab=settings&amp;view=controller&amp;setup=guide"><?=gettext('Run the setup guide')?></a> <?=gettext('(it starts from the settings below).')?></p>
		<div class="form-check form-switch">
			<input class="form-check-input" type="checkbox" role="switch" id="enable" name="enable" <?=$s['enable'] ? 'checked' : ''?>/>
			<label class="form-check-label" for="enable"><?=gettext('Run this firewall as a FreeSense Fleet controller')?></label>
		</div>
<?php $points_table($rows); ?>
		<div class="fs-fleet-field"><label class="form-label" for="wg_port"><?=gettext('Tunnel port (UDP)')?></label>
			<input class="form-control fs-mono" id="wg_port" name="wg_port" inputmode="numeric" value="<?=(int)$s['wg_port']?>" style="max-width:9rem"/>
			<div class="fs-fleet-hint"><?=gettext('One for every connection point: the Fleet tunnel (WireGuard) listens on a single port.')?></div></div>
		<div class="form-check form-switch">
			<input class="form-check-input" type="checkbox" role="switch" id="rules_manual" name="rules_manual" <?=$s['rules_manual'] ? 'checked' : ''?>/>
			<label class="form-check-label" for="rules_manual"><?=gettext('Let me manage the firewall rules myself')?></label>
		</div>
<?php if ($s['rules_manual']): ?>
		<div class="fs-fleet-note"><?=gettext('Fleet adds no rules. Open these yourself:')?>
			<ul class="mb-0">
<?php foreach ($s['points'] as $mp): ?>
				<li><?=htmlspecialchars(sprintf(gettext('TCP %1$d to this firewall (joining), on %2$s'), $mp['port'], $ctl_ifaces[$mp['iface']] ?? $mp['iface']))?></li>
<?php endforeach; ?>
				<li><?=htmlspecialchars(sprintf(gettext('UDP %1$d to this firewall (tunnel), on the same interfaces'), $s['wg_port']))?></li>
			</ul>
			<?=gettext('Then use Settings > Self-check, "Test the ports from outside".')?></div>
<?php elseif ($s['enable']): ?>
		<p class="fs-fleet-hint"><?=sprintf(gettext('Fleet keeps its rules under %1$s (locked; change them here) and the aliases FleetEnroll, FleetTunnel and FleetBlocked, for: %2$s.'),
		    '<a href="/firewall_rules.php?if=FloatingRules">' . gettext('Firewall > Rules > Floating') . '</a>', htmlspecialchars(implode(', ', $rule_ifaces)))?></p>
<?php endif; ?>
<?php if ($ready && !fleet_data_on_zfs()): ?>
		<div class="fs-fleet-note"><?=fs_badge('warn', gettext('No rollback'))?> <?=gettext('This controller runs on UFS. Fleet works, but a failed update of this controller cannot roll back automatically. ZFS is recommended for the controller.')?></div>
<?php endif; ?>
	</div>
<?php } ?>
	</div>
<?php if (!($first_run || $setup_again || $setup_done)): ?>
	<div class="panel-footer">
		<button class="btn btn-primary" type="submit" name="save_settings" value="1"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
	</div>
<?php endif; ?>
</div>
</form>
<?php endif; ?>

<?php endif; ?>
<script src="/fleet/assets/fleet-naming.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-naming.js')?>"></script>
<script src="/fleet/assets/fleet-invite.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-invite.js')?>"></script>
<script src="/fleet/assets/fleet-setup.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-setup.js')?>"></script>
<?php include('foot.inc');
