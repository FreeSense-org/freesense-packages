<?php
/*
 * fleet_box.php
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
 * One firewall in the fleet: what it last reported, its place in the fleet,
 * recent events, and "Open WebUI" (a one-time sign-in the box issues over
 * the tunnel; the browser then goes to an address the box reported).
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$s = fleet_ctl_settings();
$box = ($s['enable'] && is_file(FLEET_DATA . '/fleet.db')) ? fleet_box_get((string)($_REQUEST['id'] ?? '')) : null;
if ($box === null) {
	header('Location: /fleet/fleet_dashboard.php');
	exit;
}
$st = json_decode((string)$box['status'], true) ?: array();
/* The page is named after the firewall; the breadcrumb leads back to the fleet. */
$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), (string)$box['label']);
$manage = isAllowedPage('fleet/fleet.php');
$who = (string)($_SESSION['Username'] ?? 'admin');
$input_errors = array();
$savemsg = null;
$rebooting = false;

/* Backups hold the whole configuration (secrets included): only for those who manage the fleet. */
if ($manage && isset($_GET['download'])) {
	$row = fleet_backup_get((int)$_GET['download']);
	$xml = (($row !== null) && ($row['node_id'] === $box['node_id'])) ? fleet_backup_read($row) : null;
	if ($xml !== null) {
		fleet_audit($who, 'backup_download', "{$box['node_id']} ({$box['label']}): backup of " . date('Y-m-d H:i', (int)$row['time']));
		$name = preg_replace('/[^A-Za-z0-9._-]/', '_', (string)(json_decode((string)$box['status'], true)['hostname'] ?? $box['name']));
		header('Content-Type: application/xml');
		header('Content-Disposition: attachment; filename="config-' . $name . '-' . date('Ymd-His', (int)$row['time']) . '.xml"');
		header('Cache-Control: no-store');
		echo $xml;
		exit;
	}
	$input_errors[] = gettext('FLEET-E802: That backup could not be read. Its file is missing or damaged.');
}
if ($manage && isset($_POST['restore_id'])) {
	$row = fleet_backup_get((int)$_POST['restore_id']);
	if (($row === null) || ($row['node_id'] !== $box['node_id'])) {
		$input_errors[] = gettext('That backup does not belong to this firewall.');
	} else {
		/* In the background (it waits up to a minute for the firewall to answer); Activity shows each step. */
		$running = fleet_op_running($box['node_id']);
		if ($running !== null) {
			$input_errors[] = sprintf(gettext('Something is already running on this firewall (%s). Wait until it is done.'), $running['text']);
		} else {
			$op = fleet_op_start($box['node_id'], 'restore', 'Starting', $who);
			fleet_op_set($op, 'running', 'Starting', 0);
			mwexec_bg('/usr/local/bin/php /usr/local/sbin/freesense-fleet-run restore ' . (int)$op . ' ' . (int)$row['id']);
			header('Location: /fleet/fleet_activity.php?op=' . (int)$op);
			exit;
		}
	}
}
/* Updates: check now, or start the update (after the review). */
if ($manage && isset($_POST['update_check'])) {
	$info = fleet_update_check($box, true);
	$box = fleet_box_get($box['node_id']);
	if ($info['error'] !== null) {
		$input_errors[] = $info['error'];
	} else {
		$savemsg = $info['available'] ? sprintf(gettext('Version %s is available.'), fleet_version_number($info['latest'])) : gettext('The firewall is up to date.');
	}
}
if ($manage && isset($_POST['policy_fix'])) {
	try {
		$fixres = fleet_remediate_box($box, $who, true);
		if (strncmp($fixres, 'FLEET-E', 7) === 0) {
			$input_errors[] = $fixres;
		} else {
			$savemsg = $fixres;
		}
	} catch (RuntimeException $e) {
		$input_errors[] = $e->getMessage();
	}
}
if ($manage && isset($_POST['update_start'])) {
	try {
		fleet_box_update($box, $who);
		header('Location: /fleet/fleet_activity.php?op=' . (int)fleet_op_running($box['node_id'])['id']);
		exit;
	} catch (RuntimeException $e) {
		$input_errors[] = $e->getMessage();
	}
}
/* Manage: reboot, a service, the state table. The box refuses these itself unless it joined as Managed. */
if ($manage && isset($_POST['manage_action'])) {
	try {
		switch ((string)$_POST['manage_action']) {
		case 'reboot':
			$savemsg = fleet_box_reboot($box, $who);
			$rebooting = true;
			break;
		case 'states':
			$savemsg = fleet_box_states_reset($box, $who);
			break;
		case 'start':
		case 'stop':
		case 'restart':
			$svc = null;
			foreach (fleet_box_services($box) as $candidate) {
				if (($candidate['name'] === (string)($_POST['service'] ?? '')) &&
				    ((string)($candidate['vpnid'] ?? '') === (string)($_POST['vpnid'] ?? '')) &&
				    ((string)($candidate['zone'] ?? '') === (string)($_POST['zone'] ?? ''))) {
					$svc = $candidate;
				}
			}
			if ($svc === null) {
				throw new RuntimeException(gettext('That service is not on this firewall any more. Reload the page.'));
			}
			$savemsg = fleet_box_service($box, $svc, (string)$_POST['manage_action'], $who);
			break;
		}
	} catch (RuntimeException $e) {
		$input_errors[] = $e->getMessage();
	}
}
if ($manage && isset($_POST['set_groups'])) {
	fleet_box_set_groups($box, (array)($_POST['groups'] ?? array()), $who);
	$savemsg = gettext('Groups saved.');
}
if ($manage && (isset($_POST['pin']) || isset($_POST['unpin']))) {
	$pid = (int)($_POST['pin'] ?? $_POST['unpin']);
	$prow = fleet_backup_get($pid);
	try {
		if (($prow === null) || ($prow['node_id'] !== $box['node_id'])) {
			throw new RuntimeException(gettext('That backup does not exist any more.'));
		}
		fleet_backup_pin($pid, isset($_POST['pin']), $who);
		$savemsg = isset($_POST['pin']) ? gettext('Pinned: this backup is never removed.') : gettext('Unpinned: the keep rules decide again.');
	} catch (RuntimeException $e) {
		$input_errors[] = $e->getMessage();
	}
}
if ($manage && ($_POST['backup_now'] ?? false)) {
	try {
		list($result) = fleet_backup_box($box, 'manual', $who);
		$savemsg = ($result === 'stored') ? gettext('Backed up and checked.') : gettext('No change since the last backup, so nothing new was stored.');
	} catch (RuntimeException $e) {
		fleet_audit($who, 'backup_failed', "{$box['node_id']} ({$box['label']}): " . $e->getMessage());
		$input_errors[] = $e->getMessage();
	}
}

if (($_POST['open_webui'] ?? false) && $manage) {
	$base = (string)($_POST['base'] ?? '');
	$user = (string)($_POST['user'] ?? '');
	try {
		$path = fleet_box_handoff($box, $user, "{$who}@" . (string)config_get_path('system/hostname', 'controller'));
		$url = fleet_handoff_url($st, $base, $path);
		if ($url === null) {
			throw new RuntimeException(gettext('That address is not one this firewall reported. Reload the page and pick an address from the list.'));
		}
		fleet_audit($who, 'handoff', "{$box['node_id']} ({$box['label']}): WebUI as {$user} via {$base}");
		/* No Referer: the box's WebGUI refuses foreign referers, and it need not learn the controller's address. */
		header('Referrer-Policy: no-referrer');
		header('Location: ' . $url);
		exit;
	} catch (RuntimeException $e) {
		$input_errors[] = $e->getMessage();
	}
}

$state = in_array($box['state'], array('online', 'degraded', 'offline'), true) ? $box['state'] : 'new';
$state_names = array('online' => gettext('Online'), 'degraded' => gettext('Degraded'), 'offline' => gettext('Offline'), 'new' => gettext('Joining'));
$when = function ($ts) {
	return $ts ? htmlspecialchars(date('Y-m-d H:i', (int)$ts)) : '<span class="fs-muted">' . gettext('never') . '</span>';
};
$ev_types = array_map(function ($t) { return $t[0]; }, FLEET_EVENT_TYPES);
$ev_filters = fleet_list_filters($_GET, array('q' => null, 'type' => $ev_types, 'since' => FLEET_OPS_SINCE));
list($events, $ev_page) = (($_GET['view'] ?? '') === 'events')
    ? fleet_events_find($box['node_id'], $ev_filters, max(1, (int)($_GET['page'] ?? 1)), time()) : array(array(), fleet_list_page(0, 1));
$webgui = (array)($st['webgui'] ?? array());
/* Inside addresses first: WAN is rarely the one an administrator's browser reaches. */
usort($webgui, function ($x, $y) {
	return (strcasecmp((string)$x['name'], 'WAN') === 0) <=> (strcasecmp((string)$y['name'], 'WAN') === 0);
});
$users = (array)($st['handoff_users'] ?? array());
$rev = (array)($st['config_revision'] ?? array());
/* A unified diff as lines colored by kind. Each line is a block, so no newline between them. */
$render_diff = function (string $diff, string $label) {
	echo '<pre class="fs-mono" aria-label="' . htmlspecialchars($label) . '">';
	foreach (explode("\n", $diff) as $line) {
		$c = ($line === '') ? '' : (($line[0] === '+') ? 'add' : (($line[0] === '-') ? 'del' : (($line[0] === '@') ? 'hunk' : '')));
		echo '<span' . (($c !== '') ? ' class="' . $c . '"' : '') . '>' . htmlspecialchars($line) . '</span>';
	}
	echo '</pre>';
};
$asset = function ($f) {
	return '/fleet/assets/' . $f . '?v=' . (int)@filemtime('/usr/local/www/fleet/assets/' . $f);
};

$views = array('overview' => gettext('Overview'), 'system' => gettext('System'), 'stats' => gettext('Stats'), 'updates' => gettext('Updates'), 'policies' => gettext('Policies'), 'backups' => gettext('Backups'),
    'manage' => gettext('Manage'), 'events' => gettext('Events'));
if (!$manage) {
	unset($views['backups'], $views['manage']);
}
$view = fs_view_param(array_keys($views), 'overview');
/* A link or form target on this page, in a view. */
$here = function (string $view, array $more = array()) use ($box) {
	return '?' . htmlspecialchars(http_build_query(array_merge(array('id' => $box['node_id'], 'view' => $view), $more)));
};

include('head.inc');
?>
<link rel="stylesheet" href="<?=$asset('fleet.css')?>">
<?php
if ($manage) {
	$tab_array = array(
		array(gettext('Dashboard'), true, '/fleet/fleet_dashboard.php'),
		array(gettext('Activity'), false, '/fleet/fleet_activity.php'),
		array(gettext('Updates'), false, '/fleet/fleet_updates.php'),
		array(gettext('Schedules'), false, '/fleet/fleet_schedules.php'),
		array(gettext('Backups'), false, '/fleet/fleet_backups.php'),
		array(gettext('Policies'), false, '/fleet/fleet_policies.php'),
		array(gettext('Templates'), false, '/fleet/fleet_templates.php'),
		array(gettext('Users'), false, '/fleet/fleet_users.php'),
		array(gettext('Firewalls'), false, '/fleet/fleet.php'),
		array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
	);
	display_top_tabs($tab_array);
}
if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box(htmlspecialchars($savemsg), 'success');
}
?>
<div class="fs-fleet-box-head" data-state="<?=$state?>">
	<div class="fs-fleet-box-names">
		<a class="fs-fleet-back" href="/fleet/fleet_dashboard.php"><i class="fa-solid fa-arrow-left" aria-hidden="true"></i><?=gettext('All firewalls')?></a>
		<div class="fs-fleet-box-status">
<?php if ($state === 'online'): ?>
			<span class="fs-fleet-ok"><?=$state_names['online']?></span>
<?php else: ?>
			<?=fs_badge($state === 'new' ? 'pending' : $state, $state_names[$state])?>
<?php endif; ?>
			<span class="fs-fleet-checked"><?=htmlspecialchars((string)($st['hostname'] ?? $box['name']))?>, <?=htmlspecialchars((string)($st['version'] ?? ''))?></span>
		</div>
	</div>
</div>
<?php if ($state !== 'online' && (string)$box['error'] !== ''): ?>
<p class="fs-fleet-problem fs-fleet-problem--lead"><?=htmlspecialchars($box['error'])?></p>
<?php endif; ?>
<?php fs_view_switch($views, $view); ?>

<?php if ($view === 'overview'): ?>
<div class="row g-3 fs-fleet-panels">
	<div class="col-lg-6">
		<div class="panel panel-default h-100">
			<div class="panel-heading"><h2 class="panel-title"><?=gettext('This firewall')?></h2></div>
			<div class="panel-body fs-fleet-pad">
				<dl class="fs-fleet-facts fs-fleet-facts--wide">
					<dt><?=gettext('Version')?></dt><dd><?=htmlspecialchars((string)($st['version'] ?? '-'))?></dd>
					<dt><?=gettext('Platform')?></dt><dd><?=htmlspecialchars((string)($st['platform'] ?? '-'))?></dd>
					<dt><?=gettext('Configuration')?></dt><dd><?=$when($rev['time'] ?? 0)?><?php if (($rev['description'] ?? '') !== ''): ?><div class="fs-muted"><?=htmlspecialchars($rev['description'])?></div><?php endif; ?></dd>
					<dt><?=gettext('Rollback protection')?></dt><dd><?php if (!isset($st['rollback_protection'])): ?>-<?php elseif ($st['rollback_protection']): ?><?=gettext('Yes (ZFS boot environments)')?><?php else: ?><?=fs_badge('warn', gettext('No rollback'))?> <span class="fs-muted"><?=gettext('A failed update cannot roll back by itself.')?></span><?php endif; ?></dd>
					<dt><?=gettext('CARP')?></dt><dd><?php $ha_carp = (string)($st['carp'] ?? 'none'); list($ha_pairs, $ha_boxes) = fleet_ha_now(); $ha_pair = fleet_ha_pair_of($ha_pairs, $box['node_id']); ?>
						<?=($ha_carp === 'none') ? gettext('Not used') : (in_array($ha_carp, array('master', 'backup'), true) ? htmlspecialchars(strtoupper($ha_carp)) : fs_badge('warn', ucfirst($ha_carp)))?>
<?php if ($ha_pair !== null): ?>
						<div class="small"><?=gettext('HA pair with')?> <?php foreach (array_diff($ha_pair['nodes'], array($box['node_id'])) as $hn): ?><a href="/fleet/fleet_box.php?id=<?=urlencode($hn)?>"><?=htmlspecialchars($ha_boxes[$hn]['label'])?></a> <?php endforeach; ?>
							<?=($ha_pair['problem'] === null) ? '' : fs_badge('down', ($ha_pair['problem'][0] === 'split') ? gettext('Split-brain') : gettext('No MASTER'))?>
							<?=($ha_pair['primary'] === $box['node_id']) ? '<span class="fs-muted">' . gettext('(pushes HA sync)') . '</span>' : ''?></div>
<?php endif; ?></dd>
					<dt><?=gettext('Fleet policy')?></dt><dd><?=isset($st['policy_bundle']['version']) ? sprintf(gettext('Version %d'), (int)$st['policy_bundle']['version']) : gettext('None')?><?php if (!empty($st['breakglass'])): ?> <?=fs_badge('warn', gettext('Lock suspended'))?><?php endif; ?></dd>
				</dl>
			</div>
		</div>
	</div>
	<div class="col-lg-6">
		<div class="panel panel-default h-100">
			<div class="panel-heading"><h2 class="panel-title"><?=gettext('In the fleet')?></h2></div>
			<div class="panel-body fs-fleet-pad">
				<dl class="fs-fleet-facts fs-fleet-facts--wide">
					<dt><?=gettext('Access')?></dt><dd><?=($box['role'] === 'managed') ? gettext('Managed') : gettext('Monitor only')?></dd>
					<dt><?=gettext('Tunnel address')?></dt><dd class="fs-mono"><?=htmlspecialchars($box['overlay'])?></dd>
					<dt><?=gettext('Joined')?></dt><dd><?=$when($box['joined'])?></dd>
					<dt><?=gettext('Last seen')?></dt><dd><?=$when($box['last_seen'])?></dd>
<?php if ($manage): $latest = fleet_backup_latest($box['node_id']); ?>
					<dt><?=gettext('Last backup')?></dt><dd><?=$latest ? $when($latest['time']) . ' <a class="fs-fleet-inline-link" href="' . $here('backups') . '">' . gettext('Backups') . '</a>' : $when(0)?></dd>
<?php endif; ?>
					<dt><?=gettext('Groups')?></dt><dd><?php $mine = fleet_box_groups($box['node_id']); ?>
<?php if (empty($mine)): ?>
						<span class="fs-muted"><?=gettext('None')?></span>
<?php else: ?>
						<span class="fs-fleet-groups"><?php foreach ($mine as $grp): ?><span class="fs-fleet-group" style="--fs-fleet-group: var(--fs-series-<?=htmlspecialchars(fleet_group_color((string)$grp['color']))?>)"><?=htmlspecialchars($grp['name'])?></span><?php endforeach; ?></span>
<?php endif; ?>
<?php if ($manage): ?>
						<a class="fs-fleet-inline-link" href="<?=$here('overview', array('groups' => 'edit'))?>"><?=gettext('Change')?></a>
<?php endif; ?>
					</dd>
					<dt><?=gettext('Box ID')?></dt><dd class="fs-mono"><?=htmlspecialchars($box['node_id'])?></dd>
				</dl>
			</div>
<?php if ($manage && (($_GET['groups'] ?? '') === 'edit')): $all = fleet_groups_all(); $in = array_column($mine, 'id'); ?>
			<div class="panel-footer">
<?php if (empty($all)): ?>
				<span class="small fs-muted"><?=gettext('There are no groups yet.')?> <a class="fs-fleet-inline-link" href="/fleet/fleet.php?view=groups"><?=gettext('Add a group')?></a></span>
<?php else: ?>
				<form method="post" action="<?=$here('overview')?>" class="fs-fleet-groupform">
					<fieldset>
						<legend class="visually-hidden"><?=gettext('Groups')?></legend>
<?php foreach ($all as $grp): ?>
						<label class="form-check fs-fleet-groupcheck"><input class="form-check-input" type="checkbox" name="groups[]" value="<?=(int)$grp['id']?>"<?=in_array($grp['id'], $in) ? ' checked' : ''?>/>
							<span class="fs-fleet-group" style="--fs-fleet-group: var(--fs-series-<?=htmlspecialchars(fleet_group_color((string)$grp['color']))?>)"><?=htmlspecialchars($grp['name'])?></span></label>
<?php endforeach; ?>
					</fieldset>
					<button class="btn btn-sm btn-primary" type="submit" name="set_groups" value="1"><?=gettext('Save groups')?></button>
					<a class="btn btn-sm btn-outline-secondary" href="<?=$here('overview')?>"><?=gettext('Cancel')?></a>
				</form>
<?php endif; ?>
			</div>
<?php endif; ?>
		</div>
	</div>
</div>

<?php if ($manage): ?>
<div class="panel panel-default" id="webui">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Open WebUI')?></h2></div>
	<div class="panel-body fs-fleet-pad">
<?php if (empty($users)): ?>
		<p class="fs-fleet-lead"><?=gettext("This firewall does not allow sign-in from the controller. A local administrator turns it on, for chosen users only, on the firewall's console:")?></p>
		<code class="fs-fleet-command">freesense-join handoff-users admin</code>
<?php elseif (empty($webgui)): ?>
		<p class="fs-fleet-lead"><?=gettext('This firewall has not reported a WebGUI address yet. It does so with its next status check.')?></p>
<?php else: ?>
		<form method="post" action="<?=$here('overview')?>" class="fs-fleet-form">
			<div class="fs-fleet-field fs-fleet-field--wide"><label class="form-label" for="base"><?=gettext('Address')?></label>
				<select class="form-select" id="base" name="base">
<?php foreach ($webgui as $w): ?>
					<option value="<?=htmlspecialchars($w['url'])?>"><?=htmlspecialchars($w['name'] . ': ' . $w['url'])?></option>
<?php endforeach; ?>
				</select></div>
			<div class="fs-fleet-field"><label class="form-label" for="user"><?=gettext('Sign in as')?></label>
				<select class="form-select" id="user" name="user">
<?php foreach ($users as $u): ?>
					<option value="<?=htmlspecialchars($u)?>"><?=htmlspecialchars($u)?></option>
<?php endforeach; ?>
				</select></div>
			<div class="fs-fleet-field fs-fleet-field--button">
				<button class="btn btn-primary" type="submit" name="open_webui" value="1" <?=($state === 'offline') ? 'disabled' : ''?>><i class="fa-solid fa-arrow-up-right-from-square icon-embed-btn" aria-hidden="true"></i><?=gettext('Open WebUI')?></button>
			</div>
		</form>
<?php endif; ?>
	</div>
<?php if (!empty($users) && !empty($webgui)): ?>
	<div class="panel-footer small fs-muted"><?=gettext("Signs you in on the firewall's own WebUI with a one-time link that is valid for 60 seconds. Works only if your browser can reach the address you choose.")?></div>
<?php endif; ?>
</div>
<?php endif; ?>

<?php elseif ($view === 'backups'):
	$backups = fleet_backup_list($box['node_id'], 200);
	/* Why each backup is kept (or that the next clean-up removes it): the same rules as the nightly clean-up. */
	list($box_rules, $box_sets) = fleet_backup_rules_by_box()[$box['node_id']] ?? array(array(fleet_backup_default_rule()), array());
	$kept = fleet_backup_keep(fleet_db()->query('SELECT id, time, reason, pinned FROM backups WHERE node_id = ' . fleet_db()->quote($box['node_id']))->fetchAll(),
	    $box_rules, time(), fleet_opt('backup_safety_days'), fleet_tz());
	$diff_id = (int)($_GET['diff'] ?? 0);
	$review = isset($_GET['restore']) ? fleet_backup_get((int)$_GET['restore']) : null;
	if (($review !== null) && ($review['node_id'] === $box['node_id'])):
		try {
			$live = fleet_backup_fetch($box);
			$wanted = fleet_backup_read($review);
			$change = ($wanted === null) ? null : fleet_backup_diff($live, $wanted);
			$fetch_error = ($wanted === null) ? gettext('FLEET-E802: That backup could not be read.') : null;
		} catch (RuntimeException $e) {
			$change = null;
			$fetch_error = $e->getMessage();
		}
?>
<div class="panel panel-default fs-fleet-review" role="region" aria-labelledby="review-title">
	<div class="panel-heading"><h2 id="review-title" class="panel-title"><?=sprintf(gettext('Restore the backup from %s?'), htmlspecialchars(date('Y-m-d H:i', (int)$review['time'])))?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=sprintf(gettext('The firewall gets this configuration back. Its current configuration is backed up first, and it keeps its place in the fleet. If it does not answer within %d minutes afterwards, it goes back by itself. Rules and aliases apply at once; some interface and service settings need a reboot.'), fleet_opt('restore_confirm'))?></p>
<?php if ($fetch_error !== null): ?>
		<p class="fs-fleet-problem"><?=htmlspecialchars($fetch_error)?></p>
<?php elseif (trim((string)$change) === ''): ?>
		<p class="fs-fleet-hint"><?=gettext('The firewall already runs exactly this configuration. There is nothing to restore.')?></p>
<?php else: ?>
		<div class="fs-fleet-diff">
			<div class="fs-fleet-hint"><?=gettext('What changes on the firewall (- now, + after the restore)')?></div>
			<?php $render_diff($change, gettext('What changes on the firewall')); ?>
		</div>
<?php endif; ?>
	</div>
	<div class="panel-footer">
		<form method="post" action="<?=$here('backups')?>" class="fs-fleet-review-actions">
			<input type="hidden" name="restore_id" value="<?=(int)$review['id']?>"/>
			<button class="btn btn-primary" type="submit"<?=(($fetch_error !== null) || (trim((string)$change) === '') || ($state === 'offline')) ? ' disabled' : ''?>><i class="fa-solid fa-upload icon-embed-btn" aria-hidden="true"></i><?=gettext('Restore this backup')?></button>
			<a class="btn btn-outline-secondary" href="<?=$here('backups')?>"><?=gettext('Cancel')?></a>
		</form>
	</div>
</div>
<?php endif; ?>

<div class="panel panel-default">
	<div class="panel-heading fs-fleet-panel-head">
		<h2 class="panel-title"><?=gettext('Backups')?> <span class="fs-count"><?=count($backups)?></span></h2>
		<span class="fs-muted small"><?=empty($box_sets) ? sprintf(gettext('Keeps the default: %s'), htmlspecialchars(fleet_keep_rule_text(fleet_backup_default_rule()))) : sprintf(gettext('Kept by %s'), htmlspecialchars(implode(', ', $box_sets)))?>
			(<a href="/fleet/fleet_backups.php?view=sets"><?=gettext('sets')?></a>)</span>
		<a class="btn btn-sm btn-link" href="/fleet/fleet_schedules.php?node=<?=urlencode($box['node_id'])?>"><?=gettext('Schedule...')?></a>
		<form method="post" action="<?=$here('backups')?>"><button class="btn btn-sm btn-outline-secondary" name="backup_now" value="1" <?=($state === 'offline') ? 'disabled' : ''?>><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Back up now')?></button></form>
	</div>
	<div class="panel-body fs-fleet-pad">
<?php if (empty($backups)): ?>
		<p class="fs-fleet-hint"><?=gettext('No backups yet. The first one is taken tonight, after the next configuration change, or now with Back up now.')?></p>
<?php else: ?>
		<ol class="fs-fleet-backups">
<?php $running_sha = (string)($st['config_revision']['sha256'] ?? ''); ?>
<?php foreach ($backups as $i => $b): $prev = $backups[$i + 1] ?? null; ?>
			<li<?=($diff_id === (int)$b['id']) ? ' class="is-open"' : ''?>>
				<time datetime="<?=date('c', (int)$b['time'])?>"><?=htmlspecialchars(date('Y-m-d H:i', (int)$b['time']))?></time>
				<span class="fs-fleet-backup-what"><?=htmlspecialchars(((string)$b['description'] !== '') ? $b['description'] : gettext('No description'))?>
						<span class="fs-muted"><?=htmlspecialchars(fleet_backup_reason_text($b['reason']))?>, <?=htmlspecialchars(format_bytes((int)$b['size']))?>.
						<?=isset($kept[(int)$b['id']]) ? htmlspecialchars(sprintf(gettext('Kept: %s'), gettext($kept[(int)$b['id']]))) : '<span class="fs-fleet-warn-text">' . gettext('Removed at the next clean-up') . '</span>'?></span>
						<?=!empty($b['pinned']) ? fs_badge('info', gettext('Pinned')) : ''?></span>
				<span class="fs-fleet-backup-actions">
<?php if ($prev !== null): ?>
					<a class="btn btn-sm btn-link" href="<?=$here('backups', ($diff_id === (int)$b['id']) ? array() : array('diff' => (int)$b['id']))?>"<?=($diff_id === (int)$b['id']) ? ' aria-expanded="true"' : ''?>><?=($diff_id === (int)$b['id']) ? gettext('Hide changes') : gettext('Changes')?></a>
<?php endif; ?>
					<a class="btn btn-sm btn-link" href="<?=$here('backups', array('download' => (int)$b['id']))?>"><i class="fa-solid fa-download icon-embed-btn" aria-hidden="true"></i><?=gettext('Download')?></a>
<?php if ($manage): ?>
					<form method="post" action="<?=$here('backups')?>" class="d-inline"><button class="btn btn-sm btn-link" name="<?=!empty($b['pinned']) ? 'unpin' : 'pin'?>" value="<?=(int)$b['id']?>" title="<?=!empty($b['pinned']) ? gettext('Let the keep rules remove it again') : gettext('Never remove this backup')?>"><?=!empty($b['pinned']) ? gettext('Unpin') : gettext('Pin')?></button></form>
<?php endif; ?>
<?php if (($running_sha !== '') && hash_equals($running_sha, (string)$b['sha256'])): ?>
					<span class="fs-fleet-current"><?=gettext('Current')?></span>
<?php else: ?>
					<a class="btn btn-sm btn-link" href="<?=$here('backups', array('restore' => (int)$b['id']))?>"><?=gettext('Restore')?>&hellip;</a>
<?php endif; ?>
				</span>
<?php if (($diff_id === (int)$b['id']) && ($prev !== null)):
	$new = fleet_backup_read($b);
	$old = fleet_backup_read($prev);
	$diff = (($new !== null) && ($old !== null)) ? fleet_backup_diff($old, $new) : null;
?>
				<div class="fs-fleet-diff">
<?php if ($diff === null): ?>
					<p class="fs-fleet-hint"><?=gettext('FLEET-E802: One of the two backups could not be read.')?></p>
<?php else: ?>
					<div class="fs-fleet-hint"><?=sprintf(gettext('Changes since %s'), htmlspecialchars(date('Y-m-d H:i', (int)$prev['time'])))?></div>
					<?php $render_diff($diff, gettext('Changes since the backup before')); ?>
<?php endif; ?>
				</div>
<?php endif; ?>
			</li>
<?php endforeach; ?>
		</ol>
<?php endif; ?>
	</div>
	<div class="panel-footer small fs-muted"><?=gettext("A copy of this firewall's configuration is kept on the controller, encrypted, when it changes and every night. Downloads contain secrets such as password hashes and keys.")?></div>
</div>

<?php elseif ($view === 'system'):
	$mstrings = array('cpu' => gettext('CPU'), 'cores' => gettext('cores'), 'memory' => gettext('Memory'), 'swap' => gettext('Swap'), 'uptime' => gettext('Uptime'),
	    'temperature' => gettext('Temperature'), 'load' => gettext('Load (1, 5, 15 min)'), 'loadHint' => gettext('processes waiting for the CPU'),
	    'states' => gettext('States'), 'of' => gettext('of'), 'mbufs' => gettext('Network buffers'), 'up' => gettext('Up'), 'down' => gettext('Down'),
	    'checked' => gettext('Checked'), 'noData' => gettext('The firewall did not answer.'), 'noHistory' => gettext('No history for this range yet.'),
	    'showAll' => gettext('Show %d more ZFS datasets (they share the pool)'), 'avg' => gettext('average'), 'peak' => gettext('peak'), 'day' => gettext('day'), 'days' => gettext('days'));
?>
<div data-fleet-metrics="<?=htmlspecialchars($box['node_id'])?>" data-strings="<?=htmlspecialchars(json_encode($mstrings))?>">
	<div class="fs-tiles fs-fleet-tiles-row" data-m="live" aria-live="polite"><p class="fs-muted mb-0"><?=gettext('Reading the firewall...')?></p></div>
	<div class="fs-fleet-two">
		<div class="panel panel-default">
			<div class="panel-heading"><h2 class="panel-title"><?=gettext('Hardware')?></h2></div>
			<div class="panel-body fs-fleet-pad"><dl class="fs-fleet-facts fs-fleet-facts--wide mb-1" data-m="hw"></dl><div class="fs-muted small" data-m="checked"></div></div>
		</div>
		<div class="panel panel-default">
			<div class="panel-heading"><h2 class="panel-title"><?=gettext('Disks')?></h2></div>
			<div class="panel-body table-responsive"><table class="table fs-table"><thead><tr><th><?=gettext('Mounted on')?></th><th><?=gettext('Type')?></th><th><?=gettext('Used')?></th><th class="text-end"><?=gettext('Size')?></th></tr></thead>
				<tbody data-m="disks"></tbody></table></div>
		</div>
	</div>
	<div class="panel panel-default">
		<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('CPU and memory')?></h2>
			<div class="btn-group btn-group-sm" role="group" aria-label="<?=gettext('Range')?>">
<?php foreach (array('1h' => gettext('1 hour'), '24h' => gettext('24 hours'), '7d' => gettext('7 days'), '30d' => gettext('30 days')) as $rk => $rl): ?>
				<button type="button" class="btn btn-outline-secondary" data-range="<?=$rk?>" aria-pressed="<?=($rk === '24h') ? 'true' : 'false'?>"><?=$rl?></button>
<?php endforeach; ?>
			</div></div>
		<div class="panel-body fs-fleet-pad" data-m="history"></div>
	</div>
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('Interfaces')?></h2></div>
		<div class="panel-body table-responsive"><table class="table fs-table"><thead><tr><th><?=gettext('Interface')?></th><th><?=gettext('Link')?></th><th><?=gettext('Address')?></th><th><?=gettext('MAC')?></th><th class="text-end"><?=gettext('Errors')?></th></tr></thead>
			<tbody data-m="ifs"></tbody></table></div>
	</div>
</div>
<script src="<?=$asset('fleet-charts.js')?>"></script>
<script src="<?=$asset('fleet-metrics.js')?>"></script>
<?php elseif ($view === 'stats'):
	$srange = in_array($_GET['range'] ?? '', array('1h', '24h', '7d', '30d'), true) ? (string)$_GET['range'] : '24h';
	$st = fleet_trends_box($box['node_id'], $srange, time());
	$st['alerts'] = array_map(function ($a) {
		return $a + array('title' => FLEET_ALERT_EVENTS[$a['event']][0] ?? $a['event'], 'when' => date('Y-m-d H:i', (int)$a['time']));
	}, $st['alerts']);
	$sstrings = array('cpu' => gettext('CPU'), 'memory' => gettext('Memory'), 'in' => gettext('In'), 'out' => gettext('Out'), 'delay' => gettext('Latency'),
	    'stddev' => gettext('Jitter'), 'loss' => gettext('Loss'), 'states' => gettext('States'), 'temp' => gettext('Temperature'), 'warn_temp' => gettext('80 °C'),
	    'critical' => gettext('Critical'), 'warning' => gettext('Warning'), 'info' => gettext('Info'), 'backups' => gettext('Backups'),
	    'online' => gettext('Online'), 'degraded' => gettext('Degraded'), 'offline' => gettext('Offline'), 'new' => gettext('Joining'), 'none' => gettext('Not in the fleet'),
	    'nothing' => gettext('Nothing in this range.'), 'no_history' => gettext('No history for this range yet.'), 'no_gw' => gettext('This firewall has no gateway with quality history.'),
	    'no_samples' => gettext('No samples yet. The controller samples this firewall every 5 minutes.'), 'no_temp' => gettext('This firewall reports no temperature sensor.'),
	    'offline_now' => gettext('The firewall is offline; this comes back when it answers again.'), 'avg' => gettext('average %s'), 'peak' => gettext('peak %s'),
	    'limit' => gettext('limit %s'), 'none_out' => gettext('No outages in the last 30 days.'), 'none_alerts' => gettext('No alerts in the last 30 days.'));
	$sh = function (string $icon, string $tone, string $title, string $sum = '') {
		return '<header class="fs-fleet-cp-head"><span class="fs-fleet-cp-icon fs-fc-' . $tone . '"><i class="fa-solid ' . $icon . '" aria-hidden="true"></i></span><h3>' .
		    htmlspecialchars($title) . '</h3><span class="fs-fleet-cp-sum"' . (($sum === '') ? '' : ' data-sum="' . $sum . '"') . '></span></header>';
	};
?>
<div id="fs-fleet-bstats" data-node="<?=htmlspecialchars($box['node_id'])?>" data-range="<?=$srange?>" data-strings="<?=htmlspecialchars(json_encode($sstrings))?>">
	<div class="fs-fleet-dash-controls">
		<nav class="btn-group btn-group-sm" aria-label="<?=gettext('Range')?>">
<?php foreach (array('1h' => gettext('1 hour'), '24h' => gettext('24 hours'), '7d' => gettext('7 days'), '30d' => gettext('30 days')) as $rk => $rl): ?>
			<a class="btn btn-outline-secondary" href="<?=$here('stats', array('range' => $rk))?>"<?=($rk === $srange) ? ' aria-current="true"' : ''?>><?=$rl?></a>
<?php endforeach; ?>
		</nav>
	</div>
	<h2 class="fs-fleet-section"><i class="fa-solid fa-heart-pulse" aria-hidden="true"></i><?=gettext('Availability')?></h2>
	<ul class="fs-fleet-strip fs-fleet-strip--quiet">
<?php foreach (array('24h' => gettext('24 hours'), '7d' => gettext('7 days'), '30d' => gettext('30 days')) as $rk => $rl): $ap = $st['avail'][$rk]; ?>
		<li><span class="fs-fleet-strip-item"><span class="fs-fleet-cp-icon fs-fc-<?=($ap === null) ? 'neutral' : (($ap < 95) ? 'block' : (($ap < 99.5) ? 'warn' : 'pass'))?>"><i class="fa-solid fa-heart-pulse" aria-hidden="true"></i></span>
			<span class="fs-fleet-strip-v"><?=($ap === null) ? '-' : $ap . ' %'?></span><span class="fs-fleet-strip-l"><?=$rl?></span></span></li>
<?php endforeach; ?>
		<li><span class="fs-fleet-strip-item"><span class="fs-fleet-cp-icon fs-fc-<?=empty($st['outages']) ? 'neutral' : 'warn'?>"><i class="fa-solid fa-plug-circle-xmark" aria-hidden="true"></i></span>
			<span class="fs-fleet-strip-v"><?=count($st['outages'])?></span><span class="fs-fleet-strip-l"><?=gettext('outages, 30 days')?></span></span></li>
	</ul>
	<div class="fs-fleet-charts">
		<section class="fs-fleet-cp is-wide"><?=$sh('fa-wave-square', 'pass', gettext('Last 30 days'))?><div class="fs-fleet-cp-body" data-chart="days"></div></section>
		<section class="fs-fleet-cp is-wide"><?=$sh('fa-plug-circle-xmark', 'block', gettext('Outages'))?>
<?php if (empty($st['outages'])): ?>
			<p class="fs-fleet-quiet mb-0"><i class="fa-solid fa-circle-check" aria-hidden="true"></i><?=gettext('No outages in the last 30 days.')?></p>
<?php else: ?>
			<ul class="fs-fleet-attn-list">
<?php foreach (array_slice($st['outages'], 0, 8) as $o): ?>
				<li><?=fs_badge('down', fleet_uptime_text(max(60, $o['to'] - $o['from'])))?> <span><?=htmlspecialchars(date('Y-m-d H:i', $o['from']) . ' – ' . date('H:i', $o['to']))?></span></li>
<?php endforeach; ?>
			</ul>
<?php endif; ?>
		</section>
	</div>
	<h2 class="fs-fleet-section"><i class="fa-solid fa-gauge-high" aria-hidden="true"></i><?=gettext('Load')?></h2>
	<div class="fs-fleet-charts">
		<section class="fs-fleet-cp"><?=$sh('fa-microchip', 'c1', gettext('CPU and memory'), 'sys')?><div class="fs-fleet-cp-body" data-chart="sys"></div></section>
		<section class="fs-fleet-cp"><?=$sh('fa-table-list', 'c7', gettext('State table'), 'states')?><div class="fs-fleet-cp-body" data-chart="states"></div></section>
		<section class="fs-fleet-cp"><?=$sh('fa-temperature-half', 'c8', gettext('Temperature'), 'temp')?><div class="fs-fleet-cp-body" data-chart="temp"></div></section>
	</div>
	<h2 class="fs-fleet-section"><i class="fa-solid fa-network-wired" aria-hidden="true"></i><?=gettext('Network')?></h2>
	<div class="fs-fleet-charts">
		<section class="fs-fleet-cp is-wide"><?=$sh('fa-right-left', 'c6', gettext('Traffic'), 'traffic')?>
			<div class="fs-fleet-chips" data-ifs role="group" aria-label="<?=gettext('Interface')?>"></div>
			<div class="fs-fleet-cp-body" data-chart="traffic"></div></section>
		<section class="fs-fleet-cp is-wide"><?=$sh('fa-route', 'c3', gettext('Gateway quality'), 'gw')?><div class="fs-fleet-cp-body" data-chart="gw"></div></section>
	</div>
	<h2 class="fs-fleet-section"><i class="fa-solid fa-clock-rotate-left" aria-hidden="true"></i><?=gettext('Activity, 30 days')?></h2>
	<div class="fs-fleet-charts">
		<section class="fs-fleet-cp"><?=$sh('fa-bell', 'warn', gettext('Alerts per day'), 'alerts')?><div class="fs-fleet-cp-body" data-chart="alerts"></div>
<?php if (!empty($st['alerts'])): ?>
			<ul class="fs-fleet-attn-list mt-3 small">
<?php foreach ($st['alerts'] as $a): ?>
				<li><?=fs_badge(($a['severity'] === 'critical') ? 'down' : (($a['severity'] === 'warning') ? 'warn' : 'info'), ucfirst($a['severity']))?> <span><?=htmlspecialchars($a['title'])?> <span class="fs-muted"><?=htmlspecialchars($a['when'])?></span></span></li>
<?php endforeach; ?>
			</ul>
<?php endif; ?>
		</section>
		<section class="fs-fleet-cp"><?=$sh('fa-box-archive', 'c4', gettext('Backups per day'), 'backups')?><div class="fs-fleet-cp-body" data-chart="backups"></div></section>
	</div>
	<script type="application/json" data-fleet-json><?=json_encode($st, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES)?></script>
</div>
<script src="<?=$asset('fleet-charts.js')?>"></script>
<script src="<?=$asset('fleet-box-stats.js')?>"></script>
<?php elseif ($view === 'updates'):
	$uinfo = fleet_update_info($box);
	$protected = isset($st['rollback_protection']) ? (bool)$st['rollback_protection'] : null;
	$ureview = $manage && fleet_manage_allowed($box) && (($_GET['review'] ?? '') === 'update') && ($uinfo !== null) && $uinfo['available'];
	$checks = array();
	$check_error = null;
	if ($ureview) {
		try {
			$checks = fleet_update_preflight($box);
		} catch (RuntimeException $e) {
			$check_error = $e->getMessage();
		}
	}
	$blocked = !empty(array_filter($checks, function ($c) { return $c['state'] === 'fail'; })) || ($check_error !== null);
?>
<?php if ($ureview): ?>
<div class="panel panel-default fs-fleet-review" role="region" aria-labelledby="review-title">
	<div class="panel-heading"><h2 id="review-title" class="panel-title"><?=sprintf(htmlspecialchars(gettext('Update %1$s to %2$s?')), htmlspecialchars($box['label']), htmlspecialchars(fleet_version_number($uinfo['latest'])))?></h2></div>
	<div class="panel-body fs-fleet-pad">
<?php if ($protected === false): ?>
		<p class="fs-fleet-lead"><?=fs_badge('warn', gettext('No rollback'))?> <?=gettext('This firewall runs on UFS: the update runs in place and cannot roll back. If it fails, the firewall must be reinstalled and its configuration restored from Fleet. A backup is taken first.')?></p>
<?php else: ?>
		<p class="fs-fleet-lead"><?=gettext('The firewall downloads the update, saves its running system as a boot environment and restarts on the new version. If the new version fails its health check, it goes back to the old one by itself. It stops forwarding while it restarts, usually for a few minutes.')?></p>
<?php endif; ?>
		<h3 class="fs-fleet-subtitle"><?=gettext('Checks on the firewall')?></h3>
<?php if ($check_error !== null): ?>
		<p class="fs-fleet-problem"><?=htmlspecialchars($check_error)?></p>
<?php else: ?>
		<ul class="fs-fleet-checks">
<?php foreach ($checks as $c): ?>
			<li><?=fs_badge(array('pass' => 'pass', 'warn' => 'warn', 'fail' => 'block')[$c['state']] ?? 'neutral', array('pass' => gettext('OK'), 'warn' => gettext('Note'), 'fail' => gettext('Blocks'))[$c['state']] ?? $c['state'])?>
				<strong><?=htmlspecialchars((string)$c['label'])?></strong> <span class="fs-muted"><?=htmlspecialchars((string)($c['detail'] ?? ''))?></span></li>
<?php endforeach; ?>
		</ul>
<?php endif; ?>
	</div>
	<div class="panel-footer">
		<form method="post" action="<?=$here('updates')?>" class="fs-fleet-review-actions">
			<button class="btn btn-primary" type="submit" name="update_start" value="1"<?=$blocked ? ' disabled' : ''?>><i class="fa-solid fa-download icon-embed-btn" aria-hidden="true"></i><?=sprintf(gettext('Update to %s now'), htmlspecialchars(fleet_version_number($uinfo['latest'])))?></button>
			<a class="btn btn-outline-secondary" href="<?=$here('updates')?>"><?=gettext('Cancel')?></a>
<?php if ($blocked): ?>
			<span class="fs-muted small"><?=gettext('A check blocks the update. Fix it on the firewall, then check again.')?></span>
<?php endif; ?>
		</form>
	</div>
</div>
<?php endif; ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('System version')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<dl class="fs-fleet-facts">
			<dt><?=gettext('Running')?></dt><dd><?=htmlspecialchars((string)($st['version'] ?? '-'))?></dd>
<?php if ($uinfo === null): ?>
			<dt><?=gettext('Latest')?></dt><dd class="fs-muted"><?=gettext('Not checked yet')?></dd>
<?php elseif ($uinfo['error'] !== null): ?>
			<dt><?=gettext('Latest')?></dt><dd><span class="fs-fleet-problem"><?=htmlspecialchars($uinfo['error'])?></span></dd>
<?php else: ?>
			<dt><?=gettext('Latest')?></dt><dd><?=htmlspecialchars(fleet_version_number($uinfo['latest']))?> <?=$uinfo['available'] ? fs_badge('info', gettext('Update available')) : '<span class="fs-fleet-ok">' . gettext('Up to date') . '</span>'?></dd>
			<dt><?=gettext('Channel')?></dt><dd><?=htmlspecialchars($uinfo['channel'] !== '' ? $uinfo['channel'] : '-')?></dd>
<?php endif; ?>
			<dt><?=gettext('Rollback protection')?></dt><dd><?=($protected === null) ? '<span class="fs-muted">-</span>' : ($protected ? gettext('Yes (ZFS boot environments)') : fs_badge('warn', gettext('No (UFS)')))?></dd>
			<dt><?=gettext('Checked')?></dt><dd><?=($uinfo === null) ? '-' : htmlspecialchars(date('Y-m-d H:i', (int)$uinfo['checked']))?></dd>
		</dl>
	</div>
<?php if ($manage): ?>
	<div class="panel-footer">
		<form method="post" action="<?=$here('updates')?>" class="fs-fleet-review-actions">
			<button class="btn btn-sm btn-outline-secondary" type="submit" name="update_check" value="1"<?=($state === 'offline') ? ' disabled' : ''?>><i class="fa-solid fa-rotate icon-embed-btn" aria-hidden="true"></i><?=gettext('Check now')?></button>
<?php if (($uinfo !== null) && $uinfo['available'] && fleet_manage_allowed($box) && !$ureview): ?>
			<a class="btn btn-sm btn-primary" href="<?=$here('updates', array('review' => 'update'))?>"><i class="fa-solid fa-download icon-embed-btn" aria-hidden="true"></i><?=sprintf(gettext('Update to %s...'), htmlspecialchars(fleet_version_number($uinfo['latest'])))?></a>
<?php endif; ?>
		</form>
	</div>
<?php endif; ?>
</div>
<p class="fs-fleet-hint"><?=gettext('The firewall checks its own update channel (System > Update on the firewall). Several firewalls at once: a group\'s menu on the dashboard, Update.')?></p>

<?php elseif ($view === 'policies'):
	$peff = fleet_box_effective($box['node_id']);
	$pq = fleet_db()->prepare('SELECT * FROM compliance WHERE node_id = ?');
	$pq->execute(array($box['node_id']));
	$pres = array_column($pq->fetchAll(), null, 'rule_id');
	$pnames = array_column(fleet_policies_all(), 'name', 'id');
	$prem = fleet_remediations()[$box['node_id']] ?? array();
	$pfixable = 0;
	foreach ($peff as $prid => $pe) {
		$pfixable += (($pe[1] === 'remediate') && (($pres[$prid]['state'] ?? '') === 'fail')) ? 1 : 0;
	}
	$pbadge = array('pass' => fs_badge('pass', gettext('Pass')), 'fail' => fs_badge('block', gettext('Fails')), 'unknown' => fs_badge('neutral', gettext('Unknown')),
	    'excepted' => fs_badge('info', gettext('Exception')));
?>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Policy rules for this firewall')?> <span class="fs-count"><?=count($peff)?></span></h2>
		<span><?php if ($manage && ($pfixable > 0) && fleet_manage_allowed($box)): ?>
			<form method="post" action="?id=<?=urlencode($box['node_id'])?>&amp;view=policies" class="d-inline"><button class="btn btn-sm btn-primary" name="policy_fix" value="1"><i class="fa-solid fa-wrench icon-embed-btn" aria-hidden="true"></i><?=sprintf(ngettext('Fix %d rule now', 'Fix %d rules now', $pfixable), $pfixable)?></button></form>
<?php endif; ?>
		<a class="btn btn-sm btn-link" href="/fleet/fleet_policies.php?view=policies"><?=gettext('Policies...')?></a></span></div>
<?php if (empty($peff)): ?>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint mb-0"><?=gettext('No policy covers this firewall. Add a policy for all firewalls, one of its groups, or this firewall.')?></p></div>
<?php else: ?>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Rule')?></th><th><?=gettext('State')?></th><th><?=gettext('Found')?></th><th><?=gettext('Mode')?></th><th><?=gettext('From policy')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php foreach ($peff as $rid => list($params, $mode, $pid, $pname, $conflict)): $res = $pres[$rid] ?? null; ?>
		<tr><td><?=htmlspecialchars(fleet_policy_rule_title($rid, $params))?> <span class="fs-muted small"><?=htmlspecialchars(preg_replace('/:\d+$/', '', $rid))?></span></td>
			<td><?=($res === null) ? '<span class="fs-muted">' . gettext('Not checked yet') . '</span>' : ($pbadge[$res['state']] ?? htmlspecialchars($res['state']))?></td>
			<td class="small"><?=htmlspecialchars((string)($res['detail'] ?? ''))?></td>
			<td><?=($mode === 'lock') ? '<i class="fa-solid fa-lock" aria-hidden="true"></i> ' . gettext('Lock') : (($mode === 'remediate') ? '<i class="fa-solid fa-wrench" aria-hidden="true"></i> ' . gettext('Fix') .
			    (isset($prem[$rid]) ? '<div class="small ' . (($prem[$rid]['result'] === 'fixed') ? 'fs-muted' : 'fs-fleet-problem') . '">' . htmlspecialchars(date('m-d H:i', (int)$prem[$rid]['time']) . ': ' . $prem[$rid]['detail']) . '</div>' : '') :
			    '<span class="fs-muted">' . gettext('Audit') . '</span>')?></td>
			<td><a href="/fleet/fleet_policies.php?view=edit&amp;id=<?=(int)$pid?>"><?=htmlspecialchars($pname)?></a>
				<?=($conflict !== null) ? fs_badge('warn', sprintf(gettext('Conflicts with %s'), $conflict)) : ''?></td>
			<td class="text-end"><?php if ($manage && (($res['state'] ?? '') === 'fail')): ?><a class="btn btn-sm btn-link" href="/fleet/fleet_policies.php?view=exceptions&amp;node=<?=urlencode($box['node_id'])?>&amp;rule=<?=urlencode($rid)?>"><?=gettext('Exception...')?></a><?php endif; ?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php endif; ?>
	<div class="panel-footer small fs-muted"><?=gettext('Checked every 15 minutes against what the firewall reports and its newest configuration backup.')?>
<?php $bs = fleet_bundle_state()[$box['node_id']] ?? null; $bst = json_decode((string)($box['status'] ?? ''), true) ?: array(); $bg = $bst['breakglass'] ?? null; ?>
<?php if ($bs !== null): ?>
		<div class="mt-1"><?=!empty($bs['error']) ? '<span class="fs-fleet-problem">' . htmlspecialchars(sprintf(gettext('Policy rules not on the firewall yet: %s'), $bs['error'])) . '</span>' :
		    htmlspecialchars(sprintf(gettext('%1$d lock and fix rules held on the firewall since %2$s.'), (int)$bs['rules'], date('Y-m-d H:i', (int)$bs['sent'])))?></div>
<?php endif; ?>
<?php if (is_array($bg) && !empty($bg['until'])): ?>
		<div class="mt-1"><?=fs_badge('warn', gettext('Break-glass'))?> <?=htmlspecialchars(sprintf(gettext('Lock suspended on the firewall until %1$s by %2$s: %3$s'), date('Y-m-d H:i', (int)$bg['until']), (string)($bg['by'] ?? '?'), (string)($bg['reason'] ?? '')))?></div>
<?php endif; ?>
	</div>
</div>

<?php elseif ($view === 'manage'):
	$review = (string)($_GET['review'] ?? '');
	$offline = ($state === 'offline');
?>
<?php if (!fleet_manage_allowed($box)): ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Manage')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=gettext('This firewall joined as Monitor only: the controller reads its status and backups but may not change it. To manage it from here, let it leave the fleet and invite it again with Managed access.')?></p>
	</div>
</div>
<?php else: ?>
<?php if (in_array($review, array('reboot', 'states'), true)): ?>
<div class="panel panel-default fs-fleet-review" role="region" aria-labelledby="review-title">
	<div class="panel-heading"><h2 id="review-title" class="panel-title"><?=($review === 'reboot') ? sprintf(gettext('Reboot %s?'), htmlspecialchars($box['label'])) : sprintf(gettext('Reset the state table on %s?'), htmlspecialchars($box['label']))?></h2></div>
	<div class="panel-body fs-fleet-pad">
<?php if ($review === 'reboot'): ?>
		<p class="fs-fleet-lead"><?=gettext('The firewall stops forwarding while it restarts, usually for one to three minutes. A CARP backup takes over where there is one. It comes back by itself; the dashboard shows when it is online again.')?></p>
<?php else: ?>
		<p class="fs-fleet-lead"><?=gettext('Every connection through the firewall is dropped and has to start again: calls, downloads and VPN sessions are cut. The management tunnel reconnects by itself.')?></p>
<?php endif; ?>
	</div>
	<div class="panel-footer">
		<form method="post" action="<?=$here('manage')?>" class="fs-fleet-review-actions">
			<button class="btn btn-primary" type="submit" name="manage_action" value="<?=$review === 'reboot' ? 'reboot' : 'states'?>"<?=$offline ? ' disabled' : ''?>><i class="fa-solid <?=($review === 'reboot') ? 'fa-power-off' : 'fa-arrow-rotate-right'?> icon-embed-btn" aria-hidden="true"></i><?=($review === 'reboot') ? gettext('Reboot now') : gettext('Reset the state table')?></button>
			<a class="btn btn-outline-secondary" href="<?=$here('manage')?>"><?=gettext('Cancel')?></a>
		</form>
	</div>
</div>
<?php endif; ?>

<div class="row g-3 fs-fleet-panels">
	<div class="col-lg-6">
		<div class="panel panel-default h-100">
			<div class="panel-heading"><h2 class="panel-title"><?=gettext('Power')?></h2></div>
			<div class="panel-body fs-fleet-pad">
				<p class="fs-fleet-lead"><?=gettext('Restart the firewall. You see what happens before anything is done.')?></p>
				<a class="btn btn-outline-secondary<?=$offline ? ' disabled' : ''?>" href="<?=$here('manage', array('review' => 'reboot'))?>"><i class="fa-solid fa-power-off icon-embed-btn" aria-hidden="true"></i><?=gettext('Reboot')?>&hellip;</a>
			</div>
			<div class="panel-footer small fs-muted"><?=gettext('Shutting down is not offered: a firewall that is off cannot be started again from here.')?></div>
		</div>
	</div>
	<div class="col-lg-6">
		<div class="panel panel-default h-100">
			<div class="panel-heading"><h2 class="panel-title"><?=gettext('State table')?></h2></div>
			<div class="panel-body fs-fleet-pad">
				<p class="fs-fleet-lead"><?=gettext('Drop every connection through the firewall, for example after changing rules that existing connections still bypass.')?></p>
				<a class="btn btn-outline-secondary<?=$offline ? ' disabled' : ''?>" href="<?=$here('manage', array('review' => 'states'))?>"><i class="fa-solid fa-arrow-rotate-right icon-embed-btn" aria-hidden="true"></i><?=gettext('Reset the state table')?>&hellip;</a>
			</div>
		</div>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Services')?></h2></div>
<?php
	try {
		/* Right after a reboot the box is going down: asking it for its services would only wait for a timeout. */
		$services = ($offline || $rebooting) ? null : fleet_box_services($box);
		$svc_error = $rebooting ? gettext('The firewall is rebooting. Its services show here again when it is back.') : ($offline ? gettext('The firewall is offline.') : null);
	} catch (RuntimeException $e) {
		$services = null;
		$svc_error = $e->getMessage();
	}
?>
<?php if ($services === null): ?>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-problem"><?=htmlspecialchars($svc_error)?></p></div>
<?php elseif (empty($services)): ?>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=gettext('No services are enabled on this firewall.')?></p></div>
<?php else: ?>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Service')?></th><th><?=gettext('Status')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php foreach ($services as $svc): ?>
		<tr><td><?=htmlspecialchars($svc['description'] ?: $svc['name'])?> <span class="fs-muted small fs-mono"><?=htmlspecialchars($svc['name'])?></span></td>
			<td><?=$svc['running'] ? '<span class="fs-fleet-ok">' . gettext('Running') . '</span>' : fs_badge('down', gettext('Stopped'))?></td>
			<td class="text-end text-nowrap">
				<form method="post" action="<?=$here('manage')?>" class="d-inline">
					<input type="hidden" name="service" value="<?=htmlspecialchars($svc['name'])?>"/>
					<input type="hidden" name="vpnid" value="<?=htmlspecialchars((string)($svc['vpnid'] ?? ''))?>"/>
					<input type="hidden" name="zone" value="<?=htmlspecialchars((string)($svc['zone'] ?? ''))?>"/>
<?php if ($svc['running']): ?>
					<button class="btn btn-sm btn-link" name="manage_action" value="restart"><i class="fa-solid fa-arrow-rotate-right icon-embed-btn" aria-hidden="true"></i><?=gettext('Restart')?></button>
					<button class="btn btn-sm btn-link" name="manage_action" value="stop"><i class="fa-solid fa-stop icon-embed-btn" aria-hidden="true"></i><?=gettext('Stop')?></button>
<?php else: ?>
					<button class="btn btn-sm btn-link" name="manage_action" value="start"><i class="fa-solid fa-play icon-embed-btn" aria-hidden="true"></i><?=gettext('Start')?></button>
<?php endif; ?>
				</form>
			</td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php endif; ?>
	<div class="panel-footer small fs-muted"><?=gettext('The services as the firewall reports them now, like Status > Services on the firewall itself.')?></div>
</div>
<?php endif; ?>

<?php else: ?>
<?=fleet_list_filterbar(array('id' => $box['node_id'], 'view' => 'events'), $ev_filters,
    array('type' => array(gettext('Any event'), $ev_types), 'since' => array(gettext('Any time'), FLEET_OPS_SINCE)), gettext('Search events'), gettext('Search events'))?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Events')?> <span class="fs-count"><?=(int)$ev_page['total']?></span></h2></div>
	<div class="panel-body fs-fleet-pad">
<?php if (empty($events)): ?>
		<p class="fs-fleet-hint"><?=!empty($ev_filters) ? gettext('No event matches these filters.') : gettext('Nothing has happened to this firewall yet.')?></p>
<?php else: ?>
		<ol class="fs-fleet-events">
<?php foreach ($events as $ev): ?>
<?php list($what, $more) = fleet_event_text($box['node_id'], $ev['action'], $ev['detail']); ?>
			<li><time class="fs-muted" datetime="<?=date('c', (int)$ev['time'])?>"><?=htmlspecialchars(date('Y-m-d H:i', (int)$ev['time']))?></time>
				<span><?=htmlspecialchars($what)?><?php if ($more !== ''): ?> <span class="fs-muted"><?=htmlspecialchars($more)?></span><?php endif; ?></span>
				<span class="fs-muted"><?=in_array($ev['who'], array('poll', 'system', 'enrollment'), true) ? '' : htmlspecialchars($ev['who'])?></span></li>
<?php endforeach; ?>
		</ol>
<?php endif; ?>
	</div>
	<div class="panel-footer"><?=fleet_list_pager($ev_page, array('id' => $box['node_id'], 'view' => 'events'), $ev_filters)?></div>
</div>
<?php endif; ?>
<script src="/fleet/assets/fleet-list.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-list.js')?>"></script>
<?php include('foot.inc');
