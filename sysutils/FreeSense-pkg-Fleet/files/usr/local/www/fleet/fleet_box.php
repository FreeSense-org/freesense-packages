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

$views = array('overview' => gettext('Overview'), 'updates' => gettext('Updates'), 'backups' => gettext('Backups'), 'manage' => gettext('Manage'),
    'events' => gettext('Events'));
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
					<dt><?=gettext('CARP')?></dt><dd><?=(($st['carp'] ?? 'none') === 'none') ? gettext('Not used') : ((($st['carp'] ?? '') === 'ok') ? gettext('OK') : fs_badge('degraded', (string)$st['carp']))?></dd>
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
	$backups = fleet_backup_list($box['node_id']);
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
					<span class="fs-muted"><?=htmlspecialchars(fleet_backup_reason_text($b['reason']))?>, <?=htmlspecialchars(format_bytes((int)$b['size']))?></span></span>
				<span class="fs-fleet-backup-actions">
<?php if ($prev !== null): ?>
					<a class="btn btn-sm btn-link" href="<?=$here('backups', ($diff_id === (int)$b['id']) ? array() : array('diff' => (int)$b['id']))?>"<?=($diff_id === (int)$b['id']) ? ' aria-expanded="true"' : ''?>><?=($diff_id === (int)$b['id']) ? gettext('Hide changes') : gettext('Changes')?></a>
<?php endif; ?>
					<a class="btn btn-sm btn-link" href="<?=$here('backups', array('download' => (int)$b['id']))?>"><i class="fa-solid fa-download icon-embed-btn" aria-hidden="true"></i><?=gettext('Download')?></a>
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
