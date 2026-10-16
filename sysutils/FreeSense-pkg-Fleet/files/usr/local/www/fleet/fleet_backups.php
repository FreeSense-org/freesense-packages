<?php
/*
 * fleet_backups.php
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
 * Backups across the fleet: each firewall's backups at a glance
 * (Overview), and the backup sets that decide how many are kept (Sets).
 * Taking backups is the change, nightly and scheduled backups; one
 * firewall's own backups are on its page. Copies: the recovery key and
 * the copies on other firewalls (fleet_replicas.inc). Recover fleet works
 * on a controller that is not set up yet.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Backups'));
$who = (string)($_SESSION['Username'] ?? 'admin');
$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$manage = isAllowedPage('fleet/fleet.php');
$input_errors = array();
$savemsg = null;
$reopen = null;
$view = fs_view_param(array('overview', 'sets', 'copies', 'recover'), $ready ? 'overview' : 'recover');
if (!$ready && ($view !== 'recover')) {
	$view = 'recover';
}
$new_key = null;
$recover_dir = FLEET_DATA . '/recover-upload';
$recover_preview = null;

/* Recover fleet: upload, open with the recovery key, preview; then restore. Works before Fleet is set up. */
if ($manage && ($_SERVER['REQUEST_METHOD'] === 'POST') && (isset($_POST['recover_open']) || isset($_POST['recover_apply']))) {
	$view = 'recover';
	try {
		if (($err = fleet_data_prepare()) !== null) {
			throw new RuntimeException($err);
		}
		if (isset($_POST['recover_open']) && (($_POST['source'] ?? 'file') === 'offsite')) {
			exec('rm -rf ' . escapeshellarg($recover_dir));
			@mkdir($recover_dir, 0700, true);
			if (fleet_offsite_fetch((string)($_POST['offsite_target'] ?? ''), $recover_dir) === 0) {
				throw new RuntimeException(gettext('FLEET-E805: That storage holds no Fleet copies.'));
			}
		} elseif (isset($_POST['recover_open'])) {
			$up = $_FILES['archive'] ?? null;
			if (!is_array($up) || ($up['error'] !== UPLOAD_ERR_OK) || !is_uploaded_file($up['tmp_name'])) {
				throw new RuntimeException(gettext('Choose the .fsfa file: downloaded from a firewall (System > Central Management) or exported by a controller.'));
			}
			exec('rm -rf ' . escapeshellarg($recover_dir));
			@mkdir($recover_dir, 0700, true);
			list($rc) = fleet_ctl_exec(array('/usr/bin/tar', '-xzf', $up['tmp_name'], '-C', $recover_dir));
			if ($rc !== 0) {
				throw new RuntimeException(gettext('FLEET-E805: That file is not a Fleet archive.'));
			}
		}
		$opened = fleet_recover_open($recover_dir, (string)($_POST['recovery_key'] ?? ''));
		if (isset($_POST['recover_apply'])) {
			$settings = fleet_recover_apply($opened, !empty($_POST['replace']), $who);
			if (!empty($settings) && function_exists('config_set_path')) {
				config_set_path('installedpackages/fleet/config/0', $settings);
				write_config(gettext('Fleet: settings restored by Recover fleet'));
			}
			exec('rm -rf ' . escapeshellarg($recover_dir));
			$savemsg = gettext('The fleet is back: database, keys and backups. Open Settings and save once to start the controller; the firewalls reconnect to it by themselves when it has the same address.');
			$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
		} else {
			$recover_preview = fleet_recover_summary($opened);
		}
	} catch (InvalidArgumentException | RuntimeException $e) {
		$input_errors[] = $e->getMessage();
	}
}

if ($ready && $manage && ($_SERVER['REQUEST_METHOD'] === 'POST')) {
	try {
		if (isset($_POST['set_save'])) {
			$view = 'sets';
			fleet_backup_set_save(((int)($_POST['set_id'] ?? 0) > 0) ? (int)$_POST['set_id'] : null, $_POST, $who);
			$savemsg = gettext('Backup set saved. Old backups beyond its rule are removed after the next nightly backup.');
		} elseif (isset($_POST['set_delete'])) {
			$view = 'sets';
			fleet_backup_set_delete((int)$_POST['set_delete'], $who);
			$savemsg = gettext('Backup set deleted.');
		} elseif (isset($_POST['recovery_create'])) {
			$view = 'copies';
			$new_key = fleet_recovery_create($who);
		} elseif (isset($_POST['peers_save'])) {
			$view = 'copies';
			fleet_replica_targets_set(array_values((array)($_POST['targets'] ?? array())), $who);
			$savemsg = empty(fleet_replica_targets()) ? gettext('Copies on other firewalls are off.') : gettext('Saved. The copies are made with the next sync (after the nightly backup, or Sync now).');
		} elseif (isset($_POST['offsite_save'])) {
			$view = 'copies';
			fleet_offsite_ids_set(array_values((array)($_POST['offsite'] ?? array())), $who);
			$savemsg = empty(fleet_offsite_ids()) ? gettext('Off-site copies are off.') : gettext('Saved. The off-site copies are made with the next sync.');
		} elseif (isset($_POST['sync'])) {
			$view = 'copies';
			mwexec_bg('/usr/local/bin/php /usr/local/sbin/freesense-fleet-backup replicate ' . escapeshellarg($who));
			$savemsg = gettext('Sync started. Activity shows each firewall.');
		} elseif (isset($_POST['verify'])) {
			$view = 'copies';
			$res = fleet_backup_verify_all($who);
			$bad = count(array_filter($res, function ($r) { return !empty($r['problems']); }));
			$savemsg = ($bad === 0) ? sprintf(gettext('Tested the backups of %d firewalls: all could be restored.'), count($res)) :
			    sprintf(gettext('Tested %1$d firewalls: %2$d have a backup that could not be restored. See below.'), count($res), $bad);
		} elseif (isset($_POST['export'])) {
			$file = fleet_archive_export();
			fleet_audit($who, 'replicas', 'All backups exported as a Fleet archive');
			header('Content-Type: application/gzip');
			header('Content-Disposition: attachment; filename="fleet-' . date('Ymd-His') . '.fsfa"');
			header('Content-Length: ' . filesize($file));
			header('Cache-Control: no-store');
			readfile($file);
			@unlink($file);
			exit;
		} elseif (isset($_POST['prune'])) {
			list($n, $bytes) = fleet_backup_prune($who);
			$savemsg = ($n === 0) ? gettext('Nothing to remove: every backup is still kept by a rule.') :
			    sprintf(gettext('%1$d old backups removed (%2$s).'), $n, format_bytes($bytes));
		}
	} catch (InvalidArgumentException | RuntimeException $e) {
		$input_errors[] = $e->getMessage();
		if (isset($_POST['set_save'])) {
			$reopen = array('set_id' => (string)($_POST['set_id'] ?? ''), 'name' => (string)($_POST['name'] ?? ''),
			    'targets[]' => array_values((array)($_POST['targets'] ?? array()))) + array_intersect_key($_POST, array_flip(array('keep_last', 'keep_daily', 'keep_weekly', 'keep_monthly')));
		}
	}
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
		array(gettext('Backups'), true, '/fleet/fleet_backups.php'),
		array(gettext('Policies'), false, '/fleet/fleet_policies.php'),
		array(gettext('Templates'), false, '/fleet/fleet_templates.php'),
		array(gettext('Users'), false, '/fleet/fleet_users.php'),
		array(gettext('Firewalls'), false, '/fleet/fleet.php'),
		array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
	);
	display_top_tabs($tab_array);
}
if ($ready) {
	fs_view_switch(array('overview' => gettext('Overview'), 'sets' => gettext('Sets'), 'copies' => gettext('Copies'), 'recover' => gettext('Recover fleet')), $view);
}
if ($view === 'recover'):
	$has_boxes = is_file(FLEET_DATA . '/fleet.db') && ((int)fleet_db()->query('SELECT COUNT(*) FROM boxes')->fetchColumn() > 0);
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Recover fleet')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=gettext('Bring a lost controller back on this firewall: its firewalls, groups, settings, keys and every backup. You need the fleet\'s recovery key and a copy of the backups: download it from any firewall that keeps copies (System > Central Management on that firewall) or use an archive exported by the controller.')?></p>
<?php if ($recover_preview === null): ?>
		<form method="post" enctype="multipart/form-data" class="fs-fleet-form">
<?php $remote = fleet_offsite_available() ? remote_backup_targets() : array(); ?>
			<fieldset class="fs-fleet-field fs-fleet-field--wide"><legend class="form-label"><?=gettext('Where the copy is')?></legend>
				<label class="form-check"><input class="form-check-input" type="radio" name="source" value="file" checked/> <span class="form-check-label"><?=gettext('A file (.fsfa)')?></span></label>
				<input class="form-control mt-1" type="file" id="archive" name="archive" accept=".fsfa,application/gzip" aria-label="<?=gettext('Copy of the backups (.fsfa)')?>"/>
<?php if (!empty($remote)): ?>
				<label class="form-check mt-2"><input class="form-check-input" type="radio" name="source" value="offsite"/> <span class="form-check-label"><?=gettext('Off-site storage')?></span></label>
				<select class="form-select mt-1" name="offsite_target" aria-label="<?=gettext('Storage')?>">
<?php foreach ($remote as $t): ?>
					<option value="<?=htmlspecialchars($t['id'])?>"><?=htmlspecialchars(($t['descr'] ?: $t['id']) . ' (' . strtoupper($t['type']) . ')')?></option>
<?php endforeach; ?>
				</select>
<?php endif; ?>
				<div class="form-text"><?=gettext('Off-site storage: set it up again in System > Backup > Remote on this firewall first (the same bucket or server).')?></div>
			</fieldset>
			<div class="fs-fleet-field fs-fleet-field--wide"><label class="form-label" for="recovery_key"><?=gettext('Recovery key')?></label>
				<input class="form-control fs-mono" id="recovery_key" name="recovery_key" autocomplete="off" spellcheck="false" required placeholder="FRK-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"/></div>
			<div class="fs-fleet-field fs-fleet-field--button"><button class="btn btn-primary" type="submit" name="recover_open" value="1"><i class="fa-solid fa-unlock icon-embed-btn" aria-hidden="true"></i><?=gettext('Open and check')?></button></div>
		</form>
		<p class="fs-fleet-hint"><?=gettext('Nothing changes until you have seen what the copy holds.')?></p>
<?php else: ?>
		<div class="fs-fleet-review">
			<h3 class="fs-fleet-subtitle"><?=gettext('The copy opens with this key')?></h3>
			<dl class="fs-fleet-facts">
				<dt><?=gettext('Controller as of')?></dt><dd><?=htmlspecialchars(date('Y-m-d H:i', $recover_preview['created']))?></dd>
				<dt><?=gettext('Firewalls')?></dt><dd><?=(int)$recover_preview['boxes']?></dd>
				<dt><?=gettext('Backups')?></dt><dd><?=sprintf(gettext('%1$d of %2$d files present'), $recover_preview['backup_files'], $recover_preview['backup_rows'])?></dd>
			</dl>
			<form method="post" class="fs-fleet-review-actions">
				<input type="hidden" name="recovery_key" value="<?=htmlspecialchars((string)$_POST['recovery_key'])?>"/>
<?php if ($has_boxes): ?>
				<label class="form-check"><input class="form-check-input" type="checkbox" name="replace" value="1" required/> <span class="form-check-label"><?=gettext('This controller already has firewalls. Replace them all with the copy.')?></span></label>
<?php endif; ?>
				<button class="btn btn-primary" type="submit" name="recover_apply" value="1"><i class="fa-solid fa-life-ring icon-embed-btn" aria-hidden="true"></i><?=gettext('Recover the fleet')?></button>
				<a class="btn btn-outline-secondary" href="?view=recover"><?=gettext('Cancel')?></a>
			</form>
		</div>
<?php endif; ?>
	</div>
</div>
<?php include('foot.inc'); exit; endif;

$groups = fleet_groups_all();
$names = fleet_target_names();
$rules = fleet_backup_rules_by_box();
$now = time();
?>

<?php if ($view === 'overview'):
	$stats = array();
	foreach (fleet_db()->query('SELECT node_id, COUNT(*) AS n, SUM(size) AS bytes, MAX(time) AS last, SUM(pinned) AS pinned FROM backups GROUP BY node_id')->fetchAll() as $r) {
		$stats[$r['node_id']] = $r;
	}
	$boxes = fleet_db()->query('SELECT node_id, label, state FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll();
	$members = array();
	foreach (fleet_db()->query('SELECT group_id, node_id FROM box_groups')->fetchAll() as $m) {
		$members[(int)$m['group_id']][$m['node_id']] = true;
	}
	/* Old: no backup for longer than two nightly runs. */
	$stale_after = 2 * 86400;
	$state_of = function ($b) use ($stats, $now, $stale_after) {
		$last = (int)($stats[$b['node_id']]['last'] ?? 0);
		return ($last === 0) ? 'none' : ((($now - $last) > $stale_after) ? 'old' : 'ok');
	};
	/* Filters live in the URL, so a filtered list can be shared and survives a reload. */
	$q = trim((string)($_GET['q'] ?? ''));
	$fg = (int)($_GET['group'] ?? 0);
	$fs = in_array($_GET['state'] ?? '', array('ok', 'old', 'none'), true) ? (string)$_GET['state'] : '';
	$list = array_values(array_filter($boxes, function ($b) use ($q, $fg, $fs, $members, $state_of, $rules) {
		return (($q === '') || (stripos($b['label'] . ' ' . implode(' ', $rules[$b['node_id']][1] ?? array()), $q) !== false)) &&
		    (($fg === 0) || isset($members[$fg][$b['node_id']])) && (($fs === '') || ($state_of($b) === $fs));
	}));
	$counts = array('ok' => 0, 'old' => 0, 'none' => 0);
	foreach ($boxes as $b) {
		$counts[$state_of($b)]++;
	}
	$total_bytes = array_sum(array_column($stats, 'bytes'));
	$per = 50;
	$pages = max(1, (int)ceil(count($list) / $per));
	$page = min($pages, max(1, (int)($_GET['page'] ?? 1)));
	$shown = array_slice($list, ($page - 1) * $per, $per);
	$filtered = ($q !== '') || ($fg > 0) || ($fs !== '');
	$link = function (array $change) use ($q, $fg, $fs) {
		return '?' . htmlspecialchars(http_build_query(array_filter($change + array('view' => 'overview', 'q' => $q, 'group' => $fg ?: '', 'state' => $fs), 'strlen')));
	};
?>
<div class="fs-tiles fs-fleet-tiles-row">
	<a class="fs-tile fs-fleet-tile-link" href="<?=$link(array('state' => 'ok', 'page' => ''))?>"><span class="fs-tile-label"><?=gettext('Backed up in the last 2 days')?></span><span class="fs-tile-value"><?=$counts['ok']?></span></a>
	<a class="fs-tile fs-fleet-tile-link" href="<?=$link(array('state' => 'old', 'page' => ''))?>"><span class="fs-tile-label"><?=gettext('Older')?></span><span class="fs-tile-value"><?=$counts['old']?></span></a>
	<a class="fs-tile fs-fleet-tile-link" href="<?=$link(array('state' => 'none', 'page' => ''))?>"><span class="fs-tile-label"><?=gettext('No backup')?></span><span class="fs-tile-value"><?=$counts['none']?></span></a>
	<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Space used')?></span><span class="fs-tile-value"><?=htmlspecialchars(format_bytes((int)$total_bytes))?></span></div>
</div>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Backups by firewall')?></h2>
<?php if ($manage): ?>
		<form method="post" class="d-flex gap-2">
			<button class="btn btn-sm btn-outline-secondary" name="prune" value="1" title="<?=gettext('Runs by itself after every nightly backup')?>"><i class="fa-solid fa-broom icon-embed-btn" aria-hidden="true"></i><?=gettext('Remove old backups now')?></button>
		</form>
<?php endif; ?>
	</div>
	<div class="panel-body fs-fleet-pad">
		<form method="get" class="fs-fleet-filterbar" role="search">
			<input type="hidden" name="view" value="overview"/>
			<input class="form-control form-control-sm" type="search" name="q" value="<?=htmlspecialchars($q)?>" placeholder="<?=gettext('Search firewall or set')?>" aria-label="<?=gettext('Search firewalls')?>"/>
			<select class="form-select form-select-sm" name="group" aria-label="<?=gettext('Group')?>">
				<option value=""><?=gettext('Any group')?></option>
<?php foreach ($groups as $grp): ?>
				<option value="<?=(int)$grp['id']?>"<?=($fg === (int)$grp['id']) ? ' selected' : ''?>><?=htmlspecialchars($grp['name'])?></option>
<?php endforeach; ?>
			</select>
			<select class="form-select form-select-sm" name="state" aria-label="<?=gettext('Last backup')?>">
				<option value=""><?=gettext('Any last backup')?></option>
				<option value="ok"<?=($fs === 'ok') ? ' selected' : ''?>><?=gettext('In the last 2 days')?></option>
				<option value="old"<?=($fs === 'old') ? ' selected' : ''?>><?=gettext('Older')?></option>
				<option value="none"<?=($fs === 'none') ? ' selected' : ''?>><?=gettext('None')?></option>
			</select>
			<button class="btn btn-sm btn-outline-secondary" type="submit"><?=gettext('Filter')?></button>
<?php if ($filtered): ?>
			<a class="btn btn-sm btn-link" href="?view=overview"><?=gettext('Clear')?></a>
<?php endif; ?>
			<span class="fs-muted small ms-auto"><?=$filtered ? sprintf(gettext('%1$d of %2$d'), count($list), count($boxes)) : sprintf(ngettext('%d firewall', '%d firewalls', count($boxes)), count($boxes))?></span>
		</form>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Firewall')?></th><th><?=gettext('Last backup')?></th><th><?=gettext('Backups')?></th><th><?=gettext('Space')?></th><th><?=gettext('Kept by')?></th></tr></thead>
		<tbody>
<?php if (empty($shown)): ?>
		<tr><td colspan="5" class="fs-muted"><?=gettext('No firewall matches.')?> <a href="?view=overview"><?=gettext('Clear the filters')?></a></td></tr>
<?php endif; ?>
<?php foreach ($shown as $b): $st = $stats[$b['node_id']] ?? null; $s = $state_of($b); ?>
		<tr><td><a href="/fleet/fleet_box.php?id=<?=urlencode($b['node_id'])?>&amp;view=backups"><?=htmlspecialchars($b['label'])?></a></td>
			<td><?php if ($s === 'none'): ?><?=fs_badge('warn', gettext('None'))?><?php else: ?><?=htmlspecialchars(sprintf(gettext('%s ago'), fleet_op_duration($now - (int)$st['last'])))?><?=($s === 'old') ? ' ' . fs_badge('warn', gettext('Older than 2 days')) : ''?><?php endif; ?></td>
			<td><?=(int)($st['n'] ?? 0)?><?=((int)($st['pinned'] ?? 0) > 0) ? ' <span class="fs-muted small">(' . sprintf(gettext('%d pinned'), (int)$st['pinned']) . ')</span>' : ''?></td>
			<td><?=htmlspecialchars(format_bytes((int)($st['bytes'] ?? 0)))?></td>
			<td class="small"><?=empty($rules[$b['node_id']][1]) ? '<span class="fs-muted">' . sprintf(gettext('Default (%s)'), htmlspecialchars(fleet_keep_rule_text(fleet_backup_default_rule()))) . '</span>' : htmlspecialchars(implode(', ', $rules[$b['node_id']][1]))?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php if ($pages > 1): ?>
	<div class="panel-footer d-flex gap-2 align-items-center">
		<a class="btn btn-sm btn-outline-secondary<?=($page <= 1) ? ' disabled' : ''?>" href="<?=$link(array('page' => $page - 1))?>"><?=gettext('Previous')?></a>
		<span class="fs-muted small"><?=sprintf(gettext('Page %1$d of %2$d'), $page, $pages)?></span>
		<a class="btn btn-sm btn-outline-secondary<?=($page >= $pages) ? ' disabled' : ''?>" href="<?=$link(array('page' => $page + 1))?>"><?=gettext('Next')?></a>
	</div>
<?php endif; ?>
</div>

<?php elseif ($view === 'copies'):
	$peers = fleet_replica_peers();
	$targets = fleet_replica_targets();
	$status = fleet_replica_status();
	$verify = fleet_backup_verify_results();
	$labels = fleet_db()->query('SELECT node_id, label FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll(PDO::FETCH_KEY_PAIR);
	$roles = fleet_db()->query('SELECT node_id, role FROM boxes')->fetchAll(PDO::FETCH_KEY_PAIR);
	$wanted_n = count(fleet_replica_wanted_now());
?>
<?php if ($new_key !== null): ?>
<div class="panel panel-default fs-fleet-review" role="region" aria-labelledby="rk-title">
	<div class="panel-heading"><h2 id="rk-title" class="panel-title"><?=gettext('Your recovery key')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=gettext('Write it down or store it in a password manager now. It is shown only this once and is not kept on the controller. With it and any copy of the backups, a new controller gets the whole fleet back. Anyone with both can read every firewall\'s configuration.')?></p>
		<p class="fs-fleet-key"><code id="recovery-key"><?=htmlspecialchars($new_key)?></code>
			<button type="button" class="btn btn-sm btn-outline-secondary" data-fs-copy="#recovery-key"><i class="fa-solid fa-copy icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy')?></button></p>
		<p class="fs-fleet-hint"><?=gettext('Earlier recovery keys stop working once the copies are synced again.')?></p>
	</div>
</div>
<?php endif; ?>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Recovery key')?></h2>
<?php if ($manage): ?>
		<form method="post" action="?view=copies"><button class="btn btn-sm <?=fleet_recovery_ready() ? 'btn-outline-secondary' : 'btn-primary'?>" name="recovery_create" value="1"><i class="fa-solid fa-key icon-embed-btn" aria-hidden="true"></i><?=fleet_recovery_ready() ? gettext('Make a new recovery key') : gettext('Make the recovery key')?></button></form>
<?php endif; ?>
	</div>
	<div class="panel-body fs-fleet-pad">
<?php if (fleet_recovery_ready()): ?>
		<p class="mb-0"><?=sprintf(gettext('Made %1$s by %2$s. Keep it outside the fleet; the controller does not have it.'), htmlspecialchars(date('Y-m-d H:i', (int)fleet_setting('recovery_created', '0'))), htmlspecialchars((string)fleet_setting('recovery_by', '?')))?></p>
<?php else: ?>
		<p class="mb-0"><?=fs_badge('warn', gettext('None'))?> <?=gettext('Without a recovery key, the copies cannot bring the fleet back. Make one first.')?></p>
<?php endif; ?>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Copies on other firewalls')?></h2>
<?php if ($manage && (!empty($peers) || !empty(fleet_offsite_ids()))): ?>
		<form method="post" action="?view=copies"><button class="btn btn-sm btn-outline-secondary" name="sync" value="1"><i class="fa-solid fa-rotate icon-embed-btn" aria-hidden="true"></i><?=gettext('Sync now')?></button></form>
<?php endif; ?>
	</div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=sprintf(gettext('Each chosen firewall keeps every backup (%d items with the self-backup and the recovery envelope), encrypted: it cannot read them. Only managed firewalls keep copies, within their share of free space. The copies are synced after every nightly backup.'), $wanted_n)?></p>
<?php if ($manage): ?>
		<form method="post" action="?view=copies" class="fs-fleet-rings">
			<div class="fs-fleet-field fs-fleet-field--wide"><label class="form-label" for="ptargets"><?=gettext('Keep copies on')?></label>
				<select class="form-select" id="ptargets" name="targets[]" multiple size="8" data-fs-multiselect data-fs-exclusive="all"
				    data-fs-text-search="<?=gettext('Search groups and firewalls…')?>" data-fs-text-none="<?=gettext('No other firewalls (controller only)')?>" data-fs-text-more="<?=gettext('+%d more')?>">
					<option value="all"<?=in_array('all', $targets, true) ? ' selected' : ''?>><?=gettext('All managed firewalls')?></option>
<?php $grs = fleet_groups_all(); if (!empty($grs)): ?>
					<optgroup label="<?=gettext('Groups')?>">
<?php foreach ($grs as $grp): ?>
						<option value="g:<?=(int)$grp['id']?>"<?=in_array('g:' . $grp['id'], $targets, true) ? ' selected' : ''?>><?=htmlspecialchars($grp['name'])?></option>
<?php endforeach; ?>
					</optgroup>
<?php endif; ?>
					<optgroup label="<?=gettext('Firewalls')?>">
<?php foreach ($labels as $node => $label): if (($roles[$node] ?? '') !== 'managed') { continue; } ?>
						<option value="n:<?=htmlspecialchars($node)?>"<?=in_array('n:' . $node, $targets, true) ? ' selected' : ''?>><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
					</optgroup>
				</select></div>
			<div class="fs-fleet-field fs-fleet-field--button"><button class="btn btn-primary" type="submit" name="peers_save" value="1"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button></div>
		</form>
<?php endif; ?>
	</div>
<?php if (!empty($peers)): ?>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Firewall')?></th><th><?=gettext('Copies')?></th><th><?=gettext('Space')?></th><th><?=gettext('Last sync')?></th></tr></thead>
		<tbody>
<?php foreach ($peers as $p): $ps = $status[$p['node_id']] ?? array(); ?>
		<tr><td><a href="/fleet/fleet_box.php?id=<?=urlencode($p['node_id'])?>"><?=htmlspecialchars($p['label'])?></a></td>
			<td><?=isset($ps['held']) ? sprintf(gettext('%1$d of %2$d'), (int)$ps['held'], $wanted_n) : '<span class="fs-muted">' . gettext('Not synced yet') . '</span>'?>
				<?=(isset($ps['held']) && ((int)$ps['held'] >= $wanted_n) && empty($ps['error'])) ? fs_badge('pass', gettext('Complete')) : ''?></td>
			<td><?php if (!empty($ps['quota'])): $pct = (int)round(100 * (int)$ps['used'] / max(1, (int)$ps['quota'])); ?>
				<span class="fs-fleet-meter<?=($pct >= 90) ? ' is-full' : ''?>" role="meter" aria-label="<?=gettext('Space used')?>" aria-valuemin="0" aria-valuemax="100" aria-valuenow="<?=$pct?>"><span style="width: <?=max(1, $pct)?>%"></span></span> <span class="fs-muted small"><?=sprintf(gettext('%1$s of %2$s'), htmlspecialchars(format_bytes((int)$ps['used'])), htmlspecialchars(format_bytes((int)$ps['quota'])))?></span>
			<?php else: ?><span class="fs-muted">-</span><?php endif; ?></td>
			<td><?=!empty($ps['synced']) ? htmlspecialchars(date('Y-m-d H:i', (int)$ps['synced'])) : '<span class="fs-muted">-</span>'?>
				<?=!empty($ps['error']) ? '<div class="fs-fleet-problem small">' . htmlspecialchars((string)$ps['error']) . '</div>' : ''?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php elseif (!empty($targets)): ?>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=gettext('None of the chosen firewalls is managed, so none can keep copies.')?></p></div>
<?php endif; ?>
</div>

<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Off-site copies')?></h2>
		<a class="btn btn-sm btn-link" href="/diag_backup_remote.php"><?=gettext('Storage targets...')?></a></div>
	<div class="panel-body fs-fleet-pad">
<?php $remote = fleet_offsite_available() ? remote_backup_targets() : array(); $off_ids = fleet_offsite_ids(); $off_status = fleet_offsite_status(); ?>
<?php if (empty($remote)): ?>
		<p class="fs-fleet-hint mb-0"><?=gettext('No storage targets yet. Add an S3, WebDAV or SFTP target in System > Backup > Remote on this firewall; then choose it here. Fleet stores its copies there encrypted, next to (never mixed with) the firewall\'s own remote backups.')?></p>
<?php else: ?>
		<form method="post" action="?view=copies">
			<p class="fs-fleet-lead"><?=gettext('The same encrypted copies also go to these storage targets with every sync. With the recovery key they bring the fleet back even when every firewall is gone.')?></p>
			<div class="table-responsive"><table class="table fs-table">
				<thead><tr><th><?=gettext('Use')?></th><th><?=gettext('Storage')?></th><th><?=gettext('Copies')?></th><th><?=gettext('Last sync')?></th></tr></thead>
				<tbody>
<?php foreach ($remote as $t): $os = $off_status[$t['id']] ?? array(); ?>
				<tr><td><input class="form-check-input" type="checkbox" name="offsite[]" value="<?=htmlspecialchars($t['id'])?>"<?=in_array($t['id'], $off_ids, true) ? ' checked' : ''?> aria-label="<?=htmlspecialchars(sprintf(gettext('Use %s'), $t['descr'] ?: $t['id']))?>"<?=$manage ? '' : ' disabled'?>/></td>
					<td><?=htmlspecialchars(($t['descr'] ?: $t['id']))?> <span class="fs-muted small"><?=htmlspecialchars(strtoupper($t['type']))?></span></td>
					<td><?=isset($os['held']) ? sprintf(gettext('%1$d of %2$d'), (int)$os['held'], $wanted_n) : '<span class="fs-muted">-</span>'?></td>
					<td><?=!empty($os['synced']) ? htmlspecialchars(date('Y-m-d H:i', (int)$os['synced'])) : '<span class="fs-muted">-</span>'?>
						<?=!empty($os['error']) ? '<div class="fs-fleet-problem small">' . htmlspecialchars((string)$os['error']) . '</div>' : ''?></td></tr>
<?php endforeach; ?>
				</tbody></table></div>
<?php if ($manage): ?>
			<button class="btn btn-sm btn-primary" type="submit" name="offsite_save" value="1"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
<?php endif; ?>
		</form>
<?php endif; ?>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Test restores')?></h2>
<?php if ($manage): ?>
		<form method="post" action="?view=copies"><button class="btn btn-sm btn-outline-secondary" name="verify" value="1"><i class="fa-solid fa-vial icon-embed-btn" aria-hidden="true"></i><?=gettext('Test now')?></button></form>
<?php endif; ?>
	</div>
	<div class="panel-body fs-fleet-pad">
<?php if (empty($verify)): ?>
		<p class="fs-fleet-hint mb-0"><?=gettext('Not tested yet. Once a week Fleet reads back each firewall\'s newest backup and a random older one, decrypts them and checks that they could be restored.')?></p>
<?php else: $bad = array_filter($verify, function ($r) { return !empty($r['problems']); }); ?>
		<p class="mb-2"><?=sprintf(gettext('Last test %1$s: %2$d firewalls, %3$d with problems.'), htmlspecialchars(date('Y-m-d H:i', (int)fleet_setting('verify_last', '0'))), count($verify), count($bad))?>
			<?=empty($bad) ? fs_badge('pass', gettext('All could be restored')) : fs_badge('warn', gettext('Problems'))?></p>
<?php foreach ($bad as $node => $r): ?>
		<p class="fs-fleet-problem small mb-1"><?=htmlspecialchars(($labels[$node] ?? $node) . ': ' . implode('; ', $r['problems']))?></p>
<?php endforeach; ?>
<?php endif; ?>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Export')?></h2>
<?php if ($manage): ?>
		<form method="post" action="?view=copies"><button class="btn btn-sm btn-outline-secondary" name="export" value="1"><i class="fa-solid fa-file-export icon-embed-btn" aria-hidden="true"></i><?=gettext('Download all backups (.fsfa)')?></button></form>
<?php endif; ?>
	</div>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint mb-0"><?=gettext('Every backup, a fresh self-backup and the recovery envelope in one encrypted file, the same as a firewall\'s copies. Keep it off the fleet; Recover fleet opens it with the recovery key.')?></p></div>
</div>

<?php else:
	$sets = fleet_backup_sets_all();
	$sq = trim((string)($_GET['q'] ?? ''));
	$sshown = array_values(array_filter($sets, function ($set) use ($sq, $names) {
		return ($sq === '') || (stripos($set['name'] . ' ' . fleet_targets_text($set['targets'], $names), $sq) !== false);
	}));
	$def = fleet_backup_default_rule();
	$sfill = function (?array $set) use ($def) {
		$r = ($set === null) ? $def : $set['rule'];
		return json_encode(array('set_id' => ($set === null) ? '' : (string)$set['id'], 'name' => ($set === null) ? '' : $set['name'],
		    'targets[]' => ($set === null) ? array() : $set['targets'], 'keep_last' => (string)$r['last'], 'keep_daily' => (string)$r['daily'],
		    'keep_weekly' => (string)$r['weekly'], 'keep_monthly' => (string)$r['monthly']));
	};
	$boxes = fleet_db()->query('SELECT node_id, label FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll(PDO::FETCH_KEY_PAIR);
?>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Backup sets')?> <span class="fs-count"><?=count($sets)?></span></h2>
<?php if ($manage): ?>
		<button type="button" class="btn btn-sm btn-primary" data-fs-modal="#set-modal" data-fs-modal-title="<?=gettext('Add a backup set')?>" data-fs-fill="<?=htmlspecialchars($sfill(null))?>"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add set')?></button>
<?php endif; ?>
	</div>
<?php if (empty($sets)): ?>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=sprintf(gettext('No sets yet: every firewall keeps the default (%s, Settings > Backups). A set keeps more or fewer backups for chosen groups or firewalls, for example a year of monthly backups for the datacenter.'), htmlspecialchars(fleet_keep_rule_text($def)))?></p></div>
<?php else: ?>
	<div class="panel-body fs-fleet-pad">
		<form method="get" class="fs-fleet-filterbar" role="search">
			<input type="hidden" name="view" value="sets"/>
			<input class="form-control form-control-sm" type="search" name="q" value="<?=htmlspecialchars($sq)?>" placeholder="<?=gettext('Search name, group or firewall')?>" aria-label="<?=gettext('Search sets')?>"/>
			<button class="btn btn-sm btn-outline-secondary" type="submit"><?=gettext('Search')?></button>
<?php if ($sq !== ''): ?>
			<a class="btn btn-sm btn-link" href="?view=sets"><?=gettext('Clear')?></a>
			<span class="fs-muted small ms-auto"><?=sprintf(gettext('%1$d of %2$d'), count($sshown), count($sets))?></span>
<?php endif; ?>
		</form>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Name')?></th><th><?=gettext('For')?></th><th><?=gettext('Keeps')?></th><th><?=gettext('Firewalls')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($sshown)): ?>
		<tr><td colspan="5" class="fs-muted"><?=gettext('No set matches.')?> <a href="?view=sets"><?=gettext('Clear the search')?></a></td></tr>
<?php endif; ?>
<?php foreach ($sshown as $set): list($in) = fleet_targets_now($set['targets']); ?>
		<tr><td><?=htmlspecialchars($set['name'])?></td>
			<td><?=htmlspecialchars(fleet_targets_text($set['targets'], $names))?></td>
			<td><?=htmlspecialchars(fleet_keep_rule_text($set['rule']))?></td>
			<td><?=count($in)?></td>
			<td class="text-end text-nowrap">
<?php if ($manage): ?>
				<button type="button" class="btn btn-sm btn-link" data-fs-modal="#set-modal" data-fs-modal-title="<?=htmlspecialchars(sprintf(gettext('Change %s'), $set['name']))?>" data-fs-fill="<?=htmlspecialchars($sfill($set))?>"><?=gettext('Change')?></button>
				<form method="post" action="?view=sets" class="d-inline"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="set_delete" value="<?=(int)$set['id']?>"><?=gettext('Delete')?></button></form>
<?php endif; ?>
			</td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php endif; ?>
	<div class="panel-footer small fs-muted"><?=sprintf(gettext('A firewall in several sets keeps what any of them wants; one in no set keeps the default (%1$s). Never removed: each firewall\'s newest backup, pinned backups, and safety backups for %2$d days. Old backups are removed after each nightly backup.'), htmlspecialchars(fleet_keep_rule_text($def)), fleet_opt('backup_safety_days'))?></div>
</div>
<?php if ($manage):
	fs_modal_form_begin('set-modal', gettext('Add a backup set'), '?view=sets', array('set_id' => ''), $reopen);
?>
	<div class="mb-3"><label class="form-label" for="setname"><?=gettext('Name')?></label>
		<input class="form-control" id="setname" name="name" maxlength="60" required placeholder="<?=gettext('Datacenter: a year of history')?>"/></div>
	<div class="mb-3"><label class="form-label" for="settargets"><?=gettext('For')?></label>
		<select class="form-select" id="settargets" name="targets[]" multiple size="8" data-fs-multiselect data-fs-exclusive="all"
		    data-fs-text-search="<?=gettext('Search groups and firewalls…')?>" data-fs-text-none="<?=gettext('Choose firewalls…')?>" data-fs-text-more="<?=gettext('+%d more')?>">
			<option value="all"><?=gettext('All firewalls')?></option>
<?php if (!empty($groups)): ?>
			<optgroup label="<?=gettext('Groups')?>">
<?php foreach ($groups as $grp): ?>
				<option value="g:<?=(int)$grp['id']?>"><?=htmlspecialchars($grp['name'])?></option>
<?php endforeach; ?>
			</optgroup>
<?php endif; ?>
			<optgroup label="<?=gettext('Firewalls')?>">
<?php foreach ($boxes as $node => $label): ?>
				<option value="n:<?=htmlspecialchars($node)?>"><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
			</optgroup>
		</select></div>
	<fieldset><legend class="form-label"><?=gettext('Keep')?></legend>
		<div class="row g-2">
<?php foreach (array('keep_last' => array(gettext('The newest'), gettext('backups'), 1, 500), 'keep_daily' => array(gettext('One a day for'), gettext('days'), 0, 366),
    'keep_weekly' => array(gettext('One a week for'), gettext('weeks'), 0, 260), 'keep_monthly' => array(gettext('One a month for'), gettext('months'), 0, 120)) as $fld => list($lead, $unit, $min, $max)): ?>
			<div class="col-sm-6"><label class="form-label small" for="<?=$fld?>"><?=htmlspecialchars($lead)?></label>
				<div class="input-group input-group-sm"><input class="form-control" type="number" id="<?=$fld?>" name="<?=$fld?>" min="<?=$min?>" max="<?=$max?>" required/><span class="input-group-text"><?=htmlspecialchars($unit)?></span></div></div>
<?php endforeach; ?>
		</div></fieldset>
<?php
	fs_modal_form_end(gettext('Save set'), 'set_save', '1', 'fa-floppy-disk');
endif; ?>
<?php endif; ?>
<?php include('foot.inc');
