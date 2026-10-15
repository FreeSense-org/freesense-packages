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
 * firewall's own backups are on its page.
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
$view = fs_view_param(array('overview', 'sets'), 'overview');

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
		array(gettext('Firewalls'), false, '/fleet/fleet.php'),
		array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
	);
	display_top_tabs($tab_array);
}
if (!$ready): ?>
<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller')?></strong></div>
<?php include('foot.inc'); exit; endif;

fs_view_switch(array('overview' => gettext('Overview'), 'sets' => gettext('Sets')), $view);
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
