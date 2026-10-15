<?php
/*
 * fleet_schedules.php
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
 * Schedules: recurring backups, reboots and updates on any mix of groups
 * and firewalls, or every firewall (fleet_schedules.inc; the poll runs
 * them). The list comes first; adding and changing happen in a modal.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Schedules'));
$who = (string)($_SESSION['Username'] ?? 'admin');
$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$manage = isAllowedPage('fleet/fleet.php');
$input_errors = array();
$savemsg = null;
$reopen = null;

if ($ready && $manage && ($_SERVER['REQUEST_METHOD'] === 'POST')) {
	try {
		if (isset($_POST['save'])) {
			$id = ((int)($_POST['id'] ?? 0) > 0) ? (int)$_POST['id'] : null;
			fleet_schedule_save($id, $_POST, $who);
			$savemsg = gettext('Schedule saved.');
		} elseif (isset($_POST['delete'])) {
			fleet_schedule_delete((int)$_POST['delete'], $who);
			$savemsg = gettext('Schedule deleted.');
		} elseif (isset($_POST['pause']) || isset($_POST['resume'])) {
			fleet_schedule_set_enabled((int)($_POST['pause'] ?? $_POST['resume']), isset($_POST['resume']), $who);
			$savemsg = isset($_POST['resume']) ? gettext('Schedule resumed.') : gettext('Schedule paused. It does not run until you resume it.');
		} elseif (isset($_POST['run'])) {
			$s = fleet_schedule_get((int)$_POST['run']);
			if ($s === null) {
				throw new RuntimeException(gettext('That schedule does not exist any more.'));
			}
			$savemsg = fleet_schedule_run($s, $who);
		}
	} catch (InvalidArgumentException | RuntimeException $e) {
		$input_errors[] = $e->getMessage();
		if (isset($_POST['save'])) {
			/* The modal opens again with what was typed. */
			$reopen = array('id' => (string)($_POST['id'] ?? ''), 'name' => (string)($_POST['name'] ?? ''), 'kind' => (string)($_POST['kind'] ?? ''),
			    'targets[]' => array_values((array)($_POST['targets'] ?? array())), 'days[]' => array_values((array)($_POST['days'] ?? array())),
			    'time' => (string)($_POST['time'] ?? ''), 'enabled' => !empty($_POST['enabled']));
		}
	}
}

$groups = $ready ? fleet_groups_all() : array();
$boxes = $ready ? fleet_db()->query('SELECT node_id, label FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll(PDO::FETCH_KEY_PAIR) : array();
$names = $ready ? fleet_target_names() : array();
/* From a firewall's page (?node=...): the modal opens for that firewall. */
if (($reopen === null) && isset($boxes[$_GET['node'] ?? ''])) {
	$reopen = array('targets[]' => array('n:' . $_GET['node']), 'kind' => 'backup', 'days[]' => array('1', '2', '3', '4', '5', '6', '7'), 'time' => '02:30', 'enabled' => true,
	    'name' => sprintf(gettext('Back up %s'), $boxes[$_GET['node']]));
}
if ($ready && $manage) {
	fs_page_action(gettext('Add schedule'), '#', 'fa-plus', 'primary', array('data-fs-modal' => '#sched-modal', 'data-fs-modal-title' => gettext('Add a schedule'),
	    'data-fs-fill' => json_encode(array('targets[]' => array('all'), 'days[]' => array('1', '2', '3', '4', '5', '6', '7'), 'time' => '02:30', 'enabled' => true))));
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
		array(gettext('Schedules'), true, '/fleet/fleet_schedules.php'),
		array(gettext('Firewalls'), false, '/fleet/fleet.php'),
		array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
	);
	display_top_tabs($tab_array);
}
if (!$ready): ?>
<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller')?></strong></div>
<?php include('foot.inc'); exit; endif;

$kinds = array_map('gettext', FLEET_SCHEDULE_KINDS);
$day_names = array(1 => gettext('Mon'), 2 => gettext('Tue'), 3 => gettext('Wed'), 4 => gettext('Thu'), 5 => gettext('Fri'), 6 => gettext('Sat'), 7 => gettext('Sun'));
$all = fleet_schedules_all();
/* Filters live in the URL, so a filtered list can be shared and survives a reload. */
$q = trim((string)($_GET['q'] ?? ''));
$fk = isset($kinds[$_GET['kind'] ?? '']) ? (string)$_GET['kind'] : '';
$fs = in_array($_GET['state'] ?? '', array('on', 'paused'), true) ? (string)$_GET['state'] : '';
$ft = (string)($_GET['on'] ?? '');
$ft = (($ft === 'all') || isset($names[$ft])) ? $ft : '';
$list = array_values(array_filter($all, function ($s) use ($q, $fk, $fs, $ft, $names) {
	$on = fleet_targets_text($s['targets'], $names);
	return (($fk === '') || ($s['kind'] === $fk)) && (($fs === '') || (($fs === 'on') === $s['enabled'])) &&
	    (($ft === '') || in_array($ft, $s['targets'], true)) && (($q === '') || (stripos($s['name'] . ' ' . $on, $q) !== false));
}));
$filtered = ($q !== '') || ($fk !== '') || ($fs !== '') || ($ft !== '');
$now = time();

/* The target choices: All firewalls, then groups, then each firewall. */
$target_options = function (string $selected = '') use ($groups, $boxes) {
	ob_start(); ?>
	<option value="all"<?=($selected === 'all') ? ' selected' : ''?>><?=gettext('All firewalls')?></option>
<?php if (!empty($groups)): ?>
	<optgroup label="<?=gettext('Groups')?>">
<?php foreach ($groups as $grp): ?>
		<option value="g:<?=(int)$grp['id']?>"<?=($selected === 'g:' . $grp['id']) ? ' selected' : ''?>><?=htmlspecialchars($grp['name'])?></option>
<?php endforeach; ?>
	</optgroup>
<?php endif; ?>
	<optgroup label="<?=gettext('Firewalls')?>">
<?php foreach ($boxes as $node => $label): ?>
		<option value="n:<?=htmlspecialchars($node)?>"<?=($selected === 'n:' . $node) ? ' selected' : ''?>><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
	</optgroup>
<?php return ob_get_clean();
};
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Schedules')?></h2></div>
<?php if (empty($all)): ?>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=gettext('No schedules yet. A schedule backs up, reboots or updates firewalls at a set time, for example the Retail shops every night at 02:30.')?></p></div>
<?php else: ?>
	<div class="panel-body fs-fleet-pad">
		<form method="get" class="fs-fleet-filterbar" role="search">
			<input class="form-control form-control-sm" type="search" name="q" value="<?=htmlspecialchars($q)?>" placeholder="<?=gettext('Search name, group or firewall')?>" aria-label="<?=gettext('Search schedules')?>"/>
			<select class="form-select form-select-sm" name="kind" aria-label="<?=gettext('What it does')?>">
				<option value=""><?=gettext('Any job')?></option>
<?php foreach ($kinds as $k => $label): ?>
				<option value="<?=$k?>"<?=($fk === $k) ? ' selected' : ''?>><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
			</select>
			<select class="form-select form-select-sm" name="on" aria-label="<?=gettext('For')?>">
				<option value=""><?=gettext('Any target')?></option>
				<?=$target_options($ft)?>
			</select>
			<select class="form-select form-select-sm" name="state" aria-label="<?=gettext('State')?>">
				<option value=""><?=gettext('On or paused')?></option>
				<option value="on"<?=($fs === 'on') ? ' selected' : ''?>><?=gettext('On')?></option>
				<option value="paused"<?=($fs === 'paused') ? ' selected' : ''?>><?=gettext('Paused')?></option>
			</select>
			<button class="btn btn-sm btn-outline-secondary" type="submit"><?=gettext('Filter')?></button>
<?php if ($filtered): ?>
			<a class="btn btn-sm btn-link" href="?"><?=gettext('Clear')?></a>
<?php endif; ?>
			<span class="fs-muted small ms-auto"><?=$filtered ? sprintf(gettext('%1$d of %2$d'), count($list), count($all)) : sprintf(ngettext('%d schedule', '%d schedules', count($all)), count($all))?></span>
		</form>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Name')?></th><th><?=gettext('Does')?></th><th><?=gettext('For')?></th><th><?=gettext('When')?></th><th><?=gettext('Next')?></th><th><?=gettext('Last result')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($list)): ?>
		<tr><td colspan="7" class="fs-muted"><?=gettext('No schedule matches.')?> <a href="?"><?=gettext('Clear the filters')?></a></td></tr>
<?php endif; ?>
<?php foreach ($list as $s): $next = $s['enabled'] ? fleet_schedule_next($s, $now, fleet_tz()) : null; ?>
		<tr><td><?=htmlspecialchars($s['name'])?></td>
			<td><?=htmlspecialchars($kinds[$s['kind']] ?? $s['kind'])?></td>
			<td><?php
	$parts = array();
	foreach ($s['targets'] as $t) {
		if ($t === 'all') {
			$parts[] = htmlspecialchars(gettext('All firewalls'));
		} elseif (!isset($names[$t])) {
			$parts[] = fs_badge('warn', ($t[0] === 'g') ? gettext('Group deleted') : gettext('Firewall removed'));
		} elseif ($t[0] === 'n') {
			$parts[] = '<a href="/fleet/fleet_box.php?id=' . urlencode(substr($t, 2)) . '">' . htmlspecialchars($names[$t]) . '</a>';
		} else {
			$parts[] = '<a href="/fleet/fleet_dashboard.php?group=' . (int)substr($t, 2) . '">' . htmlspecialchars($names[$t]) . '</a>';
		}
	}
	echo implode(', ', $parts);
?></td>
			<td><?=htmlspecialchars(fleet_schedule_text($s))?></td>
			<td><?=$s['enabled'] ? htmlspecialchars(date('D H:i', (int)$next)) : fs_badge('neutral', gettext('Paused'))?></td>
			<td class="small"><?php if ($s['last_result'] === null): ?><span class="fs-muted"><?=gettext('Not run yet')?></span><?php else: ?>
				<?=htmlspecialchars(date('D H:i', (int)$s['ran_at']))?>: <?=htmlspecialchars((string)$s['last_result'])?>
				<?php if ($s['last_op']): ?><a href="/fleet/fleet_activity.php?op=<?=(int)$s['last_op']?>"><?=gettext('Activity')?></a><?php endif; ?><?php endif; ?></td>
			<td class="text-end text-nowrap">
<?php if ($manage): ?>
				<form method="post" class="d-inline">
					<button class="btn btn-sm btn-link" name="run" value="<?=(int)$s['id']?>"><?=gettext('Run now')?></button>
					<button class="btn btn-sm btn-link" name="<?=$s['enabled'] ? 'pause' : 'resume'?>" value="<?=(int)$s['id']?>"><?=$s['enabled'] ? gettext('Pause') : gettext('Resume')?></button>
				</form>
				<button type="button" class="btn btn-sm btn-link" data-fs-modal="#sched-modal" data-fs-modal-title="<?=htmlspecialchars(sprintf(gettext('Change %s'), $s['name']))?>"
				    data-fs-fill="<?=htmlspecialchars(json_encode(array('id' => (string)$s['id'], 'name' => $s['name'], 'kind' => $s['kind'], 'targets[]' => $s['targets'],
				    'days[]' => array_map('strval', $s['days']), 'time' => sprintf('%02d:%02d', intdiv($s['time'], 60), $s['time'] % 60), 'enabled' => $s['enabled'])))?>"><?=gettext('Change')?></button>
				<form method="post" class="d-inline"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="delete" value="<?=(int)$s['id']?>"><?=gettext('Delete')?></button></form>
<?php endif; ?>
			</td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php endif; ?>
	<div class="panel-footer small fs-muted"><?=sprintf(gettext('Times are the controller\'s time zone (%1$s). Reboots and updates go one firewall at a time and stop at the first failure, like from the dashboard. A run the controller misses by more than %2$d minutes is recorded as missed, not run late.'), htmlspecialchars(fleet_tz()), fleet_opt('schedule_grace'))?></div>
</div>

<?php if ($manage):
	fs_modal_form_begin('sched-modal', gettext('Add a schedule'), '/fleet/fleet_schedules.php', array('id' => ''), $reopen);
?>
	<div class="mb-3"><label class="form-label" for="sname"><?=gettext('Name')?></label>
		<input class="form-control" id="sname" name="name" maxlength="60" required placeholder="<?=gettext('Nightly Retail backup')?>"/></div>
	<div class="mb-3"><label class="form-label" for="skind"><?=gettext('Does')?></label>
		<select class="form-select" id="skind" name="kind">
<?php foreach ($kinds as $k => $label): ?>
			<option value="<?=$k?>"><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
		</select></div>
	<div class="mb-3"><label class="form-label" for="stargets"><?=gettext('For')?></label>
		<select class="form-select" id="stargets" name="targets[]" multiple size="8" data-fs-multiselect data-fs-exclusive="all"
		    data-fs-text-search="<?=gettext('Search groups and firewalls…')?>" data-fs-text-none="<?=gettext('Choose firewalls…')?>" data-fs-text-more="<?=gettext('+%d more')?>">
			<?=$target_options()?>
		</select>
		<div class="form-text"><?=gettext('Any mix of groups and firewalls. A firewall in two chosen groups is done once.')?></div></div>
	<fieldset class="mb-3"><legend class="form-label"><?=gettext('Days')?></legend>
		<div class="fs-fleet-days">
<?php foreach ($day_names as $d => $label): ?>
			<label class="fs-fleet-day"><input type="checkbox" name="days[]" value="<?=$d?>"/><span><?=htmlspecialchars($label)?></span></label>
<?php endforeach; ?>
		</div></fieldset>
	<div class="row g-3 align-items-end">
		<div class="col-sm-5"><label class="form-label" for="stime"><?=gettext('At')?></label>
			<input class="form-control" type="time" id="stime" name="time" required value="02:30"/></div>
		<div class="col-sm-7"><label class="form-check"><input class="form-check-input" type="checkbox" name="enabled" value="1" checked/> <span class="form-check-label"><?=gettext('On (runs at its times)')?></span></label></div>
	</div>
	<p class="fs-fleet-hint mt-3 mb-0"><?=gettext('Updates on a schedule follow the Updates settings: firewalls without rollback (UFS) are left out unless allowed there. For updates ring by ring with maintenance windows, use Updates > Rollouts.')?></p>
<?php
	fs_modal_form_end(gettext('Save schedule'), 'save', '1', 'fa-floppy-disk');
endif; ?>
<?php include('foot.inc');
