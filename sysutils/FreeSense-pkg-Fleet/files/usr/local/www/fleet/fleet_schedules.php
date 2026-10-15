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
 * Schedules: recurring backups, reboots and updates on a group or every
 * firewall (fleet_schedules.inc; the poll runs them).
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Schedules'));
$who = (string)($_SESSION['Username'] ?? 'admin');
$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$manage = isAllowedPage('fleet/fleet.php');
$input_errors = array();
$savemsg = null;

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
		array(gettext('Schedules'), true, '/fleet/fleet_schedules.php'),
		array(gettext('Firewalls'), false, '/fleet/fleet.php'),
		array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
	);
	display_top_tabs($tab_array);
}
if (!$ready): ?>
<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller')?></strong></div>
<?php include('foot.inc'); exit; endif;

$groups = array_column(fleet_groups_all(), null, 'id');
$kinds = array_map('gettext', FLEET_SCHEDULE_KINDS);
$day_names = array(1 => gettext('Mon'), 2 => gettext('Tue'), 3 => gettext('Wed'), 4 => gettext('Thu'), 5 => gettext('Fri'), 6 => gettext('Sat'), 7 => gettext('Sun'));
$all = fleet_schedules_all();
/* Filters live in the URL, so a filtered list can be shared and survives a reload. */
$q = trim((string)($_GET['q'] ?? ''));
$fk = isset($kinds[$_GET['kind'] ?? '']) ? (string)$_GET['kind'] : '';
$list = array_values(array_filter($all, function ($s) use ($q, $fk, $groups) {
	$target = ($s['group_id'] > 0) ? ($groups[$s['group_id']]['name'] ?? '') : 'All firewalls';
	return (($fk === '') || ($s['kind'] === $fk)) && (($q === '') || (stripos($s['name'] . ' ' . $target, $q) !== false));
}));
$edit = isset($_GET['edit']) ? fleet_schedule_get((int)$_GET['edit']) : null;
$f = $edit ?? array('id' => 0, 'name' => '', 'kind' => 'backup', 'group_id' => 0, 'days' => array(1, 2, 3, 4, 5, 6, 7), 'time' => 150, 'enabled' => true);
$now = time();
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Schedules')?></h2></div>
<?php if (empty($all)): ?>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=gettext('No schedules yet. A schedule backs up, reboots or updates a group at a set time, for example the Retail shops every night at 02:30.')?></p></div>
<?php else: ?>
	<div class="panel-body fs-fleet-pad">
		<form method="get" class="fs-fleet-filterbar" role="search">
			<input class="form-control form-control-sm" type="search" name="q" value="<?=htmlspecialchars($q)?>" placeholder="<?=gettext('Search name or group')?>" aria-label="<?=gettext('Search schedules')?>"/>
			<select class="form-select form-select-sm" name="kind" aria-label="<?=gettext('What it does')?>">
				<option value=""><?=gettext('Any job')?></option>
<?php foreach ($kinds as $k => $label): ?>
				<option value="<?=$k?>"<?=($fk === $k) ? ' selected' : ''?>><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
			</select>
			<button class="btn btn-sm btn-outline-secondary" type="submit"><?=gettext('Filter')?></button>
<?php if (($q !== '') || ($fk !== '')): ?>
			<a class="btn btn-sm btn-link" href="?"><?=gettext('Clear')?></a>
<?php endif; ?>
		</form>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Name')?></th><th><?=gettext('Does')?></th><th><?=gettext('On')?></th><th><?=gettext('When')?></th><th><?=gettext('Next')?></th><th><?=gettext('Last result')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($list)): ?>
		<tr><td colspan="7" class="fs-muted"><?=gettext('No schedule matches.')?></td></tr>
<?php endif; ?>
<?php foreach ($list as $s): $next = $s['enabled'] ? fleet_schedule_next($s, $now, fleet_tz()) : null; ?>
		<tr><td><?=htmlspecialchars($s['name'])?></td>
			<td><?=htmlspecialchars($kinds[$s['kind']] ?? $s['kind'])?></td>
			<td><?=($s['group_id'] > 0) ? (isset($groups[$s['group_id']]) ? htmlspecialchars($groups[$s['group_id']]['name']) : fs_badge('warn', gettext('Group deleted'))) : gettext('All firewalls')?></td>
			<td><?=htmlspecialchars(fleet_schedule_text($s))?></td>
			<td><?=$s['enabled'] ? htmlspecialchars(date('D H:i', (int)$next)) : fs_badge('neutral', gettext('Paused'))?></td>
			<td class="small"><?php if ($s['last_result'] === null): ?><span class="fs-muted"><?=gettext('Not run yet')?></span><?php else: ?>
				<?=htmlspecialchars(date('D H:i', (int)$s['last_run']))?>: <?=htmlspecialchars((string)$s['last_result'])?>
				<?php if ($s['last_op']): ?><a href="/fleet/fleet_activity.php?op=<?=(int)$s['last_op']?>"><?=gettext('Activity')?></a><?php endif; ?><?php endif; ?></td>
			<td class="text-end text-nowrap">
<?php if ($manage): ?>
				<form method="post" class="d-inline">
					<button class="btn btn-sm btn-link" name="run" value="<?=(int)$s['id']?>"><?=gettext('Run now')?></button>
					<button class="btn btn-sm btn-link" name="<?=$s['enabled'] ? 'pause' : 'resume'?>" value="<?=(int)$s['id']?>"><?=$s['enabled'] ? gettext('Pause') : gettext('Resume')?></button>
				</form>
				<a class="btn btn-sm btn-link" href="?edit=<?=(int)$s['id']?>"><?=gettext('Change')?></a>
				<form method="post" class="d-inline"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="delete" value="<?=(int)$s['id']?>"><?=gettext('Delete')?></button></form>
<?php endif; ?>
			</td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php endif; ?>
	<div class="panel-footer small fs-muted"><?=sprintf(gettext('Times are the controller\'s time zone (%1$s). Reboots and updates go one firewall at a time and stop at the first failure, like from the dashboard. A run the controller misses by more than %2$d minutes is recorded as missed, not run late.'), htmlspecialchars(fleet_tz()), fleet_opt('schedule_grace'))?></div>
</div>

<?php if ($manage): ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=($edit !== null) ? sprintf(htmlspecialchars(gettext('Change %s')), htmlspecialchars($edit['name'])) : gettext('Add a schedule')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<form method="post" action="?" class="fs-fleet-form">
			<input type="hidden" name="id" value="<?=(int)$f['id']?>"/>
			<div class="fs-fleet-field"><label class="form-label" for="sname"><?=gettext('Name')?></label>
				<input class="form-control" id="sname" name="name" maxlength="60" required value="<?=htmlspecialchars($f['name'])?>" placeholder="<?=gettext('Nightly Retail backup')?>"/></div>
			<div class="fs-fleet-field"><label class="form-label" for="skind"><?=gettext('Does')?></label>
				<select class="form-select" id="skind" name="kind">
<?php foreach ($kinds as $k => $label): ?>
					<option value="<?=$k?>"<?=($f['kind'] === $k) ? ' selected' : ''?>><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
				</select></div>
			<div class="fs-fleet-field"><label class="form-label" for="sgroup"><?=gettext('On')?></label>
				<select class="form-select" id="sgroup" name="group_id">
					<option value="0"><?=gettext('All firewalls')?></option>
<?php foreach ($groups as $g): ?>
					<option value="<?=(int)$g['id']?>"<?=($f['group_id'] === (int)$g['id']) ? ' selected' : ''?>><?=htmlspecialchars($g['name'])?></option>
<?php endforeach; ?>
				</select></div>
			<fieldset class="fs-fleet-field"><legend class="form-label"><?=gettext('Days')?></legend>
				<div class="fs-fleet-days">
<?php foreach ($day_names as $d => $label): ?>
					<label class="fs-fleet-day"><input type="checkbox" name="days[]" value="<?=$d?>"<?=in_array($d, $f['days'], true) ? ' checked' : ''?>/><span><?=htmlspecialchars($label)?></span></label>
<?php endforeach; ?>
				</div></fieldset>
			<div class="fs-fleet-field"><label class="form-label" for="stime"><?=gettext('At')?></label>
				<input class="form-control" type="time" id="stime" name="time" required value="<?=sprintf('%02d:%02d', intdiv($f['time'], 60), $f['time'] % 60)?>"/></div>
			<div class="fs-fleet-field"><label class="form-check"><input class="form-check-input" type="checkbox" name="enabled" value="1"<?=$f['enabled'] ? ' checked' : ''?>/> <span class="form-check-label"><?=gettext('On')?></span></label></div>
			<div class="fs-fleet-field fs-fleet-field--button">
				<button class="btn btn-primary" type="submit" name="save" value="1"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=($edit !== null) ? gettext('Save') : gettext('Add schedule')?></button>
<?php if ($edit !== null): ?>
				<a class="btn btn-outline-secondary" href="?"><?=gettext('Cancel')?></a>
<?php endif; ?>
			</div>
		</form>
		<p class="fs-fleet-hint"><?=gettext('Updates on a schedule follow the Updates settings: firewalls without rollback (UFS) are left out unless allowed there. For updates ring by ring with maintenance windows, use Updates > Rollouts.')?></p>
	</div>
</div>
<?php endif; ?>
<?php include('foot.inc');
