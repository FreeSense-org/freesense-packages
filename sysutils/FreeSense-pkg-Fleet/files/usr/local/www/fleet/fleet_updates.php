<?php
/*
 * fleet_updates.php
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
 * Updates across the fleet: which versions run where (Overview), rollouts
 * ring by ring with a review before they start (Rollouts), and the weekly
 * maintenance windows groups update in (Windows). The work itself is
 * fleet_rollouts.inc; the poll moves rollouts along every minute.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Updates'));
$who = (string)($_SESSION['Username'] ?? 'admin');
$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$manage = isAllowedPage('fleet/fleet.php');
$input_errors = array();
$savemsg = null;
$reopen_window = null;
$view = fs_view_param(array('overview', 'rollouts', 'windows'), 'overview');

/* ---------------- actions ---------------- */
if ($ready && $manage && ($_SERVER['REQUEST_METHOD'] === 'POST')) {
	try {
		if (isset($_POST['rollout_rings'])) {
			$rings = array_values(array_filter((array)($_POST['ring'] ?? array()), 'strlen'));
			$q = http_build_query(array('view' => 'rollouts', 'review' => 1, 'ring' => array_map('intval', $rings)));
			header('Location: /fleet/fleet_updates.php?' . $q);
			exit;
		} elseif (isset($_POST['window_save'])) {
			$view = 'windows';
			$id = ((int)($_POST['window_id'] ?? 0) > 0) ? (int)$_POST['window_id'] : null;
			fleet_window_save($id, array('name' => $_POST['name'] ?? '', 'days' => (array)($_POST['days'] ?? array()), 'start' => $_POST['start'] ?? '',
			    'length' => $_POST['length'] ?? ''), $who);
			$savemsg = gettext('Window saved. Choose it for a group on Firewalls > Groups.');
		} elseif (isset($_POST['window_delete'])) {
			$view = 'windows';
			fleet_window_delete((int)$_POST['window_delete'], $who);
			$savemsg = gettext('Window deleted.');
		} elseif (isset($_POST['rollout_resume'])) {
			$view = 'rollouts';
			fleet_rollout_resume((int)$_POST['rollout_resume'], $who);
			$savemsg = gettext('Resumed. The next firewall starts in its window.');
		} elseif (isset($_POST['rollout_cancel'])) {
			$view = 'rollouts';
			fleet_rollout_cancel((int)$_POST['rollout_cancel'], $who);
			$savemsg = gettext('Cancelled. Firewalls that had not started are left alone.');
		} elseif (isset($_POST['rollout_start'])) {
			$view = 'rollouts';
			$rings = array_map('intval', array_filter((array)($_POST['ring'] ?? array()), 'strlen'));
			$target = (string)($_POST['target'] ?? '');
			$plan = fleet_rollout_plan($rings, $target);
			$reviewed = (string)($_POST['plan'] ?? '');
			$hash = hash('sha256', json_encode(array_map(function ($r) { return array_column($r[3], 'node_id'); }, $plan['rings'])));
			if ($reviewed !== $hash) {
				throw new RuntimeException(gettext('The fleet changed while you were reviewing. Check the plan again.'));
			}
			$op = fleet_rollout_start($plan, $target, 3600 * max(0, (int)($_POST['gap'] ?? fleet_opt('rollout_gap_hours'))), $who);
			header('Location: /fleet/fleet_activity.php?op=' . (int)$op);
			exit;
		}
	} catch (InvalidArgumentException | RuntimeException $e) {
		$input_errors[] = $e->getMessage();
		if (isset($_POST['window_save'])) {
			/* The modal opens again with what was typed. */
			$reopen_window = array('window_id' => (string)($_POST['window_id'] ?? ''), 'name' => (string)($_POST['name'] ?? ''),
			    'days[]' => array_values((array)($_POST['days'] ?? array())), 'start' => (string)($_POST['start'] ?? ''), 'length' => (string)($_POST['length'] ?? ''));
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
		array(gettext('Updates'), true, '/fleet/fleet_updates.php'),
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
if (!$ready): ?>
<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller')?></strong></div>
<?php include('foot.inc'); exit; endif;

fs_view_switch(array('overview' => gettext('Overview'), 'rollouts' => gettext('Rollouts'), 'windows' => gettext('Maintenance windows')), $view);
$day_names = array(1 => gettext('Mon'), 2 => gettext('Tue'), 3 => gettext('Wed'), 4 => gettext('Thu'), 5 => gettext('Fri'), 6 => gettext('Sat'), 7 => gettext('Sun'));
$target = fleet_rollout_target();
?>

<?php if ($view === 'overview'):
	$boxes = fleet_db()->query('SELECT node_id, label, status, update_info, role FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll();
	$versions = array();
	$avail = 0;
	$failed = 0;
	foreach ($boxes as $b) {
		$st = json_decode((string)$b['status'], true) ?: array();
		$v = fleet_version_number((string)($st['version'] ?? '')) ?: gettext('unknown');
		$versions[$v][] = $b;
		$i = fleet_update_info($b);
		$avail += ($i !== null && $i['available']) ? 1 : 0;
		$failed += ($i !== null && $i['error'] !== null) ? 1 : 0;
	}
	uksort($versions, function ($a, $b) { return version_compare($b, $a); });
?>
<div class="row g-3 fs-fleet-panels">
	<div class="col-md-4"><div class="fs-tile"><span class="fs-tile-label"><?=gettext('Newest version offered')?></span><span class="fs-tile-value"><?=htmlspecialchars($target ?? (string)(array_key_first(array_diff_key($versions, array(gettext('unknown') => 1))) ?? '-'))?></span>
		<?php if (($target === null) && ($avail === 0) && ($failed === 0) && !empty($versions)): ?><span class="fs-tile-hint"><?=gettext('All up to date')?></span><?php endif; ?></div></div>
	<div class="col-md-4"><div class="fs-tile"><span class="fs-tile-label"><?=gettext('Can update')?></span><span class="fs-tile-value"><?=(int)$avail?></span></div></div>
	<div class="col-md-4"><div class="fs-tile"><span class="fs-tile-label"><?=gettext('Could not check')?></span><span class="fs-tile-value"><?=(int)$failed?></span></div></div>
</div>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Versions in the fleet')?></h2></div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Version')?></th><th><?=gettext('Firewalls')?></th><th><?=gettext('Which')?></th></tr></thead>
		<tbody>
<?php foreach ($versions as $v => $list): ?>
		<tr><td class="fs-mono"><?=htmlspecialchars($v)?> <?=($target !== null && version_compare($v, $target, '<')) ? fs_badge('info', gettext('Older')) : ''?></td><td><?=count($list)?></td>
			<td><?=implode(', ', array_map(function ($b) { return '<a href="/fleet/fleet_box.php?id=' . urlencode($b['node_id']) . '&amp;view=updates">' . htmlspecialchars($b['label']) . '</a>'; }, array_slice($list, 0, 12)))?><?=(count($list) > 12) ? ' ' . sprintf(gettext('and %d more'), count($list) - 12) : ''?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php if ($manage && $target !== null): ?>
	<div class="panel-footer"><a class="btn btn-primary btn-sm" href="?view=rollouts&amp;new=1" data-fs-modal="#rings-modal"><i class="fa-solid fa-layer-group icon-embed-btn" aria-hidden="true"></i><?=sprintf(gettext('Roll out %s...'), htmlspecialchars($target))?></a></div>
<?php endif; ?>
</div>

<?php elseif ($view === 'rollouts'):
	$groups = fleet_groups_all();
	$picked = array_map('intval', array_filter((array)($_GET['ring'] ?? array()), 'strlen'));
	$review = $manage && isset($_GET['review']) && !empty($picked) && ($target !== null);
?>
<?php if ($manage && ($target !== null) && !$review): ?>
<div class="panel panel-default">
	<div class="panel-body fs-fleet-pad fs-fleet-heading-actions">
		<p class="fs-fleet-lead mb-0"><?=sprintf(htmlspecialchars(gettext('%s is available. A rollout updates groups ring by ring, each in its maintenance window.')), htmlspecialchars($target))?></p>
		<button type="button" class="btn btn-sm btn-primary" data-fs-modal="#rings-modal"><i class="fa-solid fa-layer-group icon-embed-btn" aria-hidden="true"></i><?=sprintf(gettext('Roll out %s...'), htmlspecialchars($target))?></button>
	</div>
</div>
<?php endif; ?>
<?php if ($review):
	$plan = fleet_rollout_plan($picked, $target);
	$hash = hash('sha256', json_encode(array_map(function ($r) { return array_column($r[3], 'node_id'); }, $plan['rings'])));
	$n = array_sum(array_map(function ($r) { return count($r[3]); }, $plan['rings']));
?>
<div class="panel panel-default fs-fleet-review" role="region" aria-labelledby="review-title">
	<div class="panel-heading"><h2 id="review-title" class="panel-title"><?=sprintf(htmlspecialchars(gettext('Update %1$d firewalls to %2$s in %3$d rings?')), $n, htmlspecialchars($target), count($plan['rings']))?></h2></div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Ring')?></th><th><?=gettext('Window')?></th><th><?=gettext('Firewalls, in order')?></th></tr></thead>
		<tbody>
<?php foreach ($plan['rings'] as $r => list($gid, $name, $window, $list)): ?>
		<tr><td><strong><?=$r + 1?>. <?=htmlspecialchars(gettext($name))?></strong></td>
			<td><?=($window === null) ? '<span class="fs-muted">' . gettext('Any time') . '</span>' : htmlspecialchars(fleet_window_text($window))?></td>
			<td><?=empty($list) ? '<span class="fs-muted">' . gettext('None (all are in an earlier ring or cannot update)') . '</span>' : htmlspecialchars(implode(', ', array_column($list, 'label')))?></td></tr>
<?php endforeach; ?>
<?php foreach ($plan['skip'] as list($b, $why)): ?>
		<tr><td class="fs-muted">-</td><td></td><td><?=htmlspecialchars((string)$b['label'])?> <?=fs_badge('neutral', gettext('Left alone'))?> <span class="fs-muted"><?=htmlspecialchars(gettext($why))?></span></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
	<div class="panel-footer">
		<form method="post" class="fs-fleet-review-actions">
<?php foreach ($picked as $gid): ?>
			<input type="hidden" name="ring[]" value="<?=(int)$gid?>"/>
<?php endforeach; ?>
			<input type="hidden" name="target" value="<?=htmlspecialchars($target)?>"/>
			<input type="hidden" name="plan" value="<?=$hash?>"/>
			<label class="fs-muted small" for="gap"><?=gettext('Wait between rings')?></label>
			<div class="input-group input-group-sm fs-fleet-gap"><input class="form-control" type="number" id="gap" name="gap" min="0" max="168" value="<?=(int)fleet_opt('rollout_gap_hours')?>"/><span class="input-group-text"><?=gettext('hours')?></span></div>
			<button class="btn btn-primary" type="submit" name="rollout_start" value="1"<?=($n === 0) ? ' disabled' : ''?>><i class="fa-solid fa-layer-group icon-embed-btn" aria-hidden="true"></i><?=($n === 0) ? gettext('Nothing to update') : sprintf(gettext('Start the rollout to %s'), htmlspecialchars($target))?></button>
			<button type="button" class="btn btn-outline-secondary" data-fs-modal="#rings-modal" data-fs-fill="<?=htmlspecialchars(json_encode(array_combine(array_map(function ($i) { return 'ring[' . $i . ']'; }, array_keys($picked)), array_map('strval', $picked))))?>"><?=gettext('Change rings')?></button>
			<a class="btn btn-link" href="?view=rollouts"><?=gettext('Cancel')?></a>
		</form>
	</div>
</div>
<?php endif; ?>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Rollouts')?></h2></div>
<?php $rollouts = fleet_rollouts_all(20); ?>
<?php if (empty($rollouts)): ?>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=($target === null) ? gettext('No firewall has an update available.') : sprintf(gettext('No rollouts yet. %s is available.'), htmlspecialchars($target))?>
<?php if ($manage && $target !== null): ?> <a href="?view=rollouts&amp;new=1" data-fs-modal="#rings-modal"><?=sprintf(gettext('Roll out %s...'), htmlspecialchars($target))?></a><?php endif; ?></p></div>
<?php else: ?>
	<div class="panel-body fs-fleet-pad fs-fleet-rollouts">
<?php foreach ($rollouts as $ro):
	$rings = fleet_rollout_rings_now($ro);
	$live = in_array($ro['state'], array('running', 'paused'), true);
	$badge = array('running' => array('info', gettext('Running')), 'paused' => array('warn', gettext('Paused')), 'done' => array('pass', gettext('Done')),
	    'cancelled' => array('neutral', gettext('Cancelled')))[$ro['state']] ?? array('neutral', $ro['state']);
?>
		<article class="fs-fleet-rollout" data-state="<?=htmlspecialchars($ro['state'])?>">
			<header class="fs-fleet-rollout-head">
				<h3><a href="/fleet/fleet_activity.php?op=<?=(int)$ro['op_id']?>"><?=sprintf(htmlspecialchars(gettext('Roll out %s')), htmlspecialchars($ro['target']))?></a></h3>
				<?=fs_badge($badge[0], $badge[1])?>
				<span class="fs-muted small"><?=htmlspecialchars(date('Y-m-d H:i', (int)$ro['created']))?>, <?=htmlspecialchars($ro['who'])?></span>
<?php if ($manage && $live): ?>
				<form method="post" class="ms-auto d-flex gap-2">
<?php if ($ro['state'] === 'paused'): ?>
					<button class="btn btn-sm btn-primary" name="rollout_resume" value="<?=(int)$ro['id']?>"><i class="fa-solid fa-play icon-embed-btn" aria-hidden="true"></i><?=gettext('Resume')?></button>
<?php endif; ?>
					<button class="btn btn-sm btn-outline-secondary" name="rollout_cancel" value="<?=(int)$ro['id']?>"><?=gettext('Cancel the rest')?></button>
				</form>
<?php endif; ?>
			</header>
<?php if ($live): ?>
			<p class="fs-fleet-rollout-now"><?=htmlspecialchars((string)$ro['op_text'])?></p>
<?php endif; ?>
			<ol class="fs-fleet-ringlist">
<?php foreach ($rings as $r => $ring):
	$total = count($ring['shown']);
	$fin = count(array_filter($ring['shown'], function ($s) { return !in_array($s, array('queued', 'running'), true); }));
	$bad = count(array_keys($ring['shown'], 'failed', true));
	$ok = count(array_keys($ring['shown'], 'done', true));
	$gone = $total - $ok - $bad - ($total - $fin);
	/* Green only for real updates: a cancelled or empty ring stays grey. */
	if ($fin < $total) {
		$rstate = in_array('running', $ring['shown'], true) ? 'running' : 'queued';
	} else {
		$rstate = ($bad > 0) ? 'failed' : ((($total > 0) && ($ok === $total)) ? 'done' : 'skipped');
	}
?>
				<li><span class="fs-fleet-ringname"><?=htmlspecialchars(gettext((string)$ring['ring']['name']))?></span>
					<span class="fs-muted small"><?=($ring['window'] === null) ? gettext('any time') : htmlspecialchars(fleet_window_text($ring['window']))?></span>
					<?=fleet_progress_bar($rstate, ($total === 0) ? 100 : (int)floor(100 * $fin / $total), (string)$ring['ring']['name'], 'thin')?>
					<span class="fs-muted small fs-fleet-ringcount"><?=sprintf(gettext('%1$d of %2$d updated'), $ok, $total)?><?=($bad > 0) ? ', ' . sprintf(gettext('%d failed'), $bad) : ''?><?=($gone > 0) ? ', ' . sprintf(gettext('%d left alone'), $gone) : ''?></span></li>
<?php endforeach; ?>
			</ol>
		</article>
<?php endforeach; ?>
	</div>
<?php endif; ?>
</div>

<?php else:
	$windows = fleet_windows_all();
	$wq = trim((string)($_GET['q'] ?? ''));
	$wshown = array_values(array_filter($windows, function ($w) use ($wq) {
		return ($wq === '') || (stripos($w['name'] . ' ' . fleet_window_text($w) . ' ' . implode(' ', fleet_window_users($w['id'])), $wq) !== false);
	}));
	$wfill = function (?array $w) {
		$w = $w ?? array('id' => '', 'name' => '', 'days' => array(1, 2, 3, 4, 5), 'start' => 60, 'length' => 180);
		return json_encode(array('window_id' => (string)$w['id'], 'name' => $w['name'], 'days[]' => array_map('strval', $w['days']),
		    'start' => sprintf('%02d:%02d', intdiv($w['start'], 60), $w['start'] % 60), 'length' => (string)$w['length']));
	};
?>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Maintenance windows')?> <span class="fs-count"><?=count($windows)?></span></h2>
<?php if ($manage): ?>
		<button type="button" class="btn btn-sm btn-primary" data-fs-modal="#window-modal" data-fs-modal-title="<?=gettext('Add a window')?>" data-fs-fill="<?=htmlspecialchars($wfill(null))?>"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add window')?></button>
<?php endif; ?>
	</div>
<?php if (empty($windows)): ?>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=gettext('No windows yet. A window is a weekly time when a group may be updated, for example weeknights 01:00 for 3 hours.')?></p></div>
<?php else: ?>
	<div class="panel-body fs-fleet-pad">
		<form method="get" class="fs-fleet-filterbar" role="search" data-fleet-filters><script src="/fleet/assets/fleet-list.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-list.js')?>" defer></script>
			<input type="hidden" name="view" value="windows"/>
			<input class="form-control form-control-sm" type="search" name="q" value="<?=htmlspecialchars($wq)?>" placeholder="<?=gettext('Search name, days or group')?>" aria-label="<?=gettext('Search windows')?>"/>
			<button class="btn btn-sm btn-outline-secondary" type="submit"><?=gettext('Search')?></button>
<?php if ($wq !== ''): ?>
			<a class="btn btn-sm btn-link" href="?view=windows"><?=gettext('Clear')?></a>
			<span class="fs-muted small ms-auto"><?=sprintf(gettext('%1$d of %2$d'), count($wshown), count($windows))?></span>
<?php endif; ?>
		</form>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Name')?></th><th><?=gettext('When')?></th><th><?=gettext('Now')?></th><th><?=gettext('Used by')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($wshown)): ?>
		<tr><td colspan="5" class="fs-muted"><?=gettext('No window matches.')?> <a href="?view=windows"><?=gettext('Clear the search')?></a></td></tr>
<?php endif; ?>
<?php foreach ($wshown as $w): list($open, $left) = fleet_window_state($w, time(), fleet_tz()); $next = fleet_window_next($w, time(), fleet_tz()); $users = fleet_window_users($w['id']); ?>
		<tr><td><?=htmlspecialchars($w['name'])?></td><td><?=htmlspecialchars(fleet_window_text($w))?></td>
			<td><?=$open ? fs_badge('pass', sprintf(gettext('Open, %s left'), fleet_op_duration($left))) : '<span class="fs-muted">' . sprintf(gettext('Opens %s'), htmlspecialchars(date('D H:i', (int)$next))) . '</span>'?></td>
			<td><?=empty($users) ? '<span class="fs-muted">-</span>' : htmlspecialchars(implode(', ', $users))?></td>
			<td class="text-end text-nowrap">
<?php if ($manage): ?>
				<button type="button" class="btn btn-sm btn-link" data-fs-modal="#window-modal" data-fs-modal-title="<?=htmlspecialchars(sprintf(gettext('Change %s'), $w['name']))?>" data-fs-fill="<?=htmlspecialchars($wfill($w))?>"><?=gettext('Change')?></button>
				<form method="post" action="?view=windows" class="d-inline"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="window_delete" value="<?=(int)$w['id']?>"><?=gettext('Delete')?></button></form>
<?php endif; ?>
			</td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php endif; ?>
	<div class="panel-footer small fs-muted"><?=sprintf(gettext('Times are the controller\'s time zone (%s). A window may run past midnight. A rollout does not start an update when less than %d minutes are left.'), htmlspecialchars(fleet_tz()), fleet_opt('update_timeout'))?></div>
</div>
<?php if ($manage):
	fs_modal_form_begin('window-modal', gettext('Add a window'), '?view=windows', array('window_id' => ''), $reopen_window);
?>
	<div class="mb-3"><label class="form-label" for="wname"><?=gettext('Name')?></label>
		<input class="form-control" id="wname" name="name" maxlength="40" required placeholder="<?=gettext('Weeknights')?>"/></div>
	<fieldset class="mb-3"><legend class="form-label"><?=gettext('Days')?></legend>
		<div class="fs-fleet-days">
<?php foreach ($day_names as $d => $label): ?>
			<label class="fs-fleet-day"><input type="checkbox" name="days[]" value="<?=$d?>"/><span><?=htmlspecialchars($label)?></span></label>
<?php endforeach; ?>
		</div></fieldset>
	<div class="row g-3">
		<div class="col-sm-6"><label class="form-label" for="wstart"><?=gettext('Starts at')?></label>
			<input class="form-control" type="time" id="wstart" name="start" required value="01:00"/></div>
		<div class="col-sm-6"><label class="form-label" for="wlength"><?=gettext('Length')?></label>
			<div class="input-group"><input class="form-control" type="number" id="wlength" name="length" min="30" max="1440" step="30" required value="180"/><span class="input-group-text"><?=gettext('minutes')?></span></div></div>
	</div>
	<p class="fs-fleet-hint mt-3 mb-0"><?=gettext('Choose the window for a group on Firewalls > Groups.')?></p>
<?php
	fs_modal_form_end(gettext('Save window'), 'window_save', '1', 'fa-floppy-disk');
endif; ?>
<?php endif; ?>
<?php if ($manage && ($target !== null)):
	/* Rings: chosen in a modal from any view; the review is a page. */
	$ring_groups = fleet_groups_all();
	fs_modal_form_begin('rings-modal', sprintf(gettext('Roll out %s'), $target), '?view=rollouts');
?>
	<p class="fs-fleet-hint"><?=gettext('Rings update in order. Inside a ring, firewalls update one at a time and only in the ring\'s maintenance window (no window: any time). The next ring starts when the one before is done and the wait has passed. A failure pauses the rollout.')?></p>
<?php for ($i = 0; $i < 5; $i++): ?>
	<div class="mb-2 row g-2 align-items-center"><label class="col-3 col-form-label" for="ring<?=$i?>"><?=sprintf(gettext('Ring %d'), $i + 1)?></label>
		<div class="col-9"><select class="form-select" id="ring<?=$i?>" name="ring[<?=$i?>]"<?=($i === 0) ? ' required' : ''?>>
			<option value=""><?=($i === 0) ? gettext('Choose a group') : gettext('(none)')?></option>
<?php foreach ($ring_groups as $grp): ?>
			<option value="<?=(int)$grp['id']?>"><?=htmlspecialchars($grp['name'])?><?=$grp['window_id'] ? ' (' . htmlspecialchars(fleet_window_text(fleet_window_get((int)$grp['window_id']))) . ')' : ''?></option>
<?php endforeach; ?>
			<option value="0"><?=gettext('Everyone else (no window)')?></option>
		</select></div></div>
<?php endfor; ?>
<?php
	fs_modal_form_end(gettext('Review'), 'rollout_rings', '1', 'fa-list-check');
endif; ?>
<?php include('foot.inc');
