<?php
/*
 * fleet_policies.php
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
 * Policy Manager: how the fleet complies (Compliance), the policies and
 * their rules (Policies, with a full-page editor), and exceptions with an
 * end date (Exceptions). The rules and checks are fleet_policy.inc.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Policies'));
$who = (string)($_SESSION['Username'] ?? 'admin');
$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$manage = isAllowedPage('fleet/fleet.php');
$input_errors = array();
$savemsg = null;
$reopen = null;
$view = fs_view_param(array('compliance', 'policies', 'exceptions', 'edit'), 'compliance');
$typed = null;

if ($ready && $manage && ($_SERVER['REQUEST_METHOD'] === 'POST')) {
	try {
		if (isset($_POST['policy_save'])) {
			$view = 'edit';
			$typed = $_POST;
			$id = fleet_policy_save(((int)($_POST['policy_id'] ?? 0) > 0) ? (int)$_POST['policy_id'] : null, $_POST, $who);
			header('Location: /fleet/fleet_policies.php?view=policies&saved=' . (int)$id);
			exit;
		} elseif (isset($_POST['policy_delete'])) {
			$view = 'policies';
			fleet_policy_delete((int)$_POST['policy_delete'], $who);
			$savemsg = gettext('Policy deleted. Its firewalls are checked against the remaining policies.');
		} elseif (isset($_POST['exception_save'])) {
			$view = 'exceptions';
			fleet_policy_exception_add((string)($_POST['node'] ?? ''), (string)($_POST['rule'] ?? ''), (string)($_POST['reason'] ?? ''), (string)($_POST['until'] ?? ''), $who);
			$savemsg = gettext('Exception added.');
		} elseif (isset($_POST['exception_delete'])) {
			$view = 'exceptions';
			fleet_policy_exception_delete((int)$_POST['exception_delete'], $who);
			$savemsg = gettext('Exception ended. The rule counts again for that firewall.');
		} elseif (isset($_POST['recheck'])) {
			fleet_compliance_refresh();
			$savemsg = gettext('Every firewall was checked again.');
		}
	} catch (InvalidArgumentException | RuntimeException $e) {
		$input_errors[] = $e->getMessage();
		if (isset($_POST['exception_save'])) {
			$reopen = array_intersect_key($_POST, array_flip(array('node', 'rule', 'reason', 'until')));
		}
	}
}
if (isset($_GET['saved'])) {
	$savemsg = gettext('Policy saved and every firewall checked against it.');
}
if ($ready && $manage && ($view === 'policies')) {
	fs_page_action(gettext('Add policy'), '/fleet/fleet_policies.php?view=edit', 'fa-plus', 'primary');
}
if (($reopen === null) && ($view === 'exceptions') && isset($_GET['node'], $_GET['rule'])) {
	$reopen = array('node' => (string)$_GET['node'], 'rule' => (string)$_GET['rule'], 'until' => date('Y-m-d', time() + 30 * 86400));
}
if ($ready && $manage && ($view === 'exceptions')) {
	fs_page_action(gettext('Add exception'), '#', 'fa-plus', 'primary', array('data-fs-modal' => '#exception-modal',
	    'data-fs-fill' => json_encode(array('until' => date('Y-m-d', time() + 30 * 86400)))));
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
		array(gettext('Policies'), true, '/fleet/fleet_policies.php'),
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

$cat = fleet_policy_catalog();
$policies = fleet_policies_all();
$labels = fleet_db()->query('SELECT node_id, label FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll(PDO::FETCH_KEY_PAIR);
$names = fleet_target_names();
$groups = fleet_groups_all();
/* Every rule id in use (custom rules have their own ids), with its title. */
$rule_titles = array();
foreach ($cat as $rid => $r) {
	if (empty($r['custom'])) {
		$rule_titles[$rid] = $r['title'];
	}
}
foreach ($policies as $p) {
	foreach ($p['rules'] as $rid => list($params)) {
		$rule_titles[$rid] = fleet_policy_rule_title($rid, $params);
	}
}
if ($view !== 'edit') {
	fs_view_switch(array('compliance' => gettext('Compliance'), 'policies' => gettext('Policies'), 'exceptions' => gettext('Exceptions')), $view);
}
$state_badge = function (string $state) {
	return array('pass' => fs_badge('pass', gettext('Pass')), 'fail' => fs_badge('block', gettext('Fails')), 'unknown' => fs_badge('neutral', gettext('Unknown')),
	    'excepted' => fs_badge('info', gettext('Exception')))[$state] ?? htmlspecialchars($state);
};
?>

<?php if ($view === 'compliance'):
	$counts = fleet_compliance_counts();
	$rows = fleet_db()->query('SELECT * FROM compliance')->fetchAll();
	$by_rule = array();
	$fails_of = array();
	foreach ($rows as $r) {
		$by_rule[$r['rule_id']] = ($by_rule[$r['rule_id']] ?? array('fail' => 0, 'pass' => 0, 'unknown' => 0, 'excepted' => 0));
		$by_rule[$r['rule_id']][$r['state']]++;
		if ($r['state'] === 'fail') {
			$fails_of[$r['node_id']][] = $rule_titles[$r['rule_id']] ?? $r['rule_id'];
		}
	}
	$tot = array('pass' => 0, 'fail' => 0);
	foreach ($counts as $c) {
		$tot['pass'] += $c['pass'] + $c['excepted'];
		$tot['fail'] += $c['fail'];
	}
	$score = ($tot['pass'] + $tot['fail'] > 0) ? (int)floor(100 * $tot['pass'] / ($tot['pass'] + $tot['fail'])) : null;
	$box_state = function ($node) use ($counts) {
		$c = $counts[$node] ?? null;
		return ($c === null) ? 'none' : (($c['fail'] > 0) ? 'fail' : (($c['unknown'] > 0) ? 'unknown' : 'ok'));
	};
	$members = fleet_box_group_ids();
	/* Filters live in the URL. */
	$q = trim((string)($_GET['q'] ?? ''));
	$fs = in_array($_GET['state'] ?? '', array('fail', 'unknown', 'ok', 'none'), true) ? (string)$_GET['state'] : '';
	$fr = isset($rule_titles[$_GET['rule'] ?? '']) ? (string)$_GET['rule'] : '';
	$fg = (int)($_GET['group'] ?? 0);
	$failing_rule = array();
	foreach ($rows as $r) {
		if ($r['state'] === 'fail') {
			$failing_rule[$r['rule_id']][$r['node_id']] = true;
		}
	}
	$list = array();
	foreach ($labels as $node => $label) {
		if ((($q === '') || (stripos($label . ' ' . implode(' ', $fails_of[$node] ?? array()), $q) !== false)) && (($fs === '') || ($box_state($node) === $fs)) &&
		    (($fr === '') || isset($failing_rule[$fr][$node])) && (($fg === 0) || in_array($fg, $members[$node] ?? array(), true))) {
			$list[$node] = $label;
		}
	}
	$per = 50;
	$pages = max(1, (int)ceil(count($list) / $per));
	$page = min($pages, max(1, (int)($_GET['page'] ?? 1)));
	$shown = array_slice($list, ($page - 1) * $per, $per, true);
	$filtered = ($q !== '') || ($fs !== '') || ($fr !== '') || ($fg > 0);
	$link = function (array $change) use ($q, $fs, $fr, $fg) {
		return '?' . htmlspecialchars(http_build_query(array_filter($change + array('view' => 'compliance', 'q' => $q, 'state' => $fs, 'rule' => $fr, 'group' => $fg ?: ''), 'strlen')));
	};
	$nstate = array('fail' => 0, 'unknown' => 0, 'ok' => 0);
	foreach (array_keys($labels) as $node) {
		$s = $box_state($node);
		if (isset($nstate[$s])) {
			$nstate[$s]++;
		}
	}
?>
<?php if (empty($policies)): ?>
<div class="panel panel-default"><div class="panel-body fs-fleet-pad">
	<p class="fs-fleet-lead"><?=gettext('No policies yet. A policy holds rules (minimum or pinned version, SSH by key only, NTP set, hostname pattern...) for all firewalls, groups or single firewalls. Fleet checks them against what each firewall reports and its newest configuration backup.')?></p>
<?php if ($manage): ?>
	<a class="btn btn-primary btn-sm" href="?view=edit"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add the first policy')?></a>
<?php endif; ?>
</div></div>
<?php else: ?>
<div class="fs-tiles fs-fleet-tiles-row">
	<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Compliance')?></span><span class="fs-tile-value"><?=($score === null) ? '-' : $score . '%'?></span></div>
	<a class="fs-tile fs-fleet-tile-link" href="<?=$link(array('state' => 'fail', 'page' => ''))?>"><span class="fs-tile-label"><?=gettext('Firewalls failing a rule')?></span><span class="fs-tile-value"><?=$nstate['fail']?></span></a>
	<a class="fs-tile fs-fleet-tile-link" href="<?=$link(array('state' => 'unknown', 'page' => ''))?>"><span class="fs-tile-label"><?=gettext('Not known yet')?></span><span class="fs-tile-value"><?=$nstate['unknown']?></span></a>
	<a class="fs-tile fs-fleet-tile-link" href="<?=$link(array('state' => 'ok', 'page' => ''))?>"><span class="fs-tile-label"><?=gettext('Compliant')?></span><span class="fs-tile-value"><?=$nstate['ok']?></span></a>
</div>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><i class="fa-solid fa-shield-halved icon-embed-btn" aria-hidden="true"></i><?=gettext('Rules across the fleet')?></h2>
		<span class="fs-muted small"><?=sprintf(gettext('Checked %s'), htmlspecialchars(date('H:i', (int)fleet_setting('compliance_checked', '0'))))?>
<?php if ($manage): ?>
			<form method="post" class="d-inline"><button class="btn btn-sm btn-link" name="recheck" value="1"><?=gettext('Check now')?></button></form>
<?php endif; ?>
		</span></div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Rule')?></th><th><?=gettext('Fails')?></th><th><?=gettext('Pass')?></th><th><?=gettext('Unknown')?></th><th><?=gettext('Exceptions')?></th></tr></thead>
		<tbody>
<?php uasort($by_rule, function ($a, $b) { return $b['fail'] <=> $a['fail']; }); foreach ($by_rule as $rid => $c): ?>
		<tr><td><a href="<?=$link(array('rule' => $rid, 'state' => '', 'page' => ''))?>"><?=htmlspecialchars($rule_titles[$rid] ?? $rid)?></a> <span class="fs-muted small"><?=htmlspecialchars(preg_replace('/:\d+$/', '', $rid))?></span></td>
			<td><?=($c['fail'] > 0) ? fs_badge('block', (string)$c['fail']) : '<span class="fs-muted">0</span>'?></td><td><?=$c['pass']?></td><td><?=$c['unknown']?></td><td><?=$c['excepted']?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
</div>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-server icon-embed-btn" aria-hidden="true"></i><?=gettext('Firewalls')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<form method="get" class="fs-fleet-filterbar" role="search" data-fleet-filters><script src="/fleet/assets/fleet-list.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-list.js')?>" defer></script>
			<input type="hidden" name="view" value="compliance"/>
			<input class="form-control form-control-sm" type="search" name="q" value="<?=htmlspecialchars($q)?>" placeholder="<?=gettext('Search firewall or failing rule')?>" aria-label="<?=gettext('Search firewalls')?>"/>
			<select class="form-select form-select-sm" name="state" aria-label="<?=gettext('State')?>">
				<option value=""><?=gettext('Any state')?></option>
				<option value="fail"<?=($fs === 'fail') ? ' selected' : ''?>><?=gettext('Fails a rule')?></option>
				<option value="unknown"<?=($fs === 'unknown') ? ' selected' : ''?>><?=gettext('Not known yet')?></option>
				<option value="ok"<?=($fs === 'ok') ? ' selected' : ''?>><?=gettext('Compliant')?></option>
				<option value="none"<?=($fs === 'none') ? ' selected' : ''?>><?=gettext('No policy')?></option>
			</select>
			<select class="form-select form-select-sm" name="rule" aria-label="<?=gettext('Failing rule')?>">
				<option value=""><?=gettext('Any failing rule')?></option>
<?php foreach ($rule_titles as $rid => $t): ?>
				<option value="<?=htmlspecialchars($rid)?>"<?=($fr === $rid) ? ' selected' : ''?>><?=htmlspecialchars($t)?></option>
<?php endforeach; ?>
			</select>
			<select class="form-select form-select-sm" name="group" aria-label="<?=gettext('Group')?>">
				<option value=""><?=gettext('Any group')?></option>
<?php foreach ($groups as $grp): ?>
				<option value="<?=(int)$grp['id']?>"<?=($fg === (int)$grp['id']) ? ' selected' : ''?>><?=htmlspecialchars($grp['name'])?></option>
<?php endforeach; ?>
			</select>
			<button class="btn btn-sm btn-outline-secondary" type="submit"><?=gettext('Filter')?></button>
<?php if ($filtered): ?>
			<a class="btn btn-sm btn-link" href="?view=compliance"><?=gettext('Clear')?></a>
<?php endif; ?>
			<span class="fs-muted small ms-auto"><?=$filtered ? sprintf(gettext('%1$d of %2$d'), count($list), count($labels)) : sprintf(ngettext('%d firewall', '%d firewalls', count($labels)), count($labels))?></span>
		</form>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Firewall')?></th><th><?=gettext('State')?></th><th><?=gettext('Fails')?></th></tr></thead>
		<tbody>
<?php if (empty($shown)): ?>
		<tr><td colspan="3" class="fs-muted"><?=gettext('No firewall matches.')?> <a href="?view=compliance"><?=gettext('Clear the filters')?></a></td></tr>
<?php endif; ?>
<?php foreach ($shown as $node => $label): $s = $box_state($node); $c = $counts[$node] ?? null; ?>
		<tr><td><a href="/fleet/fleet_box.php?id=<?=urlencode($node)?>&amp;view=policies"><?=htmlspecialchars($label)?></a></td>
			<td><?=array('fail' => fs_badge('block', gettext('Fails')), 'unknown' => fs_badge('neutral', gettext('Not known yet')), 'ok' => fs_badge('pass', gettext('Compliant')),
			    'none' => '<span class="fs-muted">' . gettext('No policy') . '</span>')[$s]?>
				<?=(!empty($c['conflicts'])) ? fs_badge('warn', gettext('Conflict')) : ''?></td>
			<td class="small"><?=htmlspecialchars(implode(', ', $fails_of[$node] ?? array()))?></td></tr>
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
<?php endif; ?>

<?php elseif ($view === 'policies'):
	$pq = trim((string)($_GET['q'] ?? ''));
	$pshown = array_values(array_filter($policies, function ($p) use ($pq, $names) {
		return ($pq === '') || (stripos($p['name'] . ' ' . $p['description'] . ' ' . fleet_targets_text($p['targets'], $names), $pq) !== false);
	}));
	$fail_by_policy = array();
	foreach (fleet_db()->query("SELECT policy_id, COUNT(DISTINCT node_id) AS n FROM compliance WHERE state = 'fail' GROUP BY policy_id")->fetchAll() as $r) {
		$fail_by_policy[(int)$r['policy_id']] = (int)$r['n'];
	}
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-list-check icon-embed-btn" aria-hidden="true"></i><?=gettext('Policies')?> <span class="fs-count"><?=count($policies)?></span></h2></div>
<?php if (empty($policies)): ?>
	<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=gettext('No policies yet. Add one for all firewalls first (a baseline), then policies for groups or single firewalls that need something else: the most specific one wins for each rule.')?></p></div>
<?php else: ?>
	<div class="panel-body fs-fleet-pad">
		<form method="get" class="fs-fleet-filterbar" role="search" data-fleet-filters><script src="/fleet/assets/fleet-list.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-list.js')?>" defer></script>
			<input type="hidden" name="view" value="policies"/>
			<input class="form-control form-control-sm" type="search" name="q" value="<?=htmlspecialchars($pq)?>" placeholder="<?=gettext('Search name, description, group or firewall')?>" aria-label="<?=gettext('Search policies')?>"/>
			<button class="btn btn-sm btn-outline-secondary" type="submit"><?=gettext('Search')?></button>
<?php if ($pq !== ''): ?>
			<a class="btn btn-sm btn-link" href="?view=policies"><?=gettext('Clear')?></a>
			<span class="fs-muted small ms-auto"><?=sprintf(gettext('%1$d of %2$d'), count($pshown), count($policies))?></span>
<?php endif; ?>
		</form>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Name')?></th><th><?=gettext('For')?></th><th><?=gettext('Rules')?></th><th><?=gettext('Firewalls failing')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($pshown)): ?>
		<tr><td colspan="5" class="fs-muted"><?=gettext('No policy matches.')?> <a href="?view=policies"><?=gettext('Clear the search')?></a></td></tr>
<?php endif; ?>
<?php foreach ($pshown as $p): ?>
		<tr><td><a href="?view=edit&amp;id=<?=(int)$p['id']?>"><?=htmlspecialchars($p['name'])?></a> <?=$p['enabled'] ? '' : fs_badge('neutral', gettext('Off'))?>
				<?=($p['description'] !== '') ? '<div class="fs-muted small">' . htmlspecialchars($p['description']) . '</div>' : ''?></td>
			<td><?=htmlspecialchars(fleet_targets_text($p['targets'], $names))?></td>
			<td class="small"><?=htmlspecialchars(implode(', ', array_map(function ($rid) use ($p) { return fleet_policy_rule_title($rid, $p['rules'][$rid][0]) . (($p['rules'][$rid][1] === 'lock') ? ' (' . gettext('locked') . ')' : (($p['rules'][$rid][1] === 'remediate') ? ' (' . gettext('fixed') . ')' : '')); }, array_keys($p['rules']))))?></td>
			<td><?=!empty($fail_by_policy[(int)$p['id']]) ? '<a href="?view=compliance&amp;state=fail">' . fs_badge('block', (string)$fail_by_policy[(int)$p['id']]) . '</a>' : '<span class="fs-muted">0</span>'?></td>
			<td class="text-end text-nowrap">
<?php if ($manage): ?>
				<a class="btn btn-sm btn-link" href="?view=edit&amp;id=<?=(int)$p['id']?>"><?=gettext('Change')?></a>
				<form method="post" class="d-inline"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="policy_delete" value="<?=(int)$p['id']?>"<?=fleet_confirm(sprintf(gettext('Delete the policy "%s"?'), $p['name']), gettext('Its rules are no longer checked. Its firewalls are checked against the remaining policies.'), gettext('Delete policy'), 'danger', 'trash')?>><?=gettext('Delete')?></button></form>
<?php endif; ?>
			</td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php endif; ?>
	<div class="panel-footer small fs-muted"><?=gettext('For each rule, the most specific policy wins: a firewall\'s own policy over its groups\' over all firewalls. Two groups that set the same rule differently are shown as a conflict on the firewall.')?></div>
</div>

<?php elseif ($view === 'exceptions'):
	$all_ex = fleet_policy_exceptions();
	$eq = trim((string)($_GET['q'] ?? ''));
	$show_ended = !empty($_GET['ended']);
	$now = time();
	$exs = array_values(array_filter($all_ex, function ($e) use ($eq, $show_ended, $now, $labels, $rule_titles) {
		return ($show_ended || ((int)$e['expires'] > $now)) &&
		    (($eq === '') || (stripos(($labels[$e['node_id']] ?? $e['node_id']) . ' ' . ($rule_titles[$e['rule_id']] ?? $e['rule_id']) . ' ' . $e['reason'] . ' ' . $e['who'], $eq) !== false));
	}));
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-triangle-exclamation icon-embed-btn" aria-hidden="true"></i><?=gettext('Exceptions')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<form method="get" class="fs-fleet-filterbar" role="search" data-fleet-filters><script src="/fleet/assets/fleet-list.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-list.js')?>" defer></script>
			<input type="hidden" name="view" value="exceptions"/>
			<input class="form-control form-control-sm" type="search" name="q" value="<?=htmlspecialchars($eq)?>" placeholder="<?=gettext('Search firewall, rule, reason or who')?>" aria-label="<?=gettext('Search exceptions')?>"/>
			<label class="form-check small"><input class="form-check-input" type="checkbox" name="ended" value="1"<?=$show_ended ? ' checked' : ''?>/> <span class="form-check-label"><?=gettext('Include ended')?></span></label>
			<button class="btn btn-sm btn-outline-secondary" type="submit"><?=gettext('Filter')?></button>
		</form>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Firewall')?></th><th><?=gettext('Rule')?></th><th><?=gettext('Why')?></th><th><?=gettext('Until')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($exs)): ?>
		<tr><td colspan="5" class="fs-muted"><?=empty($all_ex) ? gettext('No exceptions. An exception lets one firewall fail one rule until a date, with a reason, for example while a site is being rebuilt.') : gettext('No exception matches.')?></td></tr>
<?php endif; ?>
<?php foreach ($exs as $e): $ended = ((int)$e['expires'] <= $now); ?>
		<tr><td><?=htmlspecialchars($labels[$e['node_id']] ?? $e['node_id'])?></td><td><?=htmlspecialchars($rule_titles[$e['rule_id']] ?? $e['rule_id'])?></td>
			<td><?=htmlspecialchars($e['reason'])?> <span class="fs-muted small">(<?=htmlspecialchars($e['who'])?>)</span></td>
			<td><?=htmlspecialchars(date('Y-m-d', (int)$e['expires'] - 1))?> <?=$ended ? fs_badge('neutral', gettext('Ended')) : ((((int)$e['expires'] - $now) < 7 * 86400) ? fs_badge('warn', gettext('Ends soon')) : '')?></td>
			<td class="text-end"><?php if ($manage && !$ended): ?><form method="post" class="d-inline"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="exception_delete" value="<?=(int)$e['id']?>"<?=fleet_confirm(gettext('End this exception now?'), gettext('The rule counts again for this firewall: it shows as failing if it still does not follow it.'), gettext('End exception'), 'warning', 'hourglass-end')?>><?=gettext('End now')?></button></form><?php endif; ?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
	<div class="panel-footer small fs-muted"><?=gettext('When an exception ends, the rule counts again: the firewall shows as failing if it still does.')?></div>
</div>

<?php else: /* edit */
	$pol = isset($_GET['id']) ? fleet_policy_get((int)$_GET['id']) : null;
	if ($typed !== null) {
		/* After an error the form shows what was typed. */
		$pol = array('id' => (int)($typed['policy_id'] ?? 0), 'name' => (string)($typed['name'] ?? ''), 'description' => (string)($typed['description'] ?? ''),
		    'targets' => (array)($typed['targets'] ?? array()), 'enabled' => !empty($typed['enabled']), 'rules' => array());
		foreach (array_keys((array)($typed['use'] ?? array())) as $rid) {
			$pol['rules'][$rid] = array((array)($typed['rule'][$rid] ?? array()), (string)($typed['rule'][$rid]['mode'] ?? 'audit'));
		}
	}
	$pol = $pol ?? array('id' => 0, 'name' => '', 'description' => '', 'targets' => array('all'), 'enabled' => true, 'rules' => array());
	$custom_ids = array_values(array_filter(array_keys($pol['rules']), function ($rid) { return strncmp($rid, 'CUSTOM:', 7) === 0; }));
	$next = 1;
	foreach ($custom_ids as $cid) {
		$next = max($next, (int)substr($cid, 7) + 1);
	}
	$custom_ids[] = 'CUSTOM:' . $next;
	$areas = array();
	foreach ($cat as $rid => $r) {
		if (empty($r['custom'])) {
			$areas[$r['area']][] = $rid;
		}
	}
	$areas['Custom'] = $custom_ids;
	$boxes_for_sel = $labels;
	$field = function (string $rid, string $pname, array $def, $value) {
		list($type, $label) = $def;
		$id = 'r-' . preg_replace('/[^A-Za-z0-9-]/', '-', $rid) . '-' . $pname;
		$name = 'rule[' . htmlspecialchars($rid) . '][' . $pname . ']';
		$h = '<label class="form-label small" for="' . $id . '">' . htmlspecialchars(gettext($label)) . '</label>';
		if (strncmp($type, 'choice:', 7) === 0) {
			$h .= '<select class="form-select form-select-sm" id="' . $id . '" name="' . $name . '">';
			foreach (explode('|', substr($type, 7)) as $o) {
				$h .= '<option value="' . $o . '"' . (($o === (string)$value) ? ' selected' : '') . '>' . htmlspecialchars(str_replace('_', ' ', $o)) . '</option>';
			}
			return $h . '</select>';
		}
		return $h . '<input class="form-control form-control-sm' . (in_array($type, array('regex', 'path'), true) ? ' fs-mono' : '') . '" id="' . $id . '" name="' . $name . '" value="' . htmlspecialchars((string)$value) . '"' .
		    (($type === 'int') ? ' type="number" min="1" max="3650"' : '') . '/>';
	};
?>
<p><a class="fs-fleet-back" href="?view=policies"><i class="fa-solid fa-arrow-left" aria-hidden="true"></i> <?=gettext('All policies')?></a></p>
<form method="post" action="?view=edit<?=$pol['id'] ? '&amp;id=' . (int)$pol['id'] : ''?>" class="fs-fleet-policy-form">
	<input type="hidden" name="policy_id" value="<?=(int)$pol['id']?>"/>
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-shield-halved icon-embed-btn" aria-hidden="true"></i><?=$pol['id'] ? sprintf(htmlspecialchars(gettext('Change %s')), htmlspecialchars($pol['name'])) : gettext('Add a policy')?></h2></div>
		<div class="panel-body fs-fleet-pad">
			<div class="row g-3">
				<div class="col-md-4"><label class="form-label" for="pname"><?=gettext('Name')?></label>
					<input class="form-control" id="pname" name="name" maxlength="60" required value="<?=htmlspecialchars($pol['name'])?>" placeholder="<?=gettext('Baseline')?>"/></div>
				<div class="col-md-8"><label class="form-label" for="pdesc"><?=gettext('Description')?></label>
					<input class="form-control" id="pdesc" name="description" maxlength="300" value="<?=htmlspecialchars($pol['description'])?>" placeholder="<?=gettext('What every firewall must meet')?>"/></div>
				<div class="col-md-8"><label class="form-label" for="ptargets"><?=gettext('For')?></label>
					<select class="form-select" id="ptargets" name="targets[]" multiple size="8" data-fs-multiselect data-fs-exclusive="all"
					    data-fs-text-search="<?=gettext('Search groups and firewalls…')?>" data-fs-text-none="<?=gettext('Choose firewalls…')?>" data-fs-text-more="<?=gettext('+%d more')?>">
						<option value="all"<?=in_array('all', $pol['targets'], true) ? ' selected' : ''?>><?=gettext('All firewalls')?></option>
<?php if (!empty($groups)): ?>
						<optgroup label="<?=gettext('Groups')?>">
<?php foreach ($groups as $grp): ?>
							<option value="g:<?=(int)$grp['id']?>"<?=in_array('g:' . $grp['id'], $pol['targets'], true) ? ' selected' : ''?>><?=htmlspecialchars($grp['name'])?></option>
<?php endforeach; ?>
						</optgroup>
<?php endif; ?>
						<optgroup label="<?=gettext('Firewalls')?>">
<?php foreach ($boxes_for_sel as $node => $label): ?>
							<option value="n:<?=htmlspecialchars($node)?>"<?=in_array('n:' . $node, $pol['targets'], true) ? ' selected' : ''?>><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
						</optgroup>
					</select>
					<div class="form-text"><?=gettext('A policy for one firewall or a group wins over a policy for all firewalls, rule by rule.')?></div></div>
				<div class="col-md-4 d-flex align-items-end"><label class="form-check"><input class="form-check-input" type="checkbox" name="enabled" value="1"<?=$pol['enabled'] ? ' checked' : ''?>/> <span class="form-check-label"><?=gettext('On')?></span></label></div>
			</div>
		</div>
	</div>
<?php
	$area_info = array(
		'Versions' => array('fa-code-branch', gettext('Which FreeSense versions the firewalls run. Pinned and allowed versions also stop updates and rollouts that would break them.')),
		'Operations' => array('fa-gears', gettext('What keeps a firewall easy to run and recover: backups, rollback protection, time and logging.')),
		'Security' => array('fa-shield-halved', gettext('How the firewall itself can be reached and logged in to.')),
		'Naming' => array('fa-tag', gettext('Names and domains that follow your conventions, so a firewall is easy to find.')),
		'Custom' => array('fa-sliders', gettext('Any configuration setting, by its path. A custom rule tests a value; it never runs code.')),
	);
	$rule_icons = array('VER-001' => 'fa-arrow-up-wide-short', 'VER-002' => 'fa-thumbtack', 'VER-003' => 'fa-list-check', 'VER-004' => 'fa-satellite-dish',
	    'OPS-010' => 'fa-box-archive', 'OPS-020' => 'fa-clock-rotate-left', 'OPS-001' => 'fa-clock', 'OPS-002' => 'fa-scroll', 'OPS-003' => 'fa-earth-europe',
	    'SEC-001' => 'fa-key', 'SEC-002' => 'fa-lock', 'SEC-003' => 'fa-user-shield', 'NAME-001' => 'fa-font', 'NAME-002' => 'fa-globe', 'NAME-003' => 'fa-sitemap', 'NAME-004' => 'fa-tags', 'CUSTOM' => 'fa-sliders');
	$n_on = count($pol['rules']);
	$n_lock = count(array_filter($pol['rules'], function ($r) { return ($r[1] ?? '') === 'lock'; }));
	/* One area at a time; the others stay in the form (hidden), so saving still posts every rule. */
	$area_now = fs_view_param(array_map('strtolower', array_keys($areas)), strtolower((string)array_key_first($areas)), 'area');
?>
	<div class="fs-fleet-picker" data-fleet-picker data-area-now="<?=htmlspecialchars($area_now)?>">
		<div class="fs-fleet-picker-bar">
			<div class="fs-fleet-picker-sum" aria-live="polite">
				<span><strong data-picker="on"><?=$n_on?></strong> <?=gettext('rules on')?></span>
				<span><i class="fa-solid fa-lock" aria-hidden="true"></i> <strong data-picker="lock"><?=$n_lock?></strong> <?=gettext('locked')?></span>
				<span><i class="fa-solid fa-wrench" aria-hidden="true"></i> <strong data-picker="fix"><?=count(array_filter($pol['rules'], function ($r) { return ($r[1] ?? '') === 'remediate'; }))?></strong> <?=gettext('fixed by Fleet')?></span>
			</div>
			<input class="form-control form-control-sm fs-fleet-picker-search" type="search" data-picker="search" placeholder="<?=gettext('Search rules: ssh, backup, version...')?>" aria-label="<?=gettext('Search rules')?>"/>
			<div class="fs-fleet-seg" role="group" aria-label="<?=gettext('Show')?>">
				<button type="button" class="is-active" data-show="all" aria-pressed="true"><?=gettext('All')?></button>
				<button type="button" data-show="on" aria-pressed="false"><?=gettext('On')?></button>
				<button type="button" data-show="off" aria-pressed="false"><?=gettext('Off')?></button>
				<button type="button" data-show="lockable" aria-pressed="false"><?=gettext('Can lock')?></button>
				<button type="button" data-show="fixable" aria-pressed="false"><?=gettext('Can fix')?></button>
			</div>
			<button type="button" class="btn btn-sm btn-link fs-fleet-picker-help" data-bs-toggle="popover" data-bs-trigger="focus" data-bs-placement="bottom"
			    data-bs-content="<?=htmlspecialchars(gettext('Fix: Fleet has the firewall correct the setting in its maintenance window, after a safety backup, and does not retry a failed fix by itself. Lock: the firewall refuses saves that break the rule, also while the controller is offline; a console administrator can suspend it (break-glass).'))?>"><i class="fa-regular fa-circle-question icon-embed-btn" aria-hidden="true"></i><?=gettext('What are Fix and Lock?')?></button>
		</div>
		<div class="fs-fleet-picker-body">
			<nav class="fs-fleet-picker-nav" aria-label="<?=gettext('Rule areas')?>">
<?php foreach ($areas as $area => $rids): $on_here = count(array_intersect($rids, array_keys($pol['rules']))); ?>
				<a href="?view=edit&amp;id=<?=(int)($_GET['id'] ?? 0)?>&amp;area=<?=strtolower($area)?>" data-area-link="<?=strtolower($area)?>"<?=(strtolower($area) === $area_now) ? ' aria-current="page"' : ''?>><i class="fa-solid <?=$area_info[$area][0]?>" aria-hidden="true"></i>
					<span><?=htmlspecialchars(gettext($area))?></span><span class="fs-count" data-area-count><?=$on_here?>/<?=count($rids)?></span></a>
<?php endforeach; ?>
			</nav>
			<div class="fs-fleet-picker-areas">
<?php foreach ($areas as $area => $rids): ?>
			<section class="fs-fleet-area" id="area-<?=strtolower($area)?>" data-area="<?=strtolower($area)?>"<?=(strtolower($area) === $area_now) ? '' : ' hidden'?>>
				<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid <?=$area_info[$area][0]?>" aria-hidden="true"></i></span>
					<div><h2><?=htmlspecialchars(gettext($area))?></h2><p><?=htmlspecialchars($area_info[$area][1])?></p></div></header>
				<div class="fs-fleet-rule-grid">
<?php foreach ($rids as $rid): $base = preg_replace('/:\d+$/', '', $rid); $r = $cat[$base]; $used = isset($pol['rules'][$rid]); $vals = $used ? $pol['rules'][$rid][0] : array();
	$lockable = fleet_policy_lockable($base); $mode_now = $used ? (string)($pol['rules'][$rid][1] ?? 'audit') : 'audit';
	$title = ($base === 'CUSTOM') ? ($used ? fleet_policy_rule_title($rid, $vals) : gettext('New custom rule')) : gettext($r['title']);
	$cid = 'use-' . preg_replace('/[^A-Za-z0-9-]/', '-', $rid); ?>
					<article class="fs-fleet-rcard<?=$used ? ' is-on' : ''?>" data-rule data-lockable="<?=$lockable ? '1' : '0'?>" data-fixable="<?=in_array($base, FLEET_POLICY_REMEDIABLE, true) ? '1' : '0'?>"
					    data-text="<?=htmlspecialchars(strtolower($title . ' ' . $base . ' ' . $r['help'] . ' ' . $area))?>">
						<div class="fs-fleet-rcard-head">
							<span class="fs-fleet-rcard-icon fs-fleet-sev-<?=htmlspecialchars($r['severity'])?>"><i class="fa-solid <?=$rule_icons[$base] ?? 'fa-circle-check'?>" aria-hidden="true"></i></span>
							<div class="fs-fleet-rcard-title"><label for="<?=$cid?>"><?=htmlspecialchars($title)?></label>
								<span class="fs-muted small"><?=htmlspecialchars($base)?> &middot; <?=htmlspecialchars(gettext(ucfirst($r['severity'])))?></span></div>
							<div class="form-check form-switch m-0"><input class="form-check-input" type="checkbox" role="switch" id="<?=$cid?>" name="use[<?=htmlspecialchars($rid)?>]" value="1"<?=$used ? ' checked' : ''?> data-rule-toggle/></div>
						</div>
						<p class="fs-fleet-rcard-help"><?=htmlspecialchars(gettext($r['help']))?></p>
<?php $fixable = in_array($base, FLEET_POLICY_REMEDIABLE, true); ?>
<?php if (!empty($r['params']) || $lockable): ?>
						<div class="fs-fleet-rcard-settings" data-rule-settings<?=$used ? '' : ' hidden'?>>
<?php foreach ($r['params'] as $pname => $def): ?>
							<div><?=$field($rid, $pname, $def, $vals[$pname] ?? $def[2])?></div>
<?php endforeach; ?>
<?php if ($lockable): $mname = 'rule[' . htmlspecialchars($rid) . '][mode]'; $mid = 'm-' . preg_replace('/[^A-Za-z0-9-]/', '-', $rid); ?>
							<div class="fs-fleet-mode-wrap"><div class="form-label small" id="<?=$mid?>-l"><?=gettext('When it is broken')?></div>
							<fieldset class="fs-fleet-mode" aria-labelledby="<?=$mid?>-l">
								<label><input type="radio" name="<?=$mname?>" value="audit"<?=(($mode_now !== 'lock') && !($fixable && ($mode_now === 'remediate'))) ? ' checked' : ''?> data-rule-mode/>
									<span title="<?=gettext('Fleet reports it; nothing changes on the firewall')?>"><i class="fa-solid fa-eye" aria-hidden="true"></i> <?=gettext('Report')?></span></label>
<?php if ($fixable): ?>
								<label><input type="radio" name="<?=$mname?>" value="remediate"<?=($mode_now === 'remediate') ? ' checked' : ''?> data-rule-mode/>
									<span title="<?=gettext('Fleet has the firewall correct it in its maintenance window')?>"><i class="fa-solid fa-wrench" aria-hidden="true"></i> <?=gettext('Fix')?></span></label>
<?php endif; ?>
								<label><input type="radio" name="<?=$mname?>" value="lock"<?=($mode_now === 'lock') ? ' checked' : ''?> data-rule-mode/>
									<span title="<?=gettext('The firewall refuses local saves that break it')?>"><i class="fa-solid fa-lock" aria-hidden="true"></i> <?=gettext('Lock')?></span></label>
							</fieldset></div>
<?php endif; ?>
						</div>
<?php endif; ?>
					</article>
<?php endforeach; ?>
				</div>
			</section>
<?php endforeach; ?>
				<p class="fs-fleet-hint" data-picker="empty" hidden><?=gettext('No rule matches.')?> <button type="button" class="btn btn-link btn-sm p-0" data-picker="clear"><?=gettext('Show all rules')?></button></p>
			</div>
		</div>
	</div>
	<div class="fs-form-actions fs-fleet-policy-actions">
		<a class="btn btn-outline-secondary" href="?view=policies"><?=gettext('Cancel')?></a>
		<button class="btn btn-primary" type="submit" name="policy_save" value="1"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save policy')?></button>
	</div>
</form>
<?php endif; ?>

<?php if ($manage && ($view === 'exceptions')):
	fs_modal_form_begin('exception-modal', gettext('Add an exception'), '?view=exceptions', array(), $reopen);
?>
	<div class="mb-3"><label class="form-label" for="exnode"><?=gettext('Firewall')?></label>
		<select class="form-select" id="exnode" name="node" required>
<?php foreach ($labels as $node => $label): ?>
			<option value="<?=htmlspecialchars($node)?>"><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
		</select></div>
	<div class="mb-3"><label class="form-label" for="exrule"><?=gettext('Rule')?></label>
		<select class="form-select" id="exrule" name="rule" required>
<?php foreach ($rule_titles as $rid => $t): ?>
			<option value="<?=htmlspecialchars($rid)?>"><?=htmlspecialchars($t)?></option>
<?php endforeach; ?>
		</select></div>
	<div class="mb-3"><label class="form-label" for="exreason"><?=gettext('Why')?></label>
		<input class="form-control" id="exreason" name="reason" maxlength="300" required placeholder="<?=gettext('Site being rebuilt; SSH passwords needed by the installer')?>"/></div>
	<div class="mb-1"><label class="form-label" for="exuntil"><?=gettext('Until (and including)')?></label>
		<input class="form-control" type="date" id="exuntil" name="until" required/></div>
<?php
	fs_modal_form_end(gettext('Add exception'), 'exception_save', '1', 'fa-floppy-disk');
endif; ?>
<?php if ($view === 'edit'): ?>
<script src="/fleet/assets/fleet-policy.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-policy.js')?>"></script>
<?php endif; ?>
<?=fleet_confirm_script()?>
<?php include('foot.inc');
