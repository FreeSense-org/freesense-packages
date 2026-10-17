<?php
/*
 * fleet_templates.php
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
 * Templates: the list (with how many firewalls are in sync), the editor
 * (alias cards) and the preview per firewall, which is also the review
 * before applying. The logic is fleet_templates.inc.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Templates'));
$who = (string)($_SESSION['Username'] ?? 'admin');
$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$manage = isAllowedPage('fleet/fleet.php');
$input_errors = array();
$savemsg = null;
$view = fs_view_param(array('list', 'edit', 'preview'), 'list');
$typed = null;

if ($ready && $manage && ($_SERVER['REQUEST_METHOD'] === 'POST')) {
	try {
		if (isset($_POST['template_save'])) {
			$view = 'edit';
			$typed = $_POST;
			$id = fleet_template_save(((int)($_POST['template_id'] ?? 0) > 0) ? (int)$_POST['template_id'] : null, $_POST, $who);
			header('Location: /fleet/fleet_templates.php?view=preview&saved=1&id=' . (int)$id);
			exit;
		} elseif (isset($_POST['template_delete'])) {
			$gone = fleet_template_get((int)$_POST['template_delete']);
			fleet_template_delete((int)$_POST['template_delete'], $who);
			$savemsg = ((($gone['kind'] ?? 'aliases') === 'aliases')) ? gettext('Template deleted. The aliases it pushed stay on the firewalls; Fleet no longer manages them.') :
			    gettext('Template deleted. The firewalls keep their settings; Fleet no longer manages them.');
		} elseif (isset($_POST['template_adopt']) || isset($_POST['template_ignore']) || isset($_POST['template_unignore'])) {
			$tid = (int)($_POST['template_adopt'] ?? $_POST['template_ignore'] ?? $_POST['template_unignore']);
			$t = fleet_template_get($tid);
			$box = fleet_box_get((string)($_POST['node'] ?? ''));
			if (($t === null) || ($box === null)) {
				throw new RuntimeException(gettext('That template or firewall no longer exists.'));
			}
			$view = 'preview';
			$_GET['id'] = $tid;
			if (isset($_POST['template_adopt'])) {
				$changed = fleet_template_adopt($t, $box, $who);
				$savemsg = empty($changed) ? sprintf(gettext('%s already matches the template: nothing to adopt.'), $box['label']) :
				    sprintf(gettext('Adopted %1$s from %2$s into the template. Check the other firewalls below before applying there.'), implode(', ', $changed), $box['label']);
			} elseif (isset($_POST['template_ignore'])) {
				fleet_template_ignore($t, $box['node_id'], (string)($_POST['reason'] ?? ''), $who);
				$savemsg = sprintf(gettext('%s keeps its own values: applying the template to all firewalls leaves it out.'), $box['label']);
			} else {
				fleet_template_unignore($t, $box['node_id'], $who);
				$savemsg = sprintf(gettext('%s follows the template again. Apply to bring it in line.'), $box['label']);
			}
		} elseif (isset($_POST['template_apply'])) {
			$t = fleet_template_get((int)$_POST['template_apply']);
			if ($t === null) {
				throw new RuntimeException(gettext('That template no longer exists.'));
			}
			$only = isset($_POST['node']) ? array((string)$_POST['node']) : null;
			$op = fleet_template_launch($t, $who, $only);
			header('Location: /fleet/fleet_activity.php?op=' . (int)$op);
			exit;
		}
	} catch (InvalidArgumentException | RuntimeException $e) {
		$input_errors[] = $e->getMessage();
	}
}
if ($ready && $manage && ($view === 'list')) {
	fs_page_action(gettext('Add template'), '/fleet/fleet_templates.php?view=edit', 'fa-plus', 'primary');
}

include('head.inc');
if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if (isset($_GET['saved'])) {
	$savemsg = gettext('Template saved. Nothing has changed on the firewalls yet: check the preview, then apply.');
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
		array(gettext('Policies'), false, '/fleet/fleet_policies.php'),
		array(gettext('Templates'), true, '/fleet/fleet_templates.php'),
		array(gettext('Users'), false, '/fleet/fleet_users.php'),
		array(gettext('Firewalls'), false, '/fleet/fleet.php'),
		array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
	);
	display_top_tabs($tab_array);
}
if (!$ready): ?>
<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller')?></strong></div>
<?php include('foot.inc'); exit; endif;

$names = fleet_target_names();
$labels = fleet_db()->query('SELECT node_id, label FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll(PDO::FETCH_KEY_PAIR);
$groups = fleet_groups_all();
$type_icons = array('host' => 'fa-server', 'network' => 'fa-network-wired', 'port' => 'fa-plug');
$action_badge = function (string $a, int $n = 0) {
	$t = array('create' => array('pass', gettext('Create')), 'update' => array('info', gettext('Change')), 'delete' => array('warn', gettext('Remove')),
	    'same' => array('neutral', gettext('Same')), 'conflict' => array('block', gettext('Conflict')))[$a];
	return fs_badge($t[0], ($n > 0) ? $t[1] . ' ' . $n : $t[1]);
};
/* What a template sets, in one line: alias names, or the settings without secrets. */
$sets_text = function (array $t): string {
	if ($t['kind'] === 'aliases') {
		return implode(', ', array_column($t['items'], 'name'));
	}
	if (isset(FLEET_TLIST_KINDS[$t['kind']])) {
		return implode(', ', array_column($t['items'], 'key'));
	}
	return fleet_tset_summary($t['kind'], $t['settings'] + array('rocommunity' => ''));
};
$kind_label = function (array $t): string {
	return ($t['kind'] === 'aliases') ? gettext('Aliases') : gettext((FLEET_TSET_KINDS[$t['kind']] ?? FLEET_TLIST_KINDS[$t['kind']])[0]);
};
$kind_icon = function (array $t): string {
	return ($t['kind'] === 'aliases') ? 'fa-list-ul' : (FLEET_TSET_KINDS[$t['kind']] ?? FLEET_TLIST_KINDS[$t['kind']])[1];
};
$is_list = function (array $t): bool {
	return ($t['kind'] === 'aliases') || isset(FLEET_TLIST_KINDS[$t['kind']]);
};
?>

<?php if ($view === 'list'):
	$all = fleet_templates_all();
	$q = trim((string)($_GET['q'] ?? ''));
	$shown = array_values(array_filter($all, function ($t) use ($q, $names) {
		return ($q === '') || (stripos($t['name'] . ' ' . $t['description'] . ' ' . fleet_targets_text($t['targets'], $names) . ' ' . implode(' ', array_column($t['items'], 'name')) . ' ' .
		    implode(' ', array_column($t['items'], 'key')) . ' ' . (($t['kind'] === 'aliases') ? 'aliases' : (FLEET_TSET_KINDS[$t['kind']] ?? FLEET_TLIST_KINDS[$t['kind']])[0]), $q) !== false);
	}));
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Templates')?> <span class="fs-count"><?=count($all)?></span></h2></div>
<?php if (empty($all)): ?>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=gettext('A template pushes the same configuration to many firewalls: aliases (lists of servers, networks or ports), or settings such as time and NTP, DNS servers, SNMP and remote logging. Fleet shows what would change on each firewall before anything is applied, and only ever changes aliases it pushed itself.')?></p>
<?php if ($manage): ?>
		<a class="btn btn-primary btn-sm" href="?view=edit"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add the first template')?></a>
<?php endif; ?>
	</div>
<?php else: ?>
	<div class="panel-body fs-fleet-pad">
		<form method="get" class="fs-fleet-filterbar" role="search">
			<input class="form-control form-control-sm" type="search" name="q" value="<?=htmlspecialchars($q)?>" placeholder="<?=gettext('Search name, alias, group or firewall')?>" aria-label="<?=gettext('Search templates')?>"/>
			<button class="btn btn-sm btn-outline-secondary" type="submit"><?=gettext('Search')?></button>
<?php if ($q !== ''): ?>
			<a class="btn btn-sm btn-link" href="?"><?=gettext('Clear')?></a>
			<span class="fs-muted small ms-auto"><?=sprintf(gettext('%1$d of %2$d'), count($shown), count($all))?></span>
<?php endif; ?>
		</form>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Name')?></th><th><?=gettext('For')?></th><th><?=gettext('Sets')?></th><th><?=gettext('Firewalls')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($shown)): ?>
		<tr><td colspan="5" class="fs-muted"><?=gettext('No template matches.')?> <a href="?"><?=gettext('Clear the search')?></a></td></tr>
<?php endif; ?>
<?php foreach ($shown as $t):
	$nodes = fleet_template_nodes($t['targets']);
	$sync = 0;
	$pending = 0;
	$unknown = 0;
	$ign = fleet_template_ignores((int)$t['id']);
	foreach ($nodes as $node) {
		if (isset($ign[$node])) {
			continue;
		}
		$plan = fleet_template_plan_from_backup($t, $node);
		if ($plan === null) {
			$unknown++;
			continue;
		}
		$c = fleet_template_plan_counts($plan);
		$st = fleet_template_states((int)$t['id'])[$node] ?? null;
		/* A changed secret cannot be seen in a backup: a template changed since it was applied counts as "to apply". */
		$secret_due = ($t['kind'] === 'snmp') && !empty($t['settings']['enable']) && (($st === null) || ($st['hash'] !== fleet_template_hash($t)));
		(($c['create'] + $c['update'] + $c['delete'] === 0) && !$secret_due) ? $sync++ : $pending++;
	}
?>
		<tr><td><a href="?view=preview&amp;id=<?=(int)$t['id']?>"><?=htmlspecialchars($t['name'])?></a>
				<?=($t['description'] !== '') ? '<div class="fs-muted small">' . htmlspecialchars($t['description']) . '</div>' : ''?></td>
			<td><?=htmlspecialchars(fleet_targets_text($t['targets'], $names))?></td>
			<td class="small"><i class="fa-solid <?=$kind_icon($t)?> fs-muted" aria-hidden="true"></i> <strong><?=htmlspecialchars($kind_label($t))?></strong>
				<div class="fs-muted"><?=htmlspecialchars($sets_text($t))?></div></td>
			<td><?=fs_badge('pass', sprintf(gettext('%1$d of %2$d in sync'), $sync, count($nodes)))?>
				<?=($pending > 0) ? fs_badge('info', sprintf(ngettext('%d to apply', '%d to apply', $pending), $pending)) : ''?>
				<?=($unknown > 0) ? fs_badge('neutral', sprintf(gettext('%d not known'), $unknown)) : ''?>
				<?=!empty($ign) ? fs_badge('neutral', sprintf(ngettext('%d ignored', '%d ignored', count($ign)), count($ign))) : ''?></td>
			<td class="text-end text-nowrap">
				<a class="btn btn-sm btn-link" href="?view=preview&amp;id=<?=(int)$t['id']?>"><?=gettext('Preview')?></a>
<?php if ($manage): ?>
				<a class="btn btn-sm btn-link" href="?view=edit&amp;id=<?=(int)$t['id']?>"><?=gettext('Change')?></a>
				<form method="post" class="d-inline"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="template_delete" value="<?=(int)$t['id']?>"><?=gettext('Delete')?></button></form>
<?php endif; ?>
			</td></tr>
<?php endforeach; ?>
		</tbody></table></div>
	<div class="panel-footer small fs-muted"><?=gettext('"In sync" is worked out from each firewall\'s newest configuration backup, so a local change shows here after the next backup.')?></div>
<?php endif; ?>
</div>
<?php if ($manage): ?>
<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-shield-halved" aria-hidden="true"></i></span>
		<div><h2><?=gettext('Rules and port forwards for many firewalls')?></h2><p><?=gettext('Applied under commit-confirm: if a change cuts Fleet off from a firewall, the firewall puts its previous rules back by itself.')?></p></div></header>
	<div class="fs-fleet-rule-grid">
<?php foreach (FLEET_TLIST_KINDS as $k => $def): ?>
		<a class="fs-fleet-rcard fs-fleet-starter" href="?view=edit&amp;kind=<?=$k?>">
			<div class="fs-fleet-rcard-head">
				<span class="fs-fleet-rcard-icon"><i class="fa-solid <?=$def[1]?>" aria-hidden="true"></i></span>
				<div class="fs-fleet-rcard-title"><strong><?=htmlspecialchars(gettext($def[0]))?></strong>
					<span class="fs-muted small"><?=htmlspecialchars(gettext($def[2]))?></span></div>
				<i class="fa-solid fa-chevron-right fs-muted" aria-hidden="true"></i>
			</div>
			<p class="fs-fleet-rcard-help"><?=htmlspecialchars(sprintf(gettext('Needs FreeSense with API level %d or later on the firewall; older firewalls are skipped with FLEET-E401.'), $def[4]))?></p>
		</a>
<?php endforeach; ?>
	</div>
</section>
<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-sliders" aria-hidden="true"></i></span>
		<div><h2><?=gettext('Settings for many firewalls')?></h2><p><?=gettext('One set of settings, the same on every firewall it is for. A firewall can have one template of each kind.')?></p></div></header>
	<div class="fs-fleet-rule-grid">
<?php foreach (FLEET_TSET_KINDS as $k => $def): ?>
		<a class="fs-fleet-rcard fs-fleet-starter" href="?view=edit&amp;kind=<?=$k?>">
			<div class="fs-fleet-rcard-head">
				<span class="fs-fleet-rcard-icon"><i class="fa-solid <?=$def[1]?>" aria-hidden="true"></i></span>
				<div class="fs-fleet-rcard-title"><strong><?=htmlspecialchars(gettext($def[0]))?></strong>
					<span class="fs-muted small"><?=htmlspecialchars(gettext($def[2]))?></span></div>
				<i class="fa-solid fa-chevron-right fs-muted" aria-hidden="true"></i>
			</div>
<?php if ($def[4] > 0): ?>
			<p class="fs-fleet-rcard-help"><?=htmlspecialchars(sprintf(gettext('Needs FreeSense with API level %d or later on the firewall; older firewalls are skipped with FLEET-E401.'), $def[4]))?></p>
<?php endif; ?>
		</a>
<?php endforeach; ?>
	</div>
</section>
<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-wand-magic-sparkles" aria-hidden="true"></i></span>
		<div><h2><?=gettext('Start from ready-made aliases')?></h2><p><?=gettext('Pick one to open it in the editor. Change what you like, choose the firewalls, then save. Nothing is pushed until you apply it.')?></p></div></header>
	<div class="fs-fleet-rule-grid">
<?php foreach (fleet_template_starters() as $key => $s): $n = array_sum(array_map(function ($a) { return count(array_filter(explode("\n", $a['entries']))); }, $s['aliases'])); ?>
		<a class="fs-fleet-rcard fs-fleet-starter" href="?view=edit&amp;starter=<?=urlencode($key)?>">
			<div class="fs-fleet-rcard-head">
				<span class="fs-fleet-rcard-icon"><i class="fa-solid <?=$s['icon']?>" aria-hidden="true"></i></span>
				<div class="fs-fleet-rcard-title"><strong><?=htmlspecialchars(gettext($s['name']))?></strong>
					<span class="fs-muted small"><?=htmlspecialchars(sprintf(ngettext('%1$d alias, %2$d entries', '%1$d aliases, %2$d entries', count($s['aliases'])), count($s['aliases']), $n))?></span></div>
				<i class="fa-solid fa-chevron-right fs-muted" aria-hidden="true"></i>
			</div>
			<p class="fs-fleet-rcard-help"><?=htmlspecialchars(gettext($s['description']))?></p>
			<div class="fs-fleet-starter-names"><?=htmlspecialchars(implode(' · ', array_column($s['aliases'], 'name')))?></div>
		</a>
<?php endforeach; ?>
	</div>
</section>
<?php endif; ?>

<?php elseif ($view === 'preview'):
	$t = fleet_template_get((int)($_GET['id'] ?? 0));
	if ($t === null): ?>
<div class="fs-fleet-empty"><strong><?=gettext('That template no longer exists.')?></strong> <a href="?"><?=gettext('All templates')?></a></div>
<?php else:
	$nodes = fleet_template_nodes($t['targets']);
	$states = fleet_template_states((int)$t['id']);
	$ignored = fleet_template_ignores((int)$t['id']);
	$live = isset($_GET['live']) && $manage;
	$rows = array();
	$tot = array('create' => 0, 'update' => 0, 'delete' => 0, 'same' => 0, 'conflict' => 0);
	$todo_boxes = 0;
	foreach ($nodes as $node) {
		$box = fleet_box_get($node);
		$plan = null;
		$err = null;
		if ($live && ($box !== null) && ($box['state'] === 'online')) {
			try {
				$plan = fleet_template_live_plan($t, $box);
			} catch (RuntimeException $e) {
				$err = $e->getMessage();
			}
		} else {
			$plan = fleet_template_plan_from_backup($t, $node);
		}
		$c = ($plan === null) ? null : fleet_template_plan_counts($plan);
		if (($c !== null) && !isset($ignored[$node])) {
			foreach ($c as $k => $v) {
				$tot[$k] += $v;
			}
			$todo_boxes += ($c['create'] + $c['update'] + $c['delete'] > 0) ? 1 : 0;
		}
		$rows[] = array($node, $box, $plan, $c, $err);
	}
?>
<p><a class="fs-fleet-back" href="?"><i class="fa-solid fa-arrow-left" aria-hidden="true"></i> <?=gettext('All templates')?></a></p>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=htmlspecialchars($t['name'])?></h2>
<?php if ($manage): ?>
		<a class="btn btn-sm btn-link" href="?view=edit&amp;id=<?=(int)$t['id']?>"><?=gettext('Change')?></a>
<?php endif; ?>
	</div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=htmlspecialchars(sprintf(ngettext('For %1$s: %2$d firewall.', 'For %1$s: %2$d firewalls.', count($nodes)), fleet_targets_text($t['targets'], $names), count($nodes)))?>
			<?=($t['description'] !== '') ? htmlspecialchars($t['description']) : ''?></p>
<?php if (isset(FLEET_TLIST_KINDS[$t['kind']])): ?>
		<div class="table-responsive"><table class="table fs-table fs-fleet-tlist-view">
			<thead><tr><th><?=gettext('Name')?></th><?php if ($t['kind'] === 'rules'): ?><th><?=gettext('Action')?></th><th><?=gettext('On')?></th><th><?=gettext('Protocol')?></th><th><?=gettext('From')?></th><th><?=gettext('To')?></th><th><?=gettext('Port')?></th>
<?php else: ?><th><?=gettext('On')?></th><th><?=gettext('Protocol')?></th><th><?=gettext('Port')?></th><th><?=gettext('Forward to')?></th><?php endif; ?><th><?=gettext('Description')?></th></tr></thead>
			<tbody>
<?php foreach ($t['items'] as $it): ?>
			<tr><td class="fs-mono"><?=htmlspecialchars($it['key'])?></td>
<?php if ($t['kind'] === 'rules'): ?>
				<td><?=fs_badge(($it['action'] === 'pass') ? 'pass' : 'block', gettext(FLEET_TRULE_ACTIONS[$it['action']]))?><?=$it['log'] ? ' <span class="fs-muted small">' . gettext('logged') . '</span>' : ''?></td>
				<td class="fs-mono"><?=htmlspecialchars($it['iface'])?></td><td><?=htmlspecialchars(gettext(FLEET_TRULE_PROTOS[$it['proto']]))?></td>
				<td class="fs-mono"><?=htmlspecialchars($it['src'])?></td><td class="fs-mono"><?=htmlspecialchars($it['dst'])?></td><td class="fs-mono"><?=htmlspecialchars($it['port'] ?: '*')?></td>
<?php else: ?>
				<td class="fs-mono"><?=htmlspecialchars($it['iface'])?></td><td><?=htmlspecialchars(gettext(FLEET_TRULE_PROTOS[$it['proto']]))?></td>
				<td class="fs-mono"><?=htmlspecialchars($it['port'])?></td><td class="fs-mono"><?=htmlspecialchars($it['target'] . ':' . $it['local'])?></td>
<?php endif; ?>
				<td class="small"><?=htmlspecialchars($it['descr'])?></td></tr>
<?php endforeach; ?>
			</tbody></table></div>
<?php elseif ($t['kind'] !== 'aliases'): $lab = fleet_tset_labels($t['kind']); ?>
		<dl class="fs-fleet-tset">
<?php foreach ($t['settings'] as $k => $v): ?>
			<dt><?=htmlspecialchars(gettext($lab[$k] ?? $k))?></dt><dd><?=htmlspecialchars(($k === 'rocommunity') ? (($v !== '') ? gettext('set (not shown)') : gettext('(none)')) : fleet_tset_text($v))?></dd>
<?php endforeach; ?>
		</dl>
<?php endif; ?>
		<div class="fs-fleet-tpl-items">
<?php foreach (($t['kind'] === 'aliases') ? $t['items'] : array() as $item): ?>
			<div class="fs-fleet-tpl-chip"><i class="fa-solid <?=$type_icons[$item['type']]?>" aria-hidden="true"></i> <strong><?=htmlspecialchars($item['name'])?></strong>
				<span class="fs-muted small"><?=sprintf(ngettext('%d entry', '%d entries', count($item['entries'])), count($item['entries']))?></span></div>
<?php endforeach; ?>
		</div>
	</div>
</div>
<div class="fs-tiles fs-fleet-tiles-row">
	<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Firewalls with changes')?></span><span class="fs-tile-value"><?=$todo_boxes?></span></div>
<?php if ($is_list($t)): ?>
	<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Create / change / remove')?></span><span class="fs-tile-value"><?=$tot['create']?> / <?=$tot['update']?> / <?=$tot['delete']?></span></div>
<?php if ($t['kind'] === 'aliases'): ?>
	<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Conflicts (skipped)')?></span><span class="fs-tile-value"><?=$tot['conflict']?></span></div>
<?php endif; ?>
<?php else: ?>
	<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Settings to change')?></span><span class="fs-tile-value"><?=$tot['update']?></span></div>
	<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Firewalls in sync')?></span><span class="fs-tile-value"><?=count(array_filter($rows, function ($r) use ($ignored) { return ($r[3] !== null) && ($r[3]['update'] === 0) && !isset($ignored[$r[0]]); }))?></span></div>
<?php endif; ?>
</div>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('What applying changes')?></h2>
		<span class="small fs-muted"><?=$live ? gettext('Read from the firewalls just now.') : gettext('From each firewall\'s newest backup.')?>
<?php if ($manage && !$live): ?>
			<a class="btn btn-sm btn-link" href="?view=preview&amp;id=<?=(int)$t['id']?>&amp;live=1"><?=gettext('Read the firewalls now')?></a>
<?php endif; ?></span></div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Firewall')?></th><th><?=gettext('Changes')?></th><th><?=gettext('Last applied')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($rows)): ?>
		<tr><td colspan="4" class="fs-muted"><?=gettext('The template is for no firewall. Change who it is for.')?></td></tr>
<?php endif; ?>
<?php foreach ($rows as list($node, $box, $plan, $c, $err)): $st = $states[$node] ?? null; ?>
		<tr><td><a href="/fleet/fleet_box.php?id=<?=urlencode($node)?>"><?=htmlspecialchars($labels[$node] ?? $node)?></a>
				<?=(($box !== null) && ($box['state'] !== 'online')) ? fs_badge('neutral', ucfirst($box['state'])) : ''?></td>
			<td>
<?php if (isset($ignored[$node])): $ig = $ignored[$node]; ?>
				<?=fs_badge('neutral', gettext('Ignored'))?> <span class="small"><?=htmlspecialchars($ig['reason'])?></span>
				<div class="fs-muted small"><?=htmlspecialchars(sprintf(gettext('By %1$s on %2$s. It keeps its own values; applying to all leaves it out.'), $ig['who'], date('Y-m-d', (int)$ig['time'])))?></div>
<?php elseif ($err !== null): ?>
				<span class="fs-fleet-problem small"><?=htmlspecialchars($err)?></span>
<?php elseif ($plan === null): ?>
				<span class="fs-muted small"><?=gettext('Not known: no configuration backup yet')?></span>
<?php elseif ($c['create'] + $c['update'] + $c['delete'] + $c['conflict'] === 0): ?>
				<?=fs_badge('pass', gettext('In sync'))?>
<?php else: ?>
				<details class="fs-fleet-tpl-diff"><summary><?php foreach (array('create', 'update', 'delete', 'conflict') as $a) { echo ($c[$a] > 0) ? $action_badge($a, $c[$a]) . ' ' : ''; } ?></summary>
					<ul>
<?php foreach ($plan as $p): if ($p['action'] === 'same') { continue; } ?>
						<li><?=$action_badge($p['action'])?> <strong><?=htmlspecialchars($p['name'])?></strong> <span class="fs-muted small"><?=htmlspecialchars($p['detail'])?></span></li>
<?php endforeach; ?>
					</ul></details>
<?php endif; ?>
			</td>
			<td class="small"><?=($st === null) ? '<span class="fs-muted">' . gettext('Never') . '</span>' :
			    htmlspecialchars(date('Y-m-d H:i', (int)$st['applied'])) . ' ' . (($st['result'] === 'done') ? '' : fs_badge('block', gettext('Failed'))) . '<div class="fs-muted">' . htmlspecialchars($st['detail']) . '</div>'?></td>
			<td class="text-end text-nowrap"><?php
	$online = ($box !== null) && ($box['state'] === 'online') && fleet_manage_allowed($box);
	$drift = ($c !== null) && ($c['create'] + $c['update'] + $c['delete'] > 0) && ($st !== null);
	if ($manage && isset($ignored[$node])): ?>
				<form method="post" class="d-inline"><input type="hidden" name="node" value="<?=htmlspecialchars($node)?>"/><button class="btn btn-sm btn-link" name="template_unignore" value="<?=(int)$t['id']?>"><?=gettext('Stop ignoring')?></button></form>
<?php elseif ($manage): ?>
<?php if ($online): ?>
				<form method="post" class="d-inline"><input type="hidden" name="node" value="<?=htmlspecialchars($node)?>"/><button class="btn btn-sm btn-link" name="template_apply" value="<?=(int)$t['id']?>"
				    title="<?=$drift ? gettext('Put the template\'s values back on this firewall') : ''?>"><?=$drift ? gettext('Revert') : gettext('Apply here')?></button></form>
<?php if ($drift): ?>
				<form method="post" class="d-inline"><input type="hidden" name="node" value="<?=htmlspecialchars($node)?>"/><button class="btn btn-sm btn-link" name="template_adopt" value="<?=(int)$t['id']?>"
				    title="<?=gettext('Take this firewall\'s values into the template')?>"><?=gettext('Adopt')?></button></form>
<?php endif; ?>
<?php endif; ?>
				<details class="fs-fleet-inline-form d-inline-block"><summary class="btn btn-sm btn-link"><?=gettext('Ignore')?></summary>
					<form method="post"><input type="hidden" name="node" value="<?=htmlspecialchars($node)?>"/>
						<label class="visually-hidden" for="ig-<?=htmlspecialchars($node)?>"><?=gettext('Why it keeps its own values')?></label>
						<input class="form-control form-control-sm" id="ig-<?=htmlspecialchars($node)?>" name="reason" maxlength="200" required placeholder="<?=gettext('Why it keeps its own values')?>"/>
						<button class="btn btn-sm btn-outline-secondary" name="template_ignore" value="<?=(int)$t['id']?>"><?=gettext('Ignore')?></button></form></details>
<?php endif; ?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php if ($manage && !empty($rows)): ?>
	<div class="panel-footer fs-fleet-review-actions fs-fleet-policy-actions">
<?php $n_apply = count($rows) - count(array_intersect_key($ignored, array_flip($nodes))); ?>
		<form method="post"><button class="btn btn-primary" name="template_apply" value="<?=(int)$t['id']?>"<?=($n_apply === 0) ? ' disabled' : ''?>><i class="fa-solid fa-paper-plane icon-embed-btn" aria-hidden="true"></i><?=sprintf(ngettext('Apply to %d firewall', 'Apply to %d firewalls', $n_apply), $n_apply)?></button></form>
		<p class="fs-fleet-policy-note"><?=isset(FLEET_TLIST_KINDS[$t['kind']]) ? gettext('Each firewall gets a safety backup and a commit-confirm window first, then the changes and one filter reload. Fleet then checks it still reaches the firewall and only then confirms; if it cannot, the firewall puts its previous rules back by itself within 5 minutes (FLEET-E310). Fleet never changes an entry it did not push, and a template\'s rules come first on their interface.') : (($t['kind'] === 'aliases') ? gettext('Each firewall gets a safety backup first, then the changes and one filter reload. Conflicts are skipped: Fleet never changes an alias it did not push. The firewalls are read again when the apply starts, so a change made since the backup is not lost.') :
		    gettext('Each firewall gets a safety backup first, then the template\'s settings in one change, applied at once. The firewalls are read again when the apply starts; one that already matches is left alone.'))?></p>
	</div>
<?php endif; ?>
</div>
<?php endif; ?>

<?php else: /* edit */
	$t = isset($_GET['id']) ? fleet_template_get((int)$_GET['id']) : null;
	if ($typed !== null) {
		$t = array('id' => (int)($typed['template_id'] ?? 0), 'name' => (string)($typed['name'] ?? ''), 'description' => (string)($typed['description'] ?? ''),
		    'targets' => (array)($typed['targets'] ?? array()), 'items' => array(), 'raw' => array_values((array)($typed['alias'] ?? array())));
	}
	$starter = fleet_template_starters()[(string)($_GET['starter'] ?? '')] ?? null;
	if (($t === null) && ($starter !== null)) {
		$t = array('id' => 0, 'name' => $starter['name'], 'description' => $starter['description'], 'targets' => array('all'), 'items' => array(), 'raw' => $starter['aliases']);
	}
	$t = $t ?? array('id' => 0, 'name' => '', 'description' => '', 'targets' => array('all'), 'items' => array());
	$edit_kind = (string)($t['kind'] ?? (($typed !== null) ? ($typed['kind'] ?? 'aliases') : ($_GET['kind'] ?? 'aliases')));
	if (($edit_kind !== 'aliases') && !isset(FLEET_TSET_KINDS[$edit_kind]) && !isset(FLEET_TLIST_KINDS[$edit_kind])) {
		$edit_kind = 'aliases';
	}
	/* The rows of a rule or port forward template: what was typed, the template's, or one to start from. */
	$trows = ($typed !== null) ? array_values((array)($typed['row'] ?? array())) : $t['items'];
	if (empty($trows)) {
		/* Empty fields with hints only: values typed into a filled example would be appended to it. */
		$trows[] = ($edit_kind === 'nat') ? array('proto' => 'tcp') : array('action' => 'pass', 'proto' => 'tcp/udp');
	}
	$trow = function (int $n, array $r) use ($edit_kind) {
		$v = function ($k) use ($r) {
			return htmlspecialchars((string)($r[$k] ?? ''));
		};
		$sel = function (string $name, array $opts, string $cur) use ($n) {
			$h = '<select class="form-select form-select-sm" name="row[' . $n . '][' . $name . ']" aria-label="' . htmlspecialchars(ucfirst($name)) . '">';
			foreach ($opts as $k => $label) {
				$h .= '<option value="' . htmlspecialchars($k) . '"' . (($k === $cur) ? ' selected' : '') . '>' . htmlspecialchars(gettext($label)) . '</option>';
			}
			return $h . '</select>';
		};
		$in = function (string $name, string $ph, int $max = 64) use ($n, $v) {
			return '<input class="form-control form-control-sm fs-mono" name="row[' . $n . '][' . $name . ']" value="' . $v($name) . '" maxlength="' . $max . '" placeholder="' . htmlspecialchars($ph) . '" aria-label="' . htmlspecialchars(ucfirst($name)) . '"/>';
		};
		$h = '<tr data-tl-row><td>' . $in('key', 'allow-dns', 24) . '</td>';
		if ($edit_kind === 'rules') {
			$h .= '<td>' . $sel('action', FLEET_TRULE_ACTIONS, (string)($r['action'] ?? 'pass')) . '</td><td>' . $in('iface', 'lan', 10) . '</td><td>' .
			    $sel('proto', FLEET_TRULE_PROTOS, (string)($r['proto'] ?? 'any')) . '</td><td>' . $in('src', 'any') . '</td><td>' . $in('dst', 'any') . '</td><td>' . $in('port', '443', 31) .
			    '</td><td class="text-center"><input class="form-check-input" type="checkbox" name="row[' . $n . '][log]" value="1"' . (!empty($r['log']) ? ' checked' : '') . ' aria-label="' . gettext('Log') . '"/></td>';
		} else {
			$h .= '<td>' . $in('iface', 'wan', 10) . '</td><td>' . $sel('proto', array('tcp' => 'TCP', 'udp' => 'UDP', 'tcp/udp' => 'TCP and UDP'), (string)($r['proto'] ?? 'tcp')) . '</td><td>' .
			    $in('port', '443', 31) . '</td><td>' . $in('target', '10.0.0.10') . '</td><td>' . $in('local', '443', 31) . '</td>';
		}
		return $h . '<td>' . str_replace('fs-mono', '', $in('descr', '', 120)) . '</td><td><button type="button" class="btn btn-sm btn-link fs-fleet-danger-link" data-tl-remove aria-label="' .
		    gettext('Remove this row') . '"><i class="fa-solid fa-trash" aria-hidden="true"></i></button></td></tr>';
	};
	/* The settings form's values: what was typed, the template's, or sensible starting values. */
	$sv = ($typed !== null) ? $typed : array();
	if (($typed === null) && !empty($t['settings'])) {
		foreach ($t['settings'] as $k => $v) {
			$sv['set_' . $k] = is_array($v) ? implode("\n", $v) : $v;
		}
		if (isset($t['settings']['contents'])) {
			$sv['set_contents'] = ($t['settings']['contents'] === 'all') ? 'all' : 'some';
			$sv['set_contents_list'] = ($t['settings']['contents'] === 'all') ? array() : $t['settings']['contents'];
		}
		$sv['set_rocommunity'] = '';
	}
	if (($typed === null) && empty($t['settings'])) {
		$sv += array('set_timezone' => fleet_tz(), 'set_timeservers' => "0.pool.ntp.org\n1.pool.ntp.org\n2.pool.ntp.org", 'set_enable' => true, 'set_contents' => 'all');
	}
	$svv = function (string $k) use ($sv) {
		return htmlspecialchars((string)($sv['set_' . $k] ?? ''));
	};
	$svc = function (string $k) use ($sv) {
		return !empty($sv['set_' . $k]) ? ' checked' : '';
	};
	$cards = $t['raw'] ?? array_map(function ($i) {
		return array('name' => $i['name'], 'type' => $i['type'], 'description' => $i['description'], 'entries' => fleet_template_entries_text($i['entries']));
	}, $t['items']);
	if (empty($cards)) {
		$cards[] = array('name' => '', 'type' => 'host', 'description' => '', 'entries' => '');
	}
	$card = function (int $n, array $a) use ($type_icons) {
		ob_start(); ?>
			<article class="fs-fleet-rcard is-on fs-fleet-tpl-card" data-tpl-card>
				<div class="fs-fleet-rcard-head">
					<span class="fs-fleet-rcard-icon"><i class="fa-solid <?=$type_icons[$a['type'] ?? 'host'] ?? 'fa-server'?>" aria-hidden="true" data-tpl-icon></i></span>
					<div class="fs-fleet-rcard-title"><span><?=gettext('Alias')?></span><span class="fs-muted small" data-tpl-count></span></div>
					<button type="button" class="btn btn-sm btn-link fs-fleet-danger-link" data-tpl-remove aria-label="<?=gettext('Remove this alias')?>"><i class="fa-solid fa-trash" aria-hidden="true"></i></button>
				</div>
				<div class="fs-fleet-tpl-fields">
					<div><label class="form-label small" for="a<?=$n?>-name"><?=gettext('Name')?></label>
						<input class="form-control form-control-sm fs-mono" id="a<?=$n?>-name" name="alias[<?=$n?>][name]" maxlength="31" value="<?=htmlspecialchars((string)$a['name'])?>" placeholder="office_nets"/></div>
					<div><label class="form-label small" for="a<?=$n?>-type"><?=gettext('Holds')?></label>
						<select class="form-select form-select-sm" id="a<?=$n?>-type" name="alias[<?=$n?>][type]" data-tpl-type>
<?php foreach (FLEET_TEMPLATE_ALIAS_TYPES as $k => $label): ?>
							<option value="<?=$k?>"<?=(($a['type'] ?? 'host') === $k) ? ' selected' : ''?>><?=htmlspecialchars(gettext($label))?></option>
<?php endforeach; ?>
						</select></div>
					<div class="fs-fleet-tpl-wide"><label class="form-label small" for="a<?=$n?>-desc"><?=gettext('Description')?></label>
						<input class="form-control form-control-sm" id="a<?=$n?>-desc" name="alias[<?=$n?>][description]" maxlength="200" value="<?=htmlspecialchars((string)$a['description'])?>"/></div>
					<div class="fs-fleet-tpl-wide"><label class="form-label small" for="a<?=$n?>-entries"><?=gettext('Entries, one per line')?></label>
						<textarea class="form-control form-control-sm fs-mono" id="a<?=$n?>-entries" name="alias[<?=$n?>][entries]" rows="4" data-tpl-entries
						    placeholder="10.0.0.0/24  # Office&#10;192.168.10.0/24  # Lab"><?=htmlspecialchars((string)$a['entries'])?></textarea>
						<div class="form-text"><?=gettext('Add a note after #. Hosts: addresses or names. Networks: CIDR. Ports: 443 or 8000:8080.')?></div></div>
				</div>
			</article>
<?php		return ob_get_clean();
	};
?>
<p><a class="fs-fleet-back" href="?"><i class="fa-solid fa-arrow-left" aria-hidden="true"></i> <?=gettext('All templates')?></a></p>
<form method="post" action="?view=edit<?=$t['id'] ? '&amp;id=' . (int)$t['id'] : ''?>">
	<input type="hidden" name="template_id" value="<?=(int)$t['id']?>"/>
	<input type="hidden" name="kind" value="<?=htmlspecialchars($edit_kind)?>"/>
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=$t['id'] ? sprintf(htmlspecialchars(gettext('Change %s')), htmlspecialchars($t['name'])) :
		    htmlspecialchars(sprintf(gettext('Add a template: %s'), ($edit_kind === 'aliases') ? gettext('Aliases') : gettext((FLEET_TSET_KINDS[$edit_kind] ?? FLEET_TLIST_KINDS[$edit_kind])[0])))?></h2></div>
		<div class="panel-body fs-fleet-pad">
			<div class="row g-3">
				<div class="col-md-4"><label class="form-label" for="tname"><?=gettext('Name')?></label>
					<input class="form-control" id="tname" name="name" maxlength="60" required value="<?=htmlspecialchars($t['name'])?>" placeholder="<?=htmlspecialchars(gettext(array('aliases' => 'Company networks', 'rules' => 'Branch baseline rules', 'nat' => 'Web server forwards', 'time' => 'Company time',
					    'dns' => 'Company DNS', 'snmp' => 'Monitoring', 'syslog' => 'Central logging')[$edit_kind] ?? 'Company networks'))?>"/></div>
				<div class="col-md-8"><label class="form-label" for="tdesc"><?=gettext('Description')?></label>
					<input class="form-control" id="tdesc" name="description" maxlength="300" value="<?=htmlspecialchars($t['description'])?>"/></div>
				<div class="col-12"><label class="form-label" for="ttargets"><?=gettext('For')?></label>
					<select class="form-select" id="ttargets" name="targets[]" multiple size="8" data-fs-multiselect data-fs-exclusive="all"
					    data-fs-text-search="<?=gettext('Search groups and firewalls…')?>" data-fs-text-none="<?=gettext('Choose firewalls…')?>" data-fs-text-more="<?=gettext('+%d more')?>">
						<option value="all"<?=in_array('all', $t['targets'], true) ? ' selected' : ''?>><?=gettext('All firewalls')?></option>
<?php if (!empty($groups)): ?>
						<optgroup label="<?=gettext('Groups')?>">
<?php foreach ($groups as $grp): ?>
							<option value="g:<?=(int)$grp['id']?>"<?=in_array('g:' . $grp['id'], $t['targets'], true) ? ' selected' : ''?>><?=htmlspecialchars($grp['name'])?></option>
<?php endforeach; ?>
						</optgroup>
<?php endif; ?>
						<optgroup label="<?=gettext('Firewalls')?>">
<?php foreach ($labels as $node => $label): ?>
							<option value="n:<?=htmlspecialchars($node)?>"<?=in_array('n:' . $node, $t['targets'], true) ? ' selected' : ''?>><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
						</optgroup>
					</select></div>
			</div>
		</div>
	</div>
<?php if (isset(FLEET_TLIST_KINDS[$edit_kind])): $def = FLEET_TLIST_KINDS[$edit_kind]; ?>
	<section class="fs-fleet-area">
		<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid <?=$def[1]?>" aria-hidden="true"></i></span>
			<div><h2><?=htmlspecialchars(gettext($def[0]))?></h2><p><?=($edit_kind === 'rules') ?
			    gettext('In this order, first on their interface. From and To: any, an interface network (lan, opt2) or address (lanip, wanip), an address, a CIDR network or an alias. Port: 443, 8000-8080 or an alias, for TCP or UDP.') :
			    gettext('Traffic to the interface\'s address on Port goes to Forward to on Local port, with a firewall rule made for it. Ports: 443, 8000-8080 or an alias.')?></p></div></header>
		<div class="panel panel-default"><div class="panel-body table-responsive"><table class="table fs-table fs-fleet-tlist-edit">
			<thead><tr><th><?=gettext('Name')?></th><?php if ($edit_kind === 'rules'): ?><th><?=gettext('Action')?></th><th><?=gettext('On')?></th><th><?=gettext('Protocol')?></th><th><?=gettext('From')?></th><th><?=gettext('To')?></th><th><?=gettext('Port')?></th><th><?=gettext('Log')?></th>
<?php else: ?><th><?=gettext('On')?></th><th><?=gettext('Protocol')?></th><th><?=gettext('Port')?></th><th><?=gettext('Forward to')?></th><th><?=gettext('Local port')?></th><?php endif; ?><th><?=gettext('Description')?></th><th><span class="visually-hidden"><?=gettext('Remove')?></span></th></tr></thead>
			<tbody data-tl-list data-next="<?=count($trows)?>">
<?php foreach (array_values($trows) as $n => $r) { echo $trow($n, $r); } ?>
			</tbody></table></div>
			<div class="panel-footer"><button type="button" class="btn btn-sm btn-outline-secondary" data-tl-add><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=($edit_kind === 'rules') ? gettext('Add rule') : gettext('Add port forward')?></button></div></div>
		<template data-tl-blank><?=$trow(999999, array('key' => '', 'iface' => ($edit_kind === 'nat') ? 'wan' : 'lan', 'src' => 'any', 'dst' => 'any'))?></template>
	</section>
<?php elseif ($edit_kind !== 'aliases'): $def = FLEET_TSET_KINDS[$edit_kind]; ?>
	<section class="fs-fleet-area">
		<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid <?=$def[1]?>" aria-hidden="true"></i></span>
			<div><h2><?=htmlspecialchars(gettext($def[0]))?></h2><p><?=htmlspecialchars(gettext($def[2]))?>. <?=gettext('Every firewall the template is for gets exactly these values.')?></p></div></header>
		<div class="panel panel-default"><div class="panel-body fs-fleet-pad"><div class="row g-3">
<?php if ($edit_kind === 'time'): ?>
			<div class="col-md-5"><label class="form-label" for="s-tz"><?=gettext('Time zone')?></label>
				<input class="form-control" id="s-tz" name="set_timezone" list="s-tz-list" required value="<?=$svv('timezone')?>" placeholder="Europe/Copenhagen"/>
				<datalist id="s-tz-list"><?php foreach (timezone_identifiers_list() as $z) { echo '<option value="' . htmlspecialchars($z) . '">'; } ?></datalist></div>
			<div class="col-md-7"><label class="form-label" for="s-ntp"><?=gettext('NTP servers, one per line')?></label>
				<textarea class="form-control fs-mono" id="s-ntp" name="set_timeservers" rows="4" required><?=$svv('timeservers')?></textarea>
				<div class="form-text"><?=gettext('Up to 5. The firewall sets its clock from these and offers time to its networks if its NTP service is on.')?></div></div>
<?php elseif ($edit_kind === 'dns'): ?>
			<div class="col-md-7"><label class="form-label" for="s-dns"><?=gettext('DNS servers, one per line')?></label>
				<textarea class="form-control fs-mono" id="s-dns" name="set_dnsservers" rows="4" required placeholder="9.9.9.9&#10;149.112.112.112"><?=$svv('dnsservers')?></textarea>
				<div class="form-text"><?=gettext('Up to 8 addresses. These replace the list on each firewall (per-server gateways there are dropped).')?></div></div>
			<div class="col-md-5"><label class="form-check mt-md-4"><input class="form-check-input" type="checkbox" name="set_dnsallowoverride" value="1"<?=$svc('dnsallowoverride')?>/>
				<span class="form-check-label"><?=gettext('Let DHCP or PPP on WAN override these')?></span></label></div>
<?php elseif ($edit_kind === 'snmp'): ?>
			<div class="col-12"><label class="form-check"><input class="form-check-input" type="checkbox" name="set_enable" value="1"<?=$svc('enable')?>/>
				<span class="form-check-label"><?=gettext('SNMP on (off turns it off on every firewall the template is for)')?></span></label></div>
			<div class="col-md-4"><label class="form-label" for="s-loc"><?=gettext('Location')?></label>
				<input class="form-control" id="s-loc" name="set_syslocation" maxlength="100" value="<?=$svv('syslocation')?>" placeholder="<?=gettext('Copenhagen, rack 4')?>"/></div>
			<div class="col-md-4"><label class="form-label" for="s-con"><?=gettext('Contact')?></label>
				<input class="form-control" id="s-con" name="set_syscontact" maxlength="100" value="<?=$svv('syscontact')?>" placeholder="noc@example.com"/></div>
			<div class="col-md-4"><label class="form-label" for="s-com"><?=gettext('Read community')?></label>
				<input class="form-control" id="s-com" name="set_rocommunity" type="password" autocomplete="off" maxlength="64"
				    placeholder="<?=!empty($t['settings']['rocommunity']) ? gettext('Set; leave empty to keep it') : ''?>"/>
				<div class="form-text"><?=gettext('Stored encrypted. Not "public".')?></div></div>
<?php else: /* syslog */ ?>
			<div class="col-12"><label class="form-check"><input class="form-check-input" type="checkbox" name="set_enable" value="1"<?=$svc('enable')?>/>
				<span class="form-check-label"><?=gettext('Send logs to remote servers')?></span></label></div>
			<div class="col-md-6"><label class="form-label" for="s-srv"><?=gettext('Servers, one per line')?></label>
				<textarea class="form-control fs-mono" id="s-srv" name="set_servers" rows="3" placeholder="logs.example.net&#10;10.0.9.5:5514"><?=$svv('servers')?></textarea>
				<div class="form-text"><?=gettext('Up to 3: a host name or address, optionally :port (UDP 514 by default).')?></div></div>
			<div class="col-md-6"><label class="form-label" for="s-ipp"><?=gettext('IP version')?></label>
				<select class="form-select" id="s-ipp" name="set_ipproto"><option value="ipv4">IPv4</option><option value="ipv6"<?=(($sv['set_ipproto'] ?? '') === 'ipv6') ? ' selected' : ''?>>IPv6</option></select></div>
			<fieldset class="col-12"><legend class="form-label"><?=gettext('Logs sent')?></legend>
				<label class="form-check"><input class="form-check-input" type="radio" name="set_contents" value="all"<?=(($sv['set_contents'] ?? 'all') === 'all') ? ' checked' : ''?>/> <span class="form-check-label"><?=gettext('All logs')?></span></label>
				<label class="form-check"><input class="form-check-input" type="radio" name="set_contents" value="some"<?=(($sv['set_contents'] ?? 'all') !== 'all') ? ' checked' : ''?>/> <span class="form-check-label"><?=gettext('Only these:')?></span></label>
				<div class="fs-fleet-checkgrid mt-1">
<?php foreach (FLEET_TSET_SYSLOG_CONTENTS as $ck => $cl): ?>
					<label class="form-check"><input class="form-check-input" type="checkbox" name="set_contents_list[]" value="<?=$ck?>"<?=in_array($ck, (array)($sv['set_contents_list'] ?? array()), true) ? ' checked' : ''?>/> <span class="form-check-label"><?=htmlspecialchars(gettext($cl))?></span></label>
<?php endforeach; ?>
				</div></fieldset>
<?php endif; ?>
		</div></div></div>
	</section>
<?php else: ?>
	<section class="fs-fleet-area">
		<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-list-ul" aria-hidden="true"></i></span>
			<div><h2><?=gettext('Aliases')?></h2><p><?=gettext('Lists of hosts, networks or ports the firewalls\' rules can use by name. On the firewall each is marked as pushed by this template.')?></p></div></header>
		<div class="fs-fleet-rule-grid fs-fleet-tpl-grid" data-tpl-list data-next="<?=count($cards)?>">
<?php foreach ($cards as $n => $a) { echo $card($n, $a); } ?>
		</div>
		<button type="button" class="btn btn-sm btn-outline-secondary mt-2" data-tpl-add><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add alias')?></button>
		<template data-tpl-blank><?=$card(999999, array('name' => '', 'type' => 'host', 'description' => '', 'entries' => ''))?></template>
	</section>
<?php endif; ?>
	<div class="fs-fleet-review-actions fs-fleet-policy-actions">
		<button class="btn btn-primary" type="submit" name="template_save" value="1"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save and preview')?></button>
		<a class="btn btn-outline-secondary" href="?"><?=gettext('Cancel')?></a>
		<p class="fs-fleet-policy-note"><?=gettext('Saving changes nothing on the firewalls. The preview shows what applying would do on each one.')?></p>
	</div>
</form>
<script src="/fleet/assets/fleet-template.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-template.js')?>"></script>
<script src="/fleet/assets/fleet-tlist.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-tlist.js')?>"></script>
<?php endif; ?>
<?php include('foot.inc');
