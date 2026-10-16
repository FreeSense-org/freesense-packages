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
			fleet_template_delete((int)$_POST['template_delete'], $who);
			$savemsg = gettext('Template deleted. The aliases it pushed stay on the firewalls; Fleet no longer manages them.');
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
?>

<?php if ($view === 'list'):
	$all = fleet_templates_all();
	$q = trim((string)($_GET['q'] ?? ''));
	$shown = array_values(array_filter($all, function ($t) use ($q, $names) {
		return ($q === '') || (stripos($t['name'] . ' ' . $t['description'] . ' ' . fleet_targets_text($t['targets'], $names) . ' ' . implode(' ', array_column($t['items'], 'name')), $q) !== false);
	}));
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Templates')?> <span class="fs-count"><?=count($all)?></span></h2></div>
<?php if (empty($all)): ?>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead"><?=gettext('A template pushes the same configuration to many firewalls. Start with aliases: a list of servers, office networks or ports that every firewall in a group should know. Fleet shows what would change on each firewall before anything is applied, and only ever changes aliases it pushed itself.')?></p>
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
		<thead><tr><th><?=gettext('Name')?></th><th><?=gettext('For')?></th><th><?=gettext('Aliases')?></th><th><?=gettext('Firewalls')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($shown)): ?>
		<tr><td colspan="5" class="fs-muted"><?=gettext('No template matches.')?> <a href="?"><?=gettext('Clear the search')?></a></td></tr>
<?php endif; ?>
<?php foreach ($shown as $t):
	$nodes = fleet_template_nodes($t['targets']);
	$sync = 0;
	$pending = 0;
	$unknown = 0;
	foreach ($nodes as $node) {
		$plan = fleet_template_plan_from_backup($t, $node);
		if ($plan === null) {
			$unknown++;
			continue;
		}
		$c = fleet_template_plan_counts($plan);
		($c['create'] + $c['update'] + $c['delete'] === 0) ? $sync++ : $pending++;
	}
?>
		<tr><td><a href="?view=preview&amp;id=<?=(int)$t['id']?>"><?=htmlspecialchars($t['name'])?></a>
				<?=($t['description'] !== '') ? '<div class="fs-muted small">' . htmlspecialchars($t['description']) . '</div>' : ''?></td>
			<td><?=htmlspecialchars(fleet_targets_text($t['targets'], $names))?></td>
			<td class="small"><?=htmlspecialchars(implode(', ', array_column($t['items'], 'name')))?></td>
			<td><?=fs_badge('pass', sprintf(gettext('%1$d of %2$d in sync'), $sync, count($nodes)))?>
				<?=($pending > 0) ? fs_badge('info', sprintf(ngettext('%d to apply', '%d to apply', $pending), $pending)) : ''?>
				<?=($unknown > 0) ? fs_badge('neutral', sprintf(gettext('%d not known'), $unknown)) : ''?></td>
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

<?php elseif ($view === 'preview'):
	$t = fleet_template_get((int)($_GET['id'] ?? 0));
	if ($t === null): ?>
<div class="fs-fleet-empty"><strong><?=gettext('That template no longer exists.')?></strong> <a href="?"><?=gettext('All templates')?></a></div>
<?php else:
	$nodes = fleet_template_nodes($t['targets']);
	$states = fleet_template_states((int)$t['id']);
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
				$plan = fleet_template_plan((int)$t['id'], $t['items'], fleet_template_remote($box));
			} catch (RuntimeException $e) {
				$err = $e->getMessage();
			}
		} else {
			$plan = fleet_template_plan_from_backup($t, $node);
		}
		$c = ($plan === null) ? null : fleet_template_plan_counts($plan);
		if ($c !== null) {
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
		<div class="fs-fleet-tpl-items">
<?php foreach ($t['items'] as $item): ?>
			<div class="fs-fleet-tpl-chip"><i class="fa-solid <?=$type_icons[$item['type']]?>" aria-hidden="true"></i> <strong><?=htmlspecialchars($item['name'])?></strong>
				<span class="fs-muted small"><?=sprintf(ngettext('%d entry', '%d entries', count($item['entries'])), count($item['entries']))?></span></div>
<?php endforeach; ?>
		</div>
	</div>
</div>
<div class="fs-tiles fs-fleet-tiles-row">
	<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Firewalls with changes')?></span><span class="fs-tile-value"><?=$todo_boxes?></span></div>
	<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Create / change / remove')?></span><span class="fs-tile-value"><?=$tot['create']?> / <?=$tot['update']?> / <?=$tot['delete']?></span></div>
	<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Conflicts (skipped)')?></span><span class="fs-tile-value"><?=$tot['conflict']?></span></div>
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
<?php if ($err !== null): ?>
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
			<td class="text-end"><?php if ($manage && ($box !== null) && ($box['state'] === 'online') && fleet_manage_allowed($box)): ?>
				<form method="post" class="d-inline"><input type="hidden" name="node" value="<?=htmlspecialchars($node)?>"/><button class="btn btn-sm btn-link" name="template_apply" value="<?=(int)$t['id']?>"><?=gettext('Apply here')?></button></form><?php endif; ?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
<?php if ($manage && !empty($rows)): ?>
	<div class="panel-footer fs-fleet-review-actions fs-fleet-policy-actions">
		<form method="post"><button class="btn btn-primary" name="template_apply" value="<?=(int)$t['id']?>"><i class="fa-solid fa-paper-plane icon-embed-btn" aria-hidden="true"></i><?=sprintf(ngettext('Apply to %d firewall', 'Apply to %d firewalls', count($rows)), count($rows))?></button></form>
		<p class="fs-fleet-policy-note"><?=gettext('Each firewall gets a safety backup first, then the changes and one filter reload. Conflicts are skipped: Fleet never changes an alias it did not push. The firewalls are read again when the apply starts, so a change made since the backup is not lost.')?></p>
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
	$t = $t ?? array('id' => 0, 'name' => '', 'description' => '', 'targets' => array('all'), 'items' => array());
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
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=$t['id'] ? sprintf(htmlspecialchars(gettext('Change %s')), htmlspecialchars($t['name'])) : gettext('Add a template')?></h2></div>
		<div class="panel-body fs-fleet-pad">
			<div class="row g-3">
				<div class="col-md-4"><label class="form-label" for="tname"><?=gettext('Name')?></label>
					<input class="form-control" id="tname" name="name" maxlength="60" required value="<?=htmlspecialchars($t['name'])?>" placeholder="<?=gettext('Company networks')?>"/></div>
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
	<section class="fs-fleet-area">
		<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-list-ul" aria-hidden="true"></i></span>
			<div><h2><?=gettext('Aliases')?></h2><p><?=gettext('Lists of hosts, networks or ports the firewalls\' rules can use by name. On the firewall each is marked as pushed by this template.')?></p></div></header>
		<div class="fs-fleet-rule-grid fs-fleet-tpl-grid" data-tpl-list data-next="<?=count($cards)?>">
<?php foreach ($cards as $n => $a) { echo $card($n, $a); } ?>
		</div>
		<button type="button" class="btn btn-sm btn-outline-secondary mt-2" data-tpl-add><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add alias')?></button>
		<template data-tpl-blank><?=$card(999999, array('name' => '', 'type' => 'host', 'description' => '', 'entries' => ''))?></template>
	</section>
	<div class="fs-fleet-review-actions fs-fleet-policy-actions">
		<button class="btn btn-primary" type="submit" name="template_save" value="1"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save and preview')?></button>
		<a class="btn btn-outline-secondary" href="?"><?=gettext('Cancel')?></a>
		<p class="fs-fleet-policy-note"><?=gettext('Saving changes nothing on the firewalls. The preview shows what applying would do on each one.')?></p>
	</div>
</form>
<script src="/fleet/assets/fleet-template.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-template.js')?>"></script>
<?php endif; ?>
<?php include('foot.inc');
