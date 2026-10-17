<?php
/*
 * fleet_ha.php
 *
 * part of FreeSense (https://freesense.org)
 * Copyright (c) 2025-2026 FreeSense
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
 * HA pairs (a view of Firewalls): the pairs Fleet sees, and setting up a
 * new one from two managed firewalls (choose them; choose the shared
 * addresses, the sync interface and what HA sync pushes; review; set up
 * as an operation). The logic is fleet_ha.inc and fleet_ha_setup.inc.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$who = (string)($_SESSION['Username'] ?? 'admin');
$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$manage = isAllowedPage('fleet/fleet.php');
$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Firewalls'), gettext('HA pairs'));
$input_errors = array();
$view = ($manage && in_array($_REQUEST['view'] ?? '', array('setup', 'group'), true)) ? $_REQUEST['view'] : 'pairs';
$group_results = null;
$in = array('primary' => (string)($_REQUEST['primary'] ?? ''), 'secondary' => (string)($_REQUEST['secondary'] ?? ''));
$plan = null;

/* The form's addresses and choices, from the request. */
$form_in = function () use ($in) {
	$vips = array();
	foreach ((array)($_POST['vip_on'] ?? array()) as $if => $on) {
		$vips[] = array('iface' => (string)$if, 'address' => (string)($_POST['vip_addr'][$if] ?? ''), 'vhid' => (int)($_POST['vip_vhid'][$if] ?? 0));
	}
	return $in + array('vips' => $vips, 'sync_iface' => (string)($_POST['sync_iface'] ?? ''), 'sections' => array_keys((array)($_POST['sections'] ?? array())));
};

if ($ready && $manage && ($_SERVER['REQUEST_METHOD'] === 'POST') && (isset($_POST['review']) || isset($_POST['setup']))) {
	$pb = fleet_box_get($in['primary']);
	$sb = fleet_box_get($in['secondary']);
	if (($pb === null) || ($sb === null)) {
		$input_errors[] = gettext('Choose two firewalls of the fleet.');
	} else {
		list($errors, $plan) = fleet_ha_setup_plan($form_in(), fleet_ha_setup_facts($pb), fleet_ha_setup_facts($sb));
		$input_errors = array_merge($input_errors, array_map('gettext', $errors));
		if (isset($_POST['setup']) && ($plan !== null)) {
			header('Location: /fleet/fleet_activity.php?op=' . fleet_ha_setup_launch($plan, $who));
			exit;
		}
	}
}

/* The managed facts of a group's firewalls, node => fleet_ha_setup_facts(). */
$group_facts = function (int $gid): array {
	$q = fleet_db()->prepare('SELECT node_id FROM box_groups WHERE group_id = ?');
	$q->execute(array($gid));
	$facts = array();
	foreach ($q->fetchAll(PDO::FETCH_COLUMN) as $n) {
		$b = fleet_box_get($n);
		if ($b !== null) {
			$facts[$n] = fleet_ha_setup_facts($b);
		}
	}
	return $facts;
};

/* Set up every suggested pair of a group, each with its suggested settings, as one operation per pair. */
if ($ready && $manage && ($_SERVER['REQUEST_METHOD'] === 'POST') && isset($_POST['setup_group'])) {
	$facts = $group_facts((int)($_POST['group'] ?? 0));
	$group_results = array();
	foreach (fleet_ha_candidates($facts) as $c) {
		list($errors, $gplan) = fleet_ha_setup_plan($c, $facts[$c['primary']], $facts[$c['secondary']]);
		$group_results[] = array($facts[$c['primary']]['label'], $facts[$c['secondary']]['label'], $errors, ($gplan === null) ? null : fleet_ha_setup_launch($gplan, $who));
	}
}

include('head.inc');
if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
?>
<link rel="stylesheet" href="/fleet/assets/fleet.css?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet.css')?>">
<?php
$tab_array = array(
	array(gettext('Dashboard'), false, '/fleet/fleet_dashboard.php'),
	array(gettext('Activity'), false, '/fleet/fleet_activity.php'),
	array(gettext('Updates'), false, '/fleet/fleet_updates.php'),
	array(gettext('Schedules'), false, '/fleet/fleet_schedules.php'),
	array(gettext('Backups'), false, '/fleet/fleet_backups.php'),
	array(gettext('Policies'), false, '/fleet/fleet_policies.php'),
	array(gettext('Templates'), false, '/fleet/fleet_templates.php'),
	array(gettext('Users'), false, '/fleet/fleet_users.php'),
	array(gettext('Firewalls'), true, '/fleet/fleet.php'),
	array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
);
display_top_tabs($tab_array);
if (!$ready): ?>
<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller')?></strong></div>
<?php include('foot.inc'); exit; endif;
echo fleet_firewalls_nav('ha', (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn());
list($pairs, $boxes) = fleet_ha_now();
?>

<?php if ($view === 'pairs'): ?>
<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-clone" aria-hidden="true"></i></span>
		<div><h2><?=gettext('HA pairs')?></h2><p><?=gettext('Firewalls that share CARP addresses. Fleet never works on both at once: the BACKUP goes first, the MASTER when its partner is back and the pair is healthy. Set up a new pair from two managed firewalls; Fleet makes the shared addresses, state sync and configuration sync on both.')?></p></div>
<?php if ($manage): ?>
		<span class="fs-fleet-area-actions"><a class="btn btn-sm btn-primary" href="?view=setup"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Set up a pair')?></a>
			<a class="btn btn-sm btn-outline-secondary" href="?view=group"><i class="fa-solid fa-layer-group icon-embed-btn" aria-hidden="true"></i><?=gettext('Pair a group')?></a></span>
<?php endif; ?>
	</header>
</section>
<div class="panel panel-default">
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Pair')?></th><th><?=gettext('State')?></th><th><?=gettext('Shared addresses')?></th><th><?=gettext('Configuration sync')?></th></tr></thead>
		<tbody>
<?php if (empty($pairs)): ?>
		<tr><td colspan="4" class="fs-muted"><?=gettext('No HA pairs yet.')?><?=$manage ? ' <a href="?view=setup">' . gettext('Set up a pair') . '</a>' : ''?></td></tr>
<?php endif; ?>
<?php foreach ($pairs as $hp): ?>
		<tr><td><?php foreach ($hp['nodes'] as $hn): ?><div><a href="/fleet/fleet_box.php?id=<?=urlencode($hn)?>"><?=htmlspecialchars($boxes[$hn]['label'])?></a>
				<?=in_array($hn, $hp['masters'], true) ? fs_badge('info', 'MASTER') : fs_badge('neutral', 'BACKUP')?><?=($boxes[$hn]['state'] !== 'online') ? ' ' . fs_badge('warn', ucfirst($boxes[$hn]['state'])) : ''?></div><?php endforeach; ?></td>
			<td><?=($hp['problem'] === null) ? fs_badge('pass', gettext('Healthy')) : fs_badge('down', gettext(fleet_ha_problem_badge($hp['problem'])))?></td>
			<td class="small"><?=implode('<br>', array_map(function ($k) { return htmlspecialchars(fleet_ha_vip_text($k)); }, array_keys($hp['vips'])))?></td>
			<td class="small"><?=($hp['primary'] !== null) ? htmlspecialchars(sprintf(gettext('From %s'), $boxes[$hp['primary']]['label'])) : '<span class="fs-muted">' . gettext('None') . '</span>'?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
</div>

<?php elseif ($view === 'group'):
	$gid = (int)($_REQUEST['group'] ?? 0);
	$facts = ($gid > 0) ? $group_facts($gid) : array();
	$cands = fleet_ha_candidates($facts);
?>
<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-layer-group" aria-hidden="true"></i></span>
		<div><h2><?=gettext('Pair a group')?></h2><p><?=gettext('Fleet pairs the group\'s managed firewalls that share an internal network (one site), with suggested settings: the sync interface, and the first free address of every other shared network as the shared address. Review a pair in the wizard, or set them all up.')?></p></div></header>
</section>
<?php if ($group_results !== null): ?>
<div class="panel panel-default"><div class="panel-body fs-fleet-pad"><ul class="mb-0">
<?php foreach ($group_results as list($la, $lb, $errs, $op)): ?>
	<li><?=htmlspecialchars("{$la} + {$lb}: ")?><?=($op !== null) ? '<a href="/fleet/fleet_activity.php?op=' . (int)$op . '">' . gettext('setting up') . '</a>' : '<span class="fs-fleet-problem">' . htmlspecialchars(implode(' ', $errs)) . '</span>'?></li>
<?php endforeach; ?>
<?php if (empty($group_results)): ?><li class="fs-muted"><?=gettext('Nothing to set up.')?></li><?php endif; ?>
</ul></div></div>
<?php endif; ?>
<form method="get" class="panel panel-default">
	<input type="hidden" name="view" value="group"/>
	<div class="panel-body fs-fleet-pad d-flex gap-2 align-items-end flex-wrap">
		<div><label class="form-label" for="ha-group"><?=gettext('Group')?></label>
			<select class="form-select" id="ha-group" name="group"><option value="0"><?=gettext('Choose...')?></option>
<?php foreach (fleet_groups_all() as $grp): ?>
				<option value="<?=(int)$grp['id']?>"<?=((int)$grp['id'] === $gid) ? ' selected' : ''?>><?=htmlspecialchars($grp['name'])?></option>
<?php endforeach; ?>
			</select></div>
		<button class="btn btn-sm btn-outline-secondary" type="submit"><?=gettext('Find pairs')?></button>
	</div>
</form>
<?php if ($gid > 0): ?>
<form method="post" class="panel panel-default">
	<input type="hidden" name="view" value="group"/><input type="hidden" name="group" value="<?=$gid?>"/>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Primary')?></th><th><?=gettext('Secondary')?></th><th><?=gettext('Shared addresses')?></th><th><?=gettext('Sync interface')?></th><th class="text-end"></th></tr></thead>
		<tbody>
<?php foreach ($cands as $c): $cf = $facts[$c['primary']]; ?>
		<tr><td><?=htmlspecialchars($cf['label'])?></td><td><?=htmlspecialchars($facts[$c['secondary']]['label'])?></td>
			<td class="small fs-mono"><?=htmlspecialchars(implode(', ', array_map(function ($v) use ($cf) { return $v['address'] . ' (' . ($cf['ifaces'][$v['iface']]['name'] ?? $v['iface']) . ')'; }, $c['vips'])))?></td>
			<td class="small"><?=htmlspecialchars($cf['ifaces'][$c['sync_iface']]['name'] ?? $c['sync_iface'])?></td>
			<td class="text-end"><a href="?view=setup&amp;primary=<?=urlencode($c['primary'])?>&amp;secondary=<?=urlencode($c['secondary'])?>"><?=gettext('Review...')?></a></td></tr>
<?php endforeach; ?>
<?php if (empty($cands)): ?>
		<tr><td colspan="5" class="fs-muted"><?=empty($facts) ? gettext('The group has no firewalls.') : gettext('No two managed firewalls of this group share an internal network, or they are already paired.')?></td></tr>
<?php endif; ?>
		</tbody></table></div>
<?php if (!empty($cands)): ?>
	<div class="panel-footer"><p class="fs-fleet-hint mb-2"><?=gettext('Check first that nothing on those networks already uses the suggested shared addresses.')?></p>
		<button class="btn btn-primary" name="setup_group" value="1"><i class="fa-solid fa-clone icon-embed-btn" aria-hidden="true"></i><?=htmlspecialchars(sprintf((count($cands) === 1) ? gettext('Set up %d pair') : gettext('Set up %d pairs'), count($cands)))?></button></div>
<?php endif; ?>
</form>
<?php endif; ?>

<?php else:
	/* Setup: firewalls that can join a pair. */
	$in_pair = array();
	foreach ($pairs as $hp) {
		foreach ($hp['nodes'] as $hn) {
			$in_pair[$hn] = true;
		}
	}
	$choice = array();
	foreach (fleet_db()->query("SELECT node_id, label, role, state FROM boxes ORDER BY label COLLATE NOCASE")->fetchAll() as $b) {
		if (($b['role'] === 'managed') && !isset($in_pair[$b['node_id']])) {
			$choice[$b['node_id']] = $b['label'] . (($b['state'] !== 'online') ? ' (' . $b['state'] . ')' : '');
		}
	}
	$chosen = isset($choice[$in['primary']], $choice[$in['secondary']]) && ($in['primary'] !== $in['secondary']);
	$pf = $chosen ? fleet_ha_setup_facts(fleet_box_get($in['primary'])) : null;
	$sf = $chosen ? fleet_ha_setup_facts(fleet_box_get($in['secondary'])) : null;
	$common = $chosen ? array_intersect_key($pf['ifaces'], $sf['ifaces']) : array();
	$clashes = array();
	foreach (($chosen ? array($pf, $sf) : array()) as $fx) {
		foreach ($fx['ifaces'] as $i) {
			if (!empty($i['clash'])) {
				$clashes[] = sprintf(gettext('On %1$s, %2$s and %3$s use the same network card (%4$s). Fix the interface assignments first; neither is offered here.'),
				    $fx['label'], $i['name'], implode(', ', $i['clash']), $i['dev']);
			}
		}
	}
	$clashes = array_values(array_unique($clashes));
	$common = array_filter($common, function ($i, $k) use ($sf) {
		return ($i['ip'] !== '') && ($sf['ifaces'][$k]['ip'] !== '') && empty($i['clash']) && empty($sf['ifaces'][$k]['clash']);
	}, ARRAY_FILTER_USE_BOTH);
	$posted = ($_SERVER['REQUEST_METHOD'] === 'POST') ? $form_in() : null;
	/* First visit: Fleet's suggestion from the two firewalls' interfaces. */
	$suggested = (($posted === null) && $chosen) ? fleet_ha_suggest($pf['ifaces'], $sf['ifaces']) : null;
	if ($suggested !== null) {
		$posted = array('vips' => $suggested['vips'], 'sync_iface' => $suggested['sync_iface'], 'sections' => $suggested['sections']);
	}
	$on = ($posted === null) ? array() : array_column($posted['vips'], null, 'iface');
	$sync_sel = ($posted === null) ? '' : $posted['sync_iface'];
	$sec_sel = ($posted === null) ? array('rules', 'aliases', 'nat') : $posted['sections'];
?>
<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-clone" aria-hidden="true"></i></span>
		<div><h2><?=gettext('Set up an HA pair')?></h2><p><?=gettext('The primary becomes MASTER and the secondary BACKUP for each shared address. Both need the same interfaces on the same networks, and a sync interface (ideally a direct link). Each firewall is changed under commit-confirm; if anything fails, Fleet undoes the setup on both.')?></p></div></header>
</section>
<?php
	$ha_steps = array('pick' => gettext('Firewalls'), 'addr' => gettext('Shared addresses'), 'sync' => gettext('Sync'), 'review' => gettext('Review'));
	/* The choices travel along as hidden fields to the review, and back. */
	$ha_hidden = function (array $p) use ($in) {
		$h = '<input type="hidden" name="view" value="setup"/><input type="hidden" name="primary" value="' . htmlspecialchars($in['primary']) . '"/>' .
		    '<input type="hidden" name="secondary" value="' . htmlspecialchars($in['secondary']) . '"/>';
		foreach ($p['vips'] as $v) {
			$k = htmlspecialchars($v['iface']);
			$h .= '<input type="hidden" name="vip_on[' . $k . ']" value="1"/><input type="hidden" name="vip_addr[' . $k . ']" value="' . htmlspecialchars($v['address']) . '"/>' .
			    '<input type="hidden" name="vip_vhid[' . $k . ']" value="' . (int)($v['vhid'] ?? 0) . '"/>';
		}
		$h .= '<input type="hidden" name="sync_iface" value="' . htmlspecialchars($p['sync_iface']) . '"/>';
		foreach ($p['sections'] as $sec) {
			$h .= '<input type="hidden" name="sections[' . htmlspecialchars($sec) . ']" value="1"/>';
		}
		return $h;
	};
?>
<?php if (!$chosen): ?>
<form method="get" class="panel panel-default">
	<input type="hidden" name="view" value="setup"/>
	<div class="panel-body fs-fleet-pad">
<?php fs_stepper($ha_steps, 'pick', array(), gettext('Set up an HA pair')); ?>
		<h3 class="fs-step-title"><?=gettext('1. The two firewalls')?></h3>
		<p class="fs-step-lead"><?=gettext('Choose which firewall is the primary (it carries the shared addresses) and which is the secondary. Fleet then reads their interfaces; nothing changes yet.')?></p>
		<div class="fs-fleet-ha-pick">
<?php foreach (array('primary' => gettext('Primary (MASTER)'), 'secondary' => gettext('Secondary (BACKUP)')) as $k => $l): ?>
			<div><label class="form-label" for="ha-<?=$k?>"><?=$l?></label>
				<select class="form-select" id="ha-<?=$k?>" name="<?=$k?>" required><option value=""><?=gettext('Choose...')?></option>
<?php foreach ($choice as $n => $label): ?>
					<option value="<?=htmlspecialchars($n)?>"<?=($in[$k] === $n) ? ' selected' : ''?>><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
				</select></div>
<?php endforeach; ?>
			<p class="fs-fleet-hint mb-0"><?=gettext('Only managed firewalls that are not in a pair are listed.')?></p>
		</div>
	</div>
	<div class="panel-footer fs-step-nav"><a class="btn btn-outline-secondary" href="?view=pairs"><?=gettext('Cancel')?></a>
		<button class="btn btn-primary" type="submit"><i class="fa-solid fa-arrow-right icon-embed-btn" aria-hidden="true"></i><?=gettext('Next: read their interfaces')?></button></div>
</form>
<?php elseif ($plan === null): ?>
<form method="post" class="panel panel-default" action="?view=setup&amp;primary=<?=urlencode($in['primary'])?>&amp;secondary=<?=urlencode($in['secondary'])?>">
	<input type="hidden" name="view" value="setup"/><input type="hidden" name="primary" value="<?=htmlspecialchars($in['primary'])?>"/><input type="hidden" name="secondary" value="<?=htmlspecialchars($in['secondary'])?>"/>
	<div class="panel-body fs-fleet-pad">
<?php fs_steps_begin($ha_steps, isset($_POST['back']) ? 'sync' : 'addr', gettext('Set up an HA pair')); ?>
<?php fs_step_begin('addr', sprintf(gettext('%1$s and %2$s share these networks. Tick the ones that get a shared address; each needs a free address on that network.'), $pf['label'], $sf['label'])); ?>
		<p class="mb-3"><a href="?view=setup"><i class="fa-solid fa-arrow-left icon-embed-btn" aria-hidden="true"></i><?=gettext('Choose other firewalls')?></a></p>
<?php if ($suggested !== null): ?>
		<p class="fs-fleet-hint"><?=gettext('Filled in from the two firewalls: the first free address of each other shared network. Check nothing else on those networks uses them.')?></p>
<?php endif; ?>
<?php foreach ($clashes as $c): ?>
		<p class="fs-fleet-problem"><?=htmlspecialchars($c)?></p>
<?php endforeach; ?>
<?php if (empty($common)): ?>
		<p class="fs-fleet-problem mb-0"><?=gettext('The two firewalls have no interface with an IPv4 address in common (or one of them did not answer).')?></p>
<?php else: ?>
		<div class="table-responsive"><table class="table fs-table">
			<thead><tr><th><?=gettext('Share')?></th><th><?=gettext('Interface')?></th><th><?=htmlspecialchars($pf['label'])?></th><th><?=htmlspecialchars($sf['label'])?></th><th><?=gettext('Shared address')?></th><th><?=gettext('VHID')?></th></tr></thead>
			<tbody>
<?php foreach ($common as $k => $i): ?>
			<tr><td><input class="form-check-input" type="checkbox" name="vip_on[<?=htmlspecialchars($k)?>]" value="1" id="vip-<?=htmlspecialchars($k)?>"<?=isset($on[$k]) ? ' checked' : ''?>/></td>
				<td><label for="vip-<?=htmlspecialchars($k)?>"><strong><?=htmlspecialchars($i['name'])?></strong> <span class="fs-muted fs-mono small"><?=htmlspecialchars($k)?></span></label></td>
				<td class="fs-mono small"><?=htmlspecialchars($i['ip'] . '/' . $i['bits'])?></td><td class="fs-mono small"><?=htmlspecialchars($sf['ifaces'][$k]['ip'] . '/' . $sf['ifaces'][$k]['bits'])?></td>
				<td><input class="form-control form-control-sm fs-mono" name="vip_addr[<?=htmlspecialchars($k)?>]" value="<?=htmlspecialchars($on[$k]['address'] ?? '')?>" placeholder="<?=gettext('a free address')?>" aria-label="<?=gettext('Shared address')?>"/></td>
				<td><input class="form-control form-control-sm fs-fleet-vhid" name="vip_vhid[<?=htmlspecialchars($k)?>]" value="<?=(int)($on[$k]['vhid'] ?? 0) ?: ''?>" placeholder="<?=gettext('auto')?>" inputmode="numeric" pattern="[0-9]*" aria-label="VHID"/></td></tr>
<?php endforeach; ?>
			</tbody></table></div>
<?php endif; ?>
<?php fs_step_end(); ?>
<?php fs_step_begin('sync', gettext('The primary sends its connection states and the configuration you choose to the secondary over this interface.')); ?>
<?php if (!empty($common)): ?>
		<div class="mb-3"><label class="form-label" for="ha-sync"><?=gettext('Sync interface')?></label>
			<select class="form-select fs-field-md" id="ha-sync" name="sync_iface">
<?php foreach ($common as $k => $i): ?>
				<option value="<?=htmlspecialchars($k)?>"<?=($sync_sel === $k) ? ' selected' : ''?>><?=htmlspecialchars("{$i['name']} ({$i['ip']} / {$sf['ifaces'][$k]['ip']})")?></option>
<?php endforeach; ?>
			</select>
			<div class="form-text"><?=gettext('A dedicated link between the two is best.')?></div>
			<div class="mt-2" data-ha-wan-warning<?=((($sync_sel !== '') ? $sync_sel : (string)array_key_first($common)) === 'wan') ? '' : ' hidden'?>><?php print_callout(htmlspecialchars(gettext('State sync is not encrypted and would cross the internet. Give both firewalls a direct link (or at least an internal network) for sync.')), 'warning', gettext('This is the WAN')); ?></div>
			<script>document.getElementById('ha-sync').addEventListener('change', function () { document.querySelector('[data-ha-wan-warning]').hidden = (this.value !== 'wan'); });</script></div>
		<fieldset><legend class="form-label"><?=gettext('The primary pushes to the secondary')?></legend>
<?php foreach (FLEET_HA_SECTIONS as $sec => $sl): ?>
			<label class="form-check form-check-inline"><input class="form-check-input" type="checkbox" name="sections[<?=$sec?>]" value="1"<?=in_array($sec, $sec_sel, true) ? ' checked' : ''?>/> <span class="form-check-label"><?=gettext($sl)?></span></label>
<?php endforeach; ?>
			<div class="form-text"><?=gettext('Users and certificates are not offered: syncing them would replace the secondary\'s Fleet access. Fleet sets the shared addresses on both itself.')?></div></fieldset>
<?php endif; ?>
		<button class="btn btn-primary" name="review" value="1" data-fs-step-submit<?=empty($common) ? ' disabled' : ''?>><i class="fa-solid fa-magnifying-glass icon-embed-btn" aria-hidden="true"></i><?=gettext('Next: review')?></button>
<?php fs_step_end(); ?>
<?php fs_steps_end(); ?>
	</div>
</form>
<?php else: $posted_now = $form_in(); ?>
<form method="post" class="panel panel-default" action="?view=setup&amp;primary=<?=urlencode($in['primary'])?>&amp;secondary=<?=urlencode($in['secondary'])?>">
	<?=$ha_hidden($posted_now)?>
	<div class="panel-body fs-fleet-pad fs-fleet-ha-review" id="ha-review">
<?php fs_stepper($ha_steps, 'review', array(), gettext('Set up an HA pair')); ?>
		<h3 class="fs-step-title"><?=gettext('4. Review')?></h3>
		<p class="fs-step-lead"><?=gettext('This is what happens on the two firewalls when you select Set up. Nothing has changed yet.')?></p>
		<ol>
<?php foreach ($plan['vips'] as $v): ?>
			<li><?=htmlspecialchars(sprintf(gettext('%1$s on %2$s, VHID %3$d: %4$s MASTER (skew 0), %5$s BACKUP (skew 100)'), $v['address'] . '/' . $v['bits'], $v['name'], $v['vhid'], $pf['label'], $sf['label']))?></li>
<?php endforeach; ?>
			<li><?=htmlspecialchars(sprintf(gettext('State sync (pfsync) on %1$s between %2$s and %3$s'), $common[$plan['sync_iface']]['name'], $plan['primary_sync_ip'], $plan['secondary_sync_ip']))?></li>
			<li><?=htmlspecialchars(empty($plan['sections']) ? sprintf(gettext('%s pushes no configuration'), $pf['label']) :
			    sprintf(gettext('%1$s pushes %2$s to %3$s, logging in as fleet-hasync (a new user on %3$s with only the HA sync privilege)'), $pf['label'],
			    implode(', ', array_map(function ($s1) { return gettext(FLEET_HA_SECTIONS[$s1]); }, $plan['sections'])), $sf['label']))?></li>
			<li><?=gettext('New random CARP and sync passwords; Fleet does not keep them.')?></li>
		</ol>
<?php if ($plan['sync_iface'] === 'wan'): ?>
		<?php print_callout(htmlspecialchars(gettext('State sync is not encrypted and would cross the internet.')), 'warning', gettext('Sync over the WAN')); ?>
<?php endif; ?>
	</div>
	<div class="panel-footer fs-step-nav">
		<button class="btn btn-outline-secondary fs-step-back" name="back" value="1"><i class="fa-solid fa-arrow-left icon-embed-btn" aria-hidden="true"></i><?=gettext('Back')?></button>
		<span class="fs-step-note"><?=gettext('It runs as an operation in Activity; if anything fails, Fleet undoes it on both.')?></span>
		<button class="btn btn-primary" name="setup" value="1"><i class="fa-solid fa-clone icon-embed-btn" aria-hidden="true"></i><?=htmlspecialchars(sprintf(gettext('Set up %1$s and %2$s as a pair'), $pf['label'], $sf['label']))?></button>
	</div>
</form>
<?php endif; ?>
<?php endif; ?>
<?php include('foot.inc');
