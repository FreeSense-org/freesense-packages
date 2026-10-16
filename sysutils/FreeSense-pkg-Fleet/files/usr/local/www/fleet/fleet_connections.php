<?php
/*
 * fleet_connections.php
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
 * Connection manager (a view of Firewalls): how Fleet reaches each
 * firewall. The advisor and the methods with what each needs; the fleet
 * default; each group's and each firewall's choice; every firewall with
 * what it should use, where that comes from, and how its path answers;
 * applying the changes as an operation. The logic is fleet_conn.inc.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$who = (string)($_SESSION['Username'] ?? 'admin');
$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$manage = isAllowedPage('fleet/fleet.php');
$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Firewalls'), gettext('Connections'));
$input_errors = array();
$savemsg = null;

if ($ready && $manage && ($_SERVER['REQUEST_METHOD'] === 'POST')) {
	try {
		$kind = (string)($_POST['kind'] ?? '');
		$target = (string)($_POST['target'] ?? '');
		if (isset($_POST['save_conn']) && ($kind === 'fleet')) {
			fleet_conn_set_fleet($_POST, $who);
			$savemsg = gettext('Fleet default saved. Firewalls that follow it show as changes to apply under Firewalls.');
		} elseif (isset($_POST['save_conn']) && ($kind === 'group')) {
			if (fleet_group_get((int)$target) === null) {
				throw new InvalidArgumentException(gettext('That group no longer exists.'));
			}
			fleet_conn_set_group((int)$target, $_POST, $who);
			$savemsg = gettext('Group saved. Its firewalls show as changes to apply under Firewalls.');
		} elseif (isset($_POST['save_conn']) && ($kind === 'box')) {
			if (fleet_box_get($target) === null) {
				throw new InvalidArgumentException(gettext('That firewall no longer exists.'));
			}
			fleet_conn_set_box($target, $_POST, $who);
			$savemsg = gettext('Firewall saved. Apply the change below.');
		} elseif (isset($_POST['save_ts_token'])) {
			fleet_ts_token_set((string)($_POST['ts_token'] ?? ''), $who);
			$savemsg = gettext('Tailscale API token saved. Fleet now checks each firewall\'s tailnet device.');
		} elseif (isset($_POST['remove_ts_token'])) {
			fleet_ts_token_set('', $who);
			$savemsg = gettext('Tailscale API token removed. Tailscale paths are only probed now.');
		} elseif (isset($_POST['ts_expiry_off'])) {
			$savemsg = fleet_ts_key_expiry_off((string)($_POST['node'] ?? ''), $who);
		} elseif (isset($_POST['apply'])) {
			$nodes = array_keys(array_filter(fleet_conn_overview(), 'fleet_conn_pending'));
			if (isset($_POST['node'])) {
				$nodes = array_values(array_intersect($nodes, array((string)$_POST['node'])));
			}
			header('Location: /fleet/fleet_activity.php?op=' . (int)fleet_conn_launch($nodes, $who));
			exit;
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
echo fleet_firewalls_nav('connections', (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn());

$fleet_cfg = fleet_conn_fleet_cfg();
$groups = fleet_groups_all();
$overview = fleet_conn_overview();
$pending = array_filter($overview, 'fleet_conn_pending');
$answers = array_intersect_key($_GET, array_flip(array('public', 'private', 'thirdparty', 'udp')));
$advice = (count($answers) === 4) ? fleet_conn_advise($answers) : null;
$method_text = function (string $m, string $iface = '') {
	return gettext(FLEET_CONN_METHODS[$m][0] ?? $m) . ((($m === 'direct') && ($iface !== '')) ? ' ' . sprintf(gettext('on %s'), $iface) : '');
};
$from_text = function (string $from) {
	if ($from === 'firewall') {
		return gettext('set on the firewall');
	}
	return ($from === 'fleet') ? gettext('fleet default') : sprintf(gettext('from group %s'), substr($from, 6));
};
/* The filters of the firewall list, kept in the URL. */
$f = fleet_list_filters($_GET, array('q' => null, 'show' => array('pending' => 1, 'fallback' => 1, 'paths' => 1)));
$rows = array_filter($overview, function ($r) use ($f) {
	if (isset($f['q']) && (stripos($r['box']['label'] . ' ' . $r['box']['name'], $f['q']) === false)) {
		return false;
	}
	switch ($f['show'] ?? '') {
	case 'pending':
		return fleet_conn_pending($r);
	case 'fallback':
		return ($r['state'] !== null) && empty($r['state']['ok']);
	case 'paths':
		return $r['state'] !== null;
	}
	return true;
});
$pg = fleet_list_page(count($rows), (int)($_GET['page'] ?? 1));
$keep = array_intersect_key($_GET, array_flip(array('public', 'private', 'thirdparty', 'udp')));
$ts = fleet_ts_check($overview);
$views = array('firewalls' => gettext('Firewalls'), 'groups' => gettext('Default and groups'), 'methods' => gettext('Methods and Tailscale'));
$view = fs_view_param(array_keys($views), 'firewalls');
$keep['view'] = $view;
$fallbacks = count(array_filter($overview, function ($r) { return ($r['state'] !== null) && empty($r['state']['ok']); }));
?>

<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-route" aria-hidden="true"></i></span>
		<div><h2><?=gettext('How Fleet reaches your firewalls')?></h2><p><?=gettext('Every firewall joins over the Fleet tunnel. Fleet can also reach it directly on an internal network, or over Tailscale; the tunnel then stays as the fallback, so a path that stops answering never cuts a firewall off. Choose for the whole fleet, a group or one firewall.')?></p></div></header>
	<div class="fs-tiles fs-fleet-tiles-row">
		<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Fleet default')?></span><span class="fs-tile-value fs-fleet-tile-text"><?=htmlspecialchars($method_text($fleet_cfg['method'], $fleet_cfg['iface']))?></span></div>
		<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Firewalls on a path')?></span><span class="fs-tile-value"><?=count(array_filter($overview, function ($r) { return $r['state'] !== null; }))?> / <?=count($overview)?></span></div>
		<a class="fs-tile" href="?view=firewalls&amp;show=fallback"><span class="fs-tile-label"><?=gettext('Using the tunnel as fallback')?></span><span class="fs-tile-value<?=$fallbacks ? ' fs-fleet-problem' : ''?>"><?=$fallbacks?></span></a>
	</div>
</section>

<?php fs_view_switch($views, $view); ?>

<?php if ($view === 'firewalls'): ?>
<?php if (!empty($pending)): ?>
<div class="fs-fleet-callout fs-fleet-conn-pending"><i class="fa-solid fa-paper-plane" aria-hidden="true"></i>
	<div class="flex-grow-1"><strong><?=htmlspecialchars(sprintf(ngettext('%d connection change is waiting', '%d connection changes are waiting', count($pending)), count($pending)))?></strong>
		<div class="small fs-muted"><?=gettext('Applying sets up each path and keeps it only when the controller reaches the firewall over it; otherwise the firewall stays on the tunnel.')?></div></div>
<?php if ($manage): ?>
	<form method="post"><button class="btn btn-sm btn-primary text-nowrap" name="apply" value="1"><i class="fa-solid fa-paper-plane icon-embed-btn" aria-hidden="true"></i><?=sprintf(ngettext('Apply %d change', 'Apply %d changes', count($pending)), count($pending))?></button></form>
<?php endif; ?>
</div>
<?php endif; ?>
<?php if ($fallbacks && (($f['show'] ?? '') !== 'fallback')): ?>
<p class="fs-fleet-problem small"><i class="fa-solid fa-triangle-exclamation icon-embed-btn" aria-hidden="true"></i><?=htmlspecialchars(sprintf(ngettext('%d firewall is on the tunnel because its path stopped answering.', '%d firewalls are on the tunnel because their path stopped answering.', $fallbacks), $fallbacks))?>
	<a href="?view=firewalls&amp;show=fallback"><?=gettext('Show them')?></a></p>
<?php endif; ?>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Firewalls')?> <span class="fs-count"><?=count($overview)?></span></h2>
	</div>
	<div class="panel-body"><?=fleet_list_filterbar($keep, $f, array('show' => array(gettext('All firewalls'), array('pending' => 'Changes to apply', 'fallback' => 'Using the tunnel as fallback', 'paths' => 'On a direct or Tailscale path'))),
	    gettext('Search firewalls'), gettext('Firewall name'))?></div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Firewall')?></th><th><?=gettext('Should use')?></th><th><?=gettext('Uses now')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($rows)): ?>
		<tr><td colspan="4" class="fs-muted"><?=empty($overview) ? gettext('No firewalls yet.') : gettext('No firewall matches these filters.')?></td></tr>
<?php endif; ?>
<?php foreach (array_slice($rows, $pg['offset'], $pg['per'], true) as $node => $r): list($wm, $wi, $wfrom, $conflict) = $r['want']; $st = $r['state']; $todo = fleet_conn_pending($r); ?>
		<tr><td><a href="/fleet/fleet_box.php?id=<?=urlencode($node)?>"><strong><?=htmlspecialchars($r['box']['label'])?></strong></a>
				<?=($r['box']['state'] !== 'online') ? fs_badge('neutral', ucfirst($r['box']['state'])) : ''?></td>
			<td><?=htmlspecialchars($method_text($wm, $wi))?><div class="fs-muted small"><?=htmlspecialchars($from_text($wfrom))?></div>
				<?=($conflict !== null) ? '<div class="fs-fleet-problem small">' . htmlspecialchars(sprintf(gettext('Groups disagree (%s): set it on the firewall.'), implode(', ', $conflict))) . '</div>' : ''?></td>
			<td><?php if ($st === null): ?>
				<?=fs_badge('neutral', gettext('Fleet tunnel'))?>
<?php elseif (!empty($st['ok'])): ?>
				<?=fs_badge('pass', ucfirst($st['method']))?> <span class="fs-mono small"><?=htmlspecialchars($st['address'])?></span>
				<div class="fs-muted small"><?=htmlspecialchars(sprintf(gettext('Answers; checked %s. Tunnel is the fallback.'), date('H:i', (int)$st['checked'])))?></div>
<?php else: ?>
				<?=fs_badge('warn', gettext('Tunnel (fallback)'))?> <span class="small"><?=htmlspecialchars(sprintf(gettext('The %1$s path on %2$s does not answer: %3$s'), $st['method'], $st['address'], $st['error']))?></span>
<?php endif; ?>
<?php foreach ((isset($ts[$node]) ? $ts[$node]['problems'] : array()) as list($pcode, $psev, $ptext)): ?>
				<div class="small <?=($psev === 'error') ? 'fs-fleet-problem' : 'fs-muted'?>"><?=htmlspecialchars(ltrim($pcode . ': ' . $ptext, ': '))?>
<?php if ($manage && ($pcode === 'FLEET-E136')): ?>
					<form method="post" class="d-inline"><input type="hidden" name="view" value="firewalls"/><input type="hidden" name="node" value="<?=htmlspecialchars($node)?>"/><button class="btn btn-sm btn-link p-0" name="ts_expiry_off" value="1"><?=gettext('Turn key expiry off')?></button></form>
<?php endif; ?></div>
<?php endforeach; ?>
				<?=$todo ? '<div>' . fs_badge('info', gettext('Change to apply')) . '</div>' : ''?></td>
			<td class="text-end text-nowrap"><?php if ($manage): ?>
				<button type="button" class="btn btn-sm btn-link" data-fs-modal="#conn-modal" data-fs-modal-title="<?=htmlspecialchars(sprintf(gettext('Connection for %s'), $r['box']['label']))?>"
				    data-fs-fill="<?=htmlspecialchars(json_encode(array('kind' => 'box', 'target' => $node, 'conn_method' => (string)$r['box']['conn_method'], 'conn_iface' => (string)$r['box']['conn_iface'])))?>"><?=gettext('Change')?></button>
<?php if ($todo && ($r['box']['state'] === 'online')): ?>
				<form method="post" class="d-inline"><input type="hidden" name="node" value="<?=htmlspecialchars($node)?>"/><button class="btn btn-sm btn-link" name="apply" value="1"><?=gettext('Apply')?></button></form>
<?php endif; ?>
<?php endif; ?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
	<div class="panel-footer"><?=fleet_list_pager($pg, $keep, $f)?></div>
</div>

<?php elseif ($view === 'groups'): ?>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=gettext('Fleet default and groups')?></h2>
<?php if ($manage): ?>
		<button type="button" class="btn btn-sm btn-link" data-fs-modal="#conn-modal" data-fs-modal-title="<?=gettext('Fleet default')?>"
		    data-fs-fill="<?=htmlspecialchars(json_encode(array('kind' => 'fleet', 'target' => '', 'conn_method' => $fleet_cfg['method'], 'conn_iface' => $fleet_cfg['iface'])))?>"><?=gettext('Change the fleet default')?></button>
<?php endif; ?>
	</div>
	<div class="panel-body fs-fleet-pad"><p class="mb-0"><?=gettext('Fleet default:')?> <strong><?=htmlspecialchars($method_text($fleet_cfg['method'], $fleet_cfg['iface']))?></strong>.
		<span class="fs-muted"><?=gettext('A group can choose its own; a firewall in several groups that disagree needs its own choice.')?></span></p></div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Group')?></th><th><?=gettext('Firewalls')?></th><th><?=gettext('Connection')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php if (empty($groups)): ?>
		<tr><td colspan="4" class="fs-muted"><?=gettext('No groups yet. Every firewall follows the fleet default unless it has its own choice.')?></td></tr>
<?php endif; ?>
<?php foreach ($groups as $grp): $gm = (string)($grp['conn_method'] ?? ''); ?>
		<tr><td><strong><?=htmlspecialchars($grp['name'])?></strong></td>
			<td><?=(int)fleet_db()->query('SELECT COUNT(*) FROM box_groups WHERE group_id = ' . (int)$grp['id'])->fetchColumn()?></td>
			<td><?=($gm === '') ? '<span class="fs-muted">' . gettext('As the fleet') . '</span>' : htmlspecialchars($method_text($gm, (string)$grp['conn_iface']))?></td>
			<td class="text-end"><?php if ($manage): ?><button type="button" class="btn btn-sm btn-link" data-fs-modal="#conn-modal" data-fs-modal-title="<?=htmlspecialchars(sprintf(gettext('Connection for group %s'), $grp['name']))?>"
			    data-fs-fill="<?=htmlspecialchars(json_encode(array('kind' => 'group', 'target' => (string)$grp['id'], 'conn_method' => $gm, 'conn_iface' => (string)$grp['conn_iface'])))?>"><?=gettext('Change')?></button><?php endif; ?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
</div>

<?php else: ?>
<div class="fs-fleet-rule-grid fs-fleet-conn-methods mb-3">
<?php foreach (FLEET_CONN_METHODS as $m => list($label, $icon)): $rec = ($advice !== null) && ($advice[0] === $m); ?>
		<article class="fs-fleet-rcard<?=$rec ? ' fs-fleet-recommended' : ''?><?=($fleet_cfg['method'] === $m) ? ' is-on' : ''?>">
			<div class="fs-fleet-rcard-head">
				<span class="fs-fleet-rcard-icon"><i class="fa-solid <?=$icon?>" aria-hidden="true"></i></span>
				<div class="fs-fleet-rcard-title"><strong><?=htmlspecialchars(gettext($label))?></strong>
					<span class="small"><?=$rec ? fs_badge('pass', gettext('Recommended for you')) : ''?><?=($fleet_cfg['method'] === $m) ? ' ' . fs_badge('info', gettext('Fleet default')) : ''?></span></div>
			</div>
			<details class="small fs-fleet-conn-reqs-wrap"><summary><?=gettext('Works only if')?></summary>
			<ul class="fs-fleet-conn-reqs">
<?php foreach (fleet_conn_requirements($m) as $req): ?>
				<li><?=htmlspecialchars(gettext($req))?></li>
<?php endforeach; ?>
			</ul></details>
		</article>
<?php endforeach; ?>
	</div>
<details class="panel panel-default fs-fleet-advisor" open>
	<summary class="panel-heading"><h2 class="panel-title d-inline"><i class="fa-solid fa-compass icon-embed-btn" aria-hidden="true"></i><?=gettext('Not sure? Answer four questions')?></h2></summary>
	<div class="panel-body fs-fleet-pad">
		<form method="get" class="fs-fleet-advisor-form"><input type="hidden" name="view" value="methods"/>
<?php foreach (array('public' => gettext('Can the controller be reached from the internet (a public address or a port forward)?'),
    'private' => gettext('Do the firewalls and the controller share a private network, MPLS or a site-to-site VPN?'),
    'thirdparty' => gettext('May a third-party coordination service (Tailscale) be used?'),
    'udp' => gettext('Do the sites allow outbound UDP?')) as $q => $text): ?>
			<fieldset class="fs-fleet-advisor-q"><legend class="form-label"><?=$text?></legend>
<?php foreach (array('yes' => gettext('Yes'), 'no' => gettext('No'), 'unsure' => gettext('Not sure')) as $v => $vl): ?>
				<label class="form-check form-check-inline"><input class="form-check-input" type="radio" name="<?=$q?>" value="<?=$v?>"<?=(($answers[$q] ?? 'unsure') === $v) ? ' checked' : ''?>/> <span class="form-check-label"><?=$vl?></span></label>
<?php endforeach; ?>
			</fieldset>
<?php endforeach; ?>
			<button class="btn btn-sm btn-primary" type="submit"><?=gettext('Recommend')?></button>
		</form>
<?php if ($advice !== null): list($am, $why, $care) = $advice; ?>
		<div class="fs-fleet-callout mt-3"><i class="fa-solid <?=FLEET_CONN_METHODS[$am][1]?>" aria-hidden="true"></i>
			<div><strong><?=htmlspecialchars(sprintf(gettext('Recommended: %s'), gettext(FLEET_CONN_METHODS[$am][0])))?></strong>
				<ul class="mb-1"><?php foreach ($why as $w) { echo '<li>' . htmlspecialchars(gettext($w)) . '</li>'; } ?></ul>
				<p class="small mb-0"><strong><?=gettext('Before you switch:')?></strong> <?=htmlspecialchars(implode(' ', array_map('gettext', $care)))?></p></div></div>
<?php endif; ?>
	</div>
</details>

<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><i class="fa-solid fa-circle-nodes icon-embed-btn" aria-hidden="true"></i><?=gettext('Tailscale API')?></h2>
<?php if ($manage): ?>
		<div>
			<button type="button" class="btn btn-sm btn-link" data-fs-modal="#ts-modal"><?=($ts === null) ? gettext('Add a token') : gettext('Replace the token')?></button>
<?php if ($ts !== null): ?>
			<form method="post" class="d-inline"><input type="hidden" name="view" value="methods"/><button class="btn btn-sm btn-link" name="remove_ts_token" value="1"><?=gettext('Remove')?></button></form>
<?php endif; ?>
		</div>
<?php endif; ?>
	</div>
	<div class="panel-body fs-fleet-pad">
<?php if ($ts === null): ?>
		<p class="mb-0"><?=gettext('Optional. With an API access token Fleet checks the tailnet device of each firewall on a Tailscale path: whether its key expires (FLEET-E136), waits for approval or is offline. Without one, Fleet only probes the path.')?></p>
<?php elseif (isset($ts['error'])): ?>
		<p class="fs-fleet-problem mb-0"><?=htmlspecialchars($ts['error'])?></p>
<?php else: $ts_bad = count(array_filter($ts, function ($t) { return !empty($t['problems']); })); ?>
		<p class="mb-0"><?=fs_badge($ts_bad ? 'warn' : 'pass', $ts_bad ? sprintf(gettext('%d need attention'), $ts_bad) : gettext('Checked'))?>
			<?=htmlspecialchars(sprintf(ngettext('%d firewall on a Tailscale path; the device list is read at most every %d minutes.', '%d firewalls on a Tailscale path; the device list is read at most every %d minutes.', count($ts)), count($ts), FLEET_TS_CACHE / 60))?></p>
<?php endif; ?>
	</div>
</div>
<?php endif; ?>

<?php if ($manage):
	fs_modal_form_begin('conn-modal', gettext('Connection'), '/fleet/fleet_connections.php', array('kind' => '', 'target' => '', 'view' => $view));
?>
	<fieldset class="mb-3"><legend class="form-label"><?=gettext('Fleet reaches these firewalls over')?></legend>
		<label class="form-check" data-conn-inherit><input class="form-check-input" type="radio" name="conn_method" value=""/> <span class="form-check-label"><?=gettext('As above (the group, or the fleet default)')?></span></label>
<?php foreach (FLEET_CONN_METHODS as $m => list($label, $icon)): ?>
		<label class="form-check"><input class="form-check-input" type="radio" name="conn_method" value="<?=$m?>"/> <span class="form-check-label"><i class="fa-solid <?=$icon?> fs-muted" aria-hidden="true"></i> <?=htmlspecialchars(gettext($label))?></span></label>
<?php endforeach; ?>
	</fieldset>
	<div class="mb-3" data-conn-iface><label class="form-label" for="c-iface"><?=gettext('Interface the controller reaches them on')?></label>
		<input class="form-control fs-mono" id="c-iface" name="conn_iface" maxlength="32" placeholder="lan"/>
		<div class="form-text"><?=gettext('The interface key on the firewalls, like lan, opt2 or a virtual IP. Not WAN.')?></div></div>
	<p class="fs-fleet-hint mb-0"><?=gettext('Saving changes nothing on the firewalls. The firewall list then shows the changes; applying sets up each path and keeps it only when the controller reaches the firewall over it.')?></p>
<?php
	fs_modal_form_end(gettext('Save'), 'save_conn', '1', 'fa-floppy-disk');
	fs_modal_form_begin('ts-modal', gettext('Tailscale API token'), '/fleet/fleet_connections.php', array('view' => 'methods'));
?>
	<div class="mb-3"><label class="form-label" for="ts-token"><?=gettext('API access token')?></label>
		<input class="form-control fs-mono" id="ts-token" name="ts_token" type="password" autocomplete="off" maxlength="220" placeholder="tskey-api-…" required/>
		<div class="form-text"><?=gettext('Create it in the Tailscale admin console under Settings > Keys. Fleet reads the devices and can turn key expiry off; it stores the token encrypted and never shows it again.')?></div></div>
	<p class="fs-fleet-hint mb-0"><?=gettext('Fleet tests the token before saving it. Tokens expire (90 days at most); add a new one before that.')?></p>
<?php
	fs_modal_form_end(gettext('Save'), 'save_ts_token', '1', 'fa-floppy-disk');
endif; ?>
<script src="/fleet/assets/fleet-connections.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-connections.js')?>"></script>
<?php include('foot.inc');
