<?php
/*
 * fleet_kiosks.php
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
 * NOC screens (a view of the Dashboard): the wall screens that show the
 * fleet without logging in. Each has its own read-only kiosk link (the
 * key is shown once), the networks it may be used from, and whether it
 * hides names; revoke cuts it off at once. The logic is fleet_kiosk.inc.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$who = (string)($_SESSION['Username'] ?? 'admin');
$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$manage = isAllowedPage('fleet/fleet.php');
$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('NOC screens'));
$input_errors = array();
$savemsg = null;
$new_link = null;
$reopen = null;
/* ?config=<screen id> or ?config=live: the layout, list and panels of a screen, or of the WebUI's live view. */
$kconf = isset($_REQUEST['config']) ? (((string)$_REQUEST['config'] === 'live') ? 'live' : (string)(int)$_REQUEST['config']) : null;

if ($ready && $manage && ($_SERVER['REQUEST_METHOD'] === 'POST')) {
	try {
		if (isset($_POST['save_config']) && ($kconf !== null)) {
			fleet_kiosk_config_set($kconf, fleet_kiosk_config_parse($_POST, true), $who);
			$savemsg = ($kconf === 'live') ? gettext('Live view changed. An open live view takes it within 10 seconds.') :
			    gettext('Screen changed. It takes the new layout within 10 seconds and keeps its link.');
		} elseif (isset($_POST['save'])) {
			if ((string)($_POST['id'] ?? '') === '') {
				list(, $key) = fleet_kiosk_create($_POST, $who);
				$host = (string)($_SERVER['HTTP_HOST'] ?? '');
				$new_link = 'https://' . $host . '/fleet/kiosk.php#' . $key;
			} else {
				fleet_kiosk_update((int)$_POST['id'], $_POST, $who);
				$savemsg = gettext('Screen changed. It keeps its link.');
			}
		} elseif (isset($_POST['revoke'])) {
			fleet_kiosk_revoke((int)$_POST['revoke'], $who);
			$savemsg = gettext('Link revoked. That screen shows "not connected" within 10 seconds.');
		}
	} catch (InvalidArgumentException $e) {
		$input_errors[] = $e->getMessage();
		$reopen = array('id' => (string)($_POST['id'] ?? ''), 'name' => (string)($_POST['name'] ?? ''), 'networks' => (string)($_POST['networks'] ?? ''), 'hide' => !empty($_POST['hide']),
		    'style' => fleet_kiosk_look((string)($_POST['style'] ?? ''), '')[0], 'theme' => fleet_kiosk_look('', (string)($_POST['theme'] ?? ''))[1]);
	}
}
if ($ready && $manage && ($kconf === null)) {
	fs_page_action(gettext('Configure live view'), '/fleet/fleet_kiosks.php?config=live', 'fa-sliders', 'secondary');
	fs_page_action(gettext('Add screen'), '#', 'fa-plus', 'primary', array('data-fs-modal' => '#kiosk-modal', 'data-fs-modal-title' => gettext('Add a NOC screen'),
	    'data-fs-fill' => json_encode(array('id' => '', 'name' => '', 'networks' => '', 'hide' => false, 'style' => 'freesense', 'theme' => 'auto'))));
}
if ($ready) {
	fs_page_action(gettext('Open live view'), '/fleet/noc.php', 'fa-display', 'secondary', array('target' => '_blank', 'rel' => 'noopener'));
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
	array(gettext('Dashboard'), true, '/fleet/fleet_dashboard.php'),
	array(gettext('Activity'), false, '/fleet/fleet_activity.php'),
	array(gettext('Updates'), false, '/fleet/fleet_updates.php'),
	array(gettext('Schedules'), false, '/fleet/fleet_schedules.php'),
	array(gettext('Backups'), false, '/fleet/fleet_backups.php'),
	array(gettext('Policies'), false, '/fleet/fleet_policies.php'),
	array(gettext('Templates'), false, '/fleet/fleet_templates.php'),
	array(gettext('Users'), false, '/fleet/fleet_users.php'),
	array(gettext('Firewalls'), false, '/fleet/fleet.php'),
	array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
);
display_top_tabs($tab_array);
echo fleet_dashboard_nav('kiosks');
if (!$ready): ?>
<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller')?></strong></div>
<?php include('foot.inc'); exit; endif;
$screens = fleet_kiosks_all();
if (($kconf !== null) && $manage):
	try {
		$kcfg = fleet_kiosk_config_get($kconf);
	} catch (InvalidArgumentException $e) {
		print_input_errors(array($e->getMessage()));
		include('foot.inc');
		exit;
	}
	$cname = ($kconf === 'live') ? gettext('the live view') : (string)(array_column($screens, 'name', 'id')[(int)$kconf] ?? '');
	$h = function ($s) { return htmlspecialchars((string)$s); };
	$chk = function (bool $on) { return $on ? ' checked' : ''; };
	$groups = fleet_groups_all();
?>
<p><a class="fs-fleet-back" href="/fleet/fleet_kiosks.php"><i class="fa-solid fa-arrow-left" aria-hidden="true"></i><?=gettext('NOC screens')?></a></p>
<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-sliders" aria-hidden="true"></i></span>
		<div><h2><?=$h(sprintf(gettext('Layout of %s'), $cname))?></h2><p><?=gettext('On the left, panels with the state of the fleet, its HA pairs and the fleet server, and charts; on the right, the firewall list. Each side turns its pages by itself when it does not fit. A problem always comes first.')?></p></div></header>
</section>
<form method="post" action="?config=<?=$h($kconf)?>" class="fs-fleet-kcfg">
	<input type="hidden" name="save_config" value="1"/>
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('Layout')?></h2></div>
		<div class="panel-body fs-fleet-pad">
			<div class="row g-3 mb-3">
				<div class="col-sm-5"><label class="form-label" for="kheading"><?=gettext('Header text')?></label>
					<input class="form-control" id="kheading" name="heading" maxlength="60" value="<?=$h($kcfg['heading'])?>" placeholder="<?=$h(gettext('Network operations'))?>"/>
					<div class="form-text"><?=gettext('Shown top left, large. Empty: the name of the screen.')?></div></div>
				<div class="col-sm-7"><label class="form-label" for="ksubheading"><?=gettext('Second line')?> <span class="fs-muted small"><?=gettext('(optional)')?></span></label>
					<input class="form-control" id="ksubheading" name="subheading" maxlength="100" value="<?=$h($kcfg['subheading'])?>" placeholder="<?=$h(gettext('On call: 1234 when something is red'))?>"/></div>
			</div>
			<fieldset class="mb-3"><legend class="form-label"><?=gettext('The screen shows')?></legend>
<?php foreach (FLEET_KIOSK_LAYOUTS as $k => $t): ?>
				<label class="form-check form-check-inline"><input class="form-check-input" type="radio" name="layout" value="<?=$k?>"<?=$chk($kcfg['layout'] === $k)?>/> <span class="form-check-label"><?=$h(gettext($t))?></span></label>
<?php endforeach; ?>
			</fieldset>
			<div class="row g-3">
				<div class="col-sm-4"><label class="form-label" for="kleft"><?=gettext('Panels take')?></label>
					<select class="form-select" id="kleft" name="left">
<?php for ($v = 25; $v <= 75; $v += 5): ?>
						<option value="<?=$v?>"<?=($kcfg['left'] === $v) ? ' selected' : ''?>><?=$h(sprintf(gettext('%d%% of the width'), $v))?></option>
<?php endfor; ?>
					</select></div>
				<div class="col-sm-4"><label class="form-label" for="kside"><?=gettext('Panels on the')?></label>
					<select class="form-select" id="kside" name="side">
						<option value="left"<?=($kcfg['side'] === 'left') ? ' selected' : ''?>><?=gettext('Left')?></option>
						<option value="right"<?=($kcfg['side'] === 'right') ? ' selected' : ''?>><?=gettext('Right')?></option>
					</select></div>
				<div class="col-sm-4"><label class="form-label" for="kview"><?=gettext('Firewalls as')?></label>
					<select class="form-select" id="kview" name="view">
						<option value="list"<?=($kcfg['view'] === 'list') ? ' selected' : ''?>><?=gettext('A list (most details)')?></option>
						<option value="tiles"<?=($kcfg['view'] === 'tiles') ? ' selected' : ''?>><?=gettext('Tiles')?></option>
					</select></div>
			</div>
		</div>
	</div>

	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('Firewall list')?></h2></div>
		<div class="panel-body fs-fleet-pad">
			<fieldset class="mb-3"><legend class="form-label"><?=gettext('Columns')?></legend>
				<div class="fs-fleet-checkgrid">
<?php foreach (FLEET_KIOSK_COLUMNS as $k => $t): ?>
					<label class="form-check"><input class="form-check-input" type="checkbox" name="columns[]" value="<?=$k?>"<?=$chk(in_array($k, $kcfg['columns'], true))?><?=in_array($k, array('state', 'name'), true) ? ' disabled' : ''?>/>
						<span class="form-check-label"><?=$h(gettext($t))?></span></label>
<?php endforeach; ?>
				</div>
				<div class="form-text"><?=gettext('State and name are always shown. CPU, memory, states and traffic are the newest load sample (every 5 minutes).')?></div></fieldset>
			<div class="row g-3 mb-3">
				<div class="col-sm-3"><label class="form-label" for="ksort"><?=gettext('Order')?></label>
					<select class="form-select" id="ksort" name="sort">
<?php foreach (FLEET_KIOSK_SORTS as $k => $t): ?>
						<option value="<?=$k?>"<?=($kcfg['sort'] === $k) ? ' selected' : ''?>><?=$h(gettext($t))?></option>
<?php endforeach; ?>
					</select>
					<div class="form-text"><?=gettext('Offline and late firewalls come first in every order.')?></div></div>
				<div class="col-sm-3"><label class="form-label" for="krows"><?=gettext('Rows per page')?></label>
					<input class="form-control" type="number" id="krows" name="rows" min="0" max="50" value="<?=(int)$kcfg['rows']?>"/>
					<div class="form-text"><?=gettext('0: as many as fit the screen.')?></div></div>
				<div class="col-sm-3"><label class="form-label" for="kflip"><?=gettext('Next page every')?></label>
					<div class="input-group"><input class="form-control" type="number" id="kflip" name="flip" min="5" max="120" value="<?=(int)$kcfg['flip']?>"/><span class="input-group-text"><?=gettext('seconds')?></span></div></div>
				<div class="col-sm-3"><span class="form-label d-block">&nbsp;</span><label class="form-check"><input class="form-check-input" type="checkbox" name="hold" value="1"<?=$chk($kcfg['hold'])?>/>
					<span class="form-check-label"><?=gettext('Stay on page 1 while a firewall is offline')?></span></label></div>
			</div>
			<fieldset><legend class="form-label"><?=gettext('Only these groups')?></legend>
<?php if (empty($groups)): ?>
				<p class="fs-fleet-hint mb-0"><?=gettext('No groups yet: the screen shows every firewall.')?></p>
<?php else: ?>
				<div class="fs-fleet-checkgrid">
<?php foreach ($groups as $grp): ?>
					<label class="form-check"><input class="form-check-input" type="checkbox" name="groups[]" value="<?=(int)$grp['id']?>"<?=$chk(in_array((int)$grp['id'], $kcfg['groups'], true))?>/>
						<span class="form-check-label"><?=$h($grp['name'])?></span></label>
<?php endforeach; ?>
				</div>
				<div class="form-text"><?=gettext('None ticked: every firewall. With one group, the charts show that group too.')?></div>
<?php endif; ?>
			</fieldset>
		</div>
	</div>

	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('Panels')?></h2></div>
		<div class="panel-body table-responsive"><table class="table fs-table">
			<thead><tr><th><?=gettext('Show')?></th><th><?=gettext('Panel')?></th><th><?=gettext('Order')?></th></tr></thead>
			<tbody>
<?php
	$order = array_flip($kcfg['panels']);
	$ids = array_keys(FLEET_KIOSK_PANELS);
	usort($ids, function ($a, $b) use ($order) { return array($order[$a] ?? 99, $a) <=> array($order[$b] ?? 99, $b); });
	foreach ($ids as $i => $k):
?>
			<tr><td><input class="form-check-input" type="checkbox" id="kp-<?=$k?>" name="panels[]" value="<?=$k?>"<?=$chk(isset($order[$k]))?>/></td>
				<td><label for="kp-<?=$k?>"><?=$h(gettext(FLEET_KIOSK_PANELS[$k][0]))?></label><?=(FLEET_KIOSK_PANELS[$k][1] === 2) ? ' <span class="fs-muted small">' . gettext('(tall)') . '</span>' : ''?></td>
				<td><input class="form-control form-control-sm fs-fleet-order" type="number" min="1" max="99" name="order[<?=$k?>]" value="<?=$i + 1?>" aria-label="<?=$h(sprintf(gettext('Order of %s'), FLEET_KIOSK_PANELS[$k][0]))?>"/></td></tr>
<?php endforeach; ?>
			</tbody></table></div>
		<div class="panel-body fs-fleet-pad pt-0"><div class="row g-3">
			<div class="col-sm-4"><label class="form-label" for="kpflip"><?=gettext('Next panels every')?></label>
				<div class="input-group"><input class="form-control" type="number" id="kpflip" name="panel_flip" min="5" max="300" value="<?=(int)$kcfg['panel_flip']?>"/><span class="input-group-text"><?=gettext('seconds')?></span></div></div>
			<div class="col-sm-4"><label class="form-label" for="krange"><?=gettext('Charts show')?></label>
				<select class="form-select" id="krange" name="range">
<?php foreach (FLEET_KIOSK_RANGES as $k => $t): ?>
					<option value="<?=$k?>"<?=($kcfg['range'] === $k) ? ' selected' : ''?>><?=$h(gettext($t))?></option>
<?php endforeach; ?>
				</select></div>
		</div>
		<p class="fs-fleet-hint"><?=gettext('Panels that do not fit go on the next page. Lower numbers come first.')?></p></div>
	</div>

	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('Sound')?></h2></div>
		<div class="panel-body fs-fleet-pad">
			<label class="form-check mb-2"><input class="form-check-input" type="checkbox" name="sound" value="1"<?=$chk($kcfg['sound'])?>/>
				<span class="form-check-label"><?=gettext('Sound on when the screen opens')?></span></label>
			<fieldset><legend class="form-label"><?=gettext('Beep when')?></legend>
<?php foreach (FLEET_KIOSK_BEEPS as $k => $t): ?>
				<label class="form-check"><input class="form-check-input" type="checkbox" name="beep[]" value="<?=$k?>"<?=$chk(in_array($k, $kcfg['beep'], true))?>/> <span class="form-check-label"><?=$h(gettext($t))?></span></label>
<?php endforeach; ?>
				<div class="form-text"><?=gettext('A browser plays sound only after someone clicked on the page once.')?></div></fieldset>
		</div>
	</div>

	<p class="d-flex gap-2"><button class="btn btn-primary" type="submit"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save layout')?></button>
<?php if ($kconf === 'live'): ?>
		<a class="btn btn-outline-secondary" href="/fleet/noc.php" target="_blank" rel="noopener"><?=gettext('Open live view')?></a>
<?php endif; ?>
		<a class="btn btn-link" href="/fleet/fleet_kiosks.php"><?=gettext('Back')?></a></p>
</form>
<?php
	include('foot.inc');
	exit;
endif;
?>

<?php if ($new_link !== null): ?>
<div class="panel panel-default fs-fleet-newkey">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('The link for this screen')?></h2></div>
	<div class="panel-body fs-fleet-pad">
		<p><?=gettext('Open it on the screen. It is shown only now: copy it before you leave this page. Anyone with the link can watch the fleet from the allowed networks, so treat it like a password.')?></p>
		<div class="fs-fleet-keyline"><code class="fs-mono" id="kiosk-link"><?=htmlspecialchars($new_link)?></code>
			<button class="btn btn-sm btn-outline-secondary" type="button" data-fs-copy="#kiosk-link"><i class="fa-solid fa-copy icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy')?></button></div>
	</div>
</div>
<?php endif; ?>

<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-display" aria-hidden="true"></i></span>
		<div><h2><?=gettext('NOC screens')?></h2><p><?=gettext('A full-screen, read-only view of the fleet for a wall screen that never logs in. Problems come first and the screen pages through the rest. Each screen has its own link, works only from its networks, and can hide names for a screen in a public place.')?></p></div></header>
<?php if (empty($screens)): ?>
	<p class="fs-fleet-hint"><?=gettext('No screens yet. Add one and open its link on the screen.')?></p>
<?php else: ?>
	<div class="panel panel-default"><div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Screen')?></th><th><?=gettext('Allowed from')?></th><th><?=gettext('Names')?></th><th><?=gettext('Style')?></th><th><?=gettext('Last seen')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php foreach ($screens as $k): ?>
		<tr><td><strong><?=htmlspecialchars($k['name'])?></strong><div class="fs-muted small"><?=htmlspecialchars(sprintf(gettext('Made %1$s by %2$s'), date('Y-m-d', (int)$k['created']), $k['who']))?></div></td>
			<td class="fs-mono small"><?=htmlspecialchars(implode(', ', $k['networks']))?></td>
			<td><?=!empty($k['hide']) ? fs_badge('info', gettext('Hidden')) : '<span class="fs-muted small">' . gettext('Shown') . '</span>'?></td>
			<td class="small"><?=htmlspecialchars(gettext(FLEET_KIOSK_STYLES[$k['style'] ?? 'freesense'][0] ?? 'FreeSense'))?>
				<span class="fs-muted"><?=htmlspecialchars(gettext(FLEET_KIOSK_THEMES[$k['theme'] ?? 'auto'] ?? ''))?></span></td>
			<td class="small"><?=($k['last_used'] !== null) ? htmlspecialchars(date('Y-m-d H:i', (int)$k['last_used']) . ' (' . $k['last_ip'] . ')') : '<span class="fs-muted">' . gettext('Not opened yet') . '</span>'?></td>
			<td class="text-end text-nowrap">
<?php if ($manage): ?>
				<button type="button" class="btn btn-sm btn-link" data-fs-modal="#kiosk-modal" data-fs-modal-title="<?=htmlspecialchars(sprintf(gettext('Change %s'), $k['name']))?>"
				    data-fs-fill="<?=htmlspecialchars(json_encode(array('id' => (string)$k['id'], 'name' => $k['name'], 'networks' => implode("\n", $k['networks']), 'hide' => !empty($k['hide']), 'style' => (string)($k['style'] ?? 'freesense'), 'theme' => (string)($k['theme'] ?? 'auto'))))?>"><?=gettext('Change')?></button>
				<a class="btn btn-sm btn-link" href="?config=<?=(int)$k['id']?>"><?=gettext('Layout')?></a>
				<form method="post" class="d-inline"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="revoke" value="<?=(int)$k['id']?>"><?=gettext('Revoke')?></button></form>
<?php endif; ?>
			</td></tr>
<?php endforeach; ?>
		</tbody></table></div></div>
<?php endif; ?>
</section>

<?php if ($manage):
	fs_modal_form_begin('kiosk-modal', gettext('Add a NOC screen'), '/fleet/fleet_kiosks.php', array('id' => ''), $reopen);
?>
	<div class="mb-3"><label class="form-label" for="kname"><?=gettext('Name')?></label>
		<input class="form-control" id="kname" name="name" maxlength="60" required placeholder="<?=gettext('NOC wall left')?>"/>
		<div class="form-text"><?=gettext('Shown at the top of the screen.')?></div></div>
	<div class="mb-3"><label class="form-label" for="knets"><?=gettext('Allowed from')?></label>
		<textarea class="form-control fs-mono" id="knets" name="networks" rows="3" required placeholder="10.20.0.15&#10;10.20.5.0/24"></textarea>
		<div class="form-text"><?=gettext('The address or network of the screen, one per line. The link does nothing from anywhere else.')?></div></div>
	<fieldset class="mb-3"><legend class="form-label"><?=gettext('Style')?></legend>
		<div class="fs-fleet-styles">
<?php foreach (FLEET_KIOSK_STYLES as $sk => list($sname, $sdesc)): ?>
			<label class="fs-fleet-style fs-fleet-style--<?=$sk?>"><input type="radio" name="style" value="<?=$sk?>"/>
				<span class="fs-fleet-style-swatch" aria-hidden="true"><i></i><i></i><i></i></span>
				<span><strong><?=htmlspecialchars(gettext($sname))?></strong><small><?=htmlspecialchars(gettext($sdesc))?></small></span></label>
<?php endforeach; ?>
		</div>
		<div class="form-text"><?=gettext('Changes reach the screen within 10 seconds; it keeps its link. Preview each style in the live view.')?></div></fieldset>
	<div class="mb-3"><label class="form-label" for="ktheme"><?=gettext('Light or dark')?></label>
		<select class="form-select" id="ktheme" name="theme">
<?php foreach (FLEET_KIOSK_THEMES as $tk => $tname): ?>
			<option value="<?=$tk?>"><?=htmlspecialchars(gettext($tname))?></option>
<?php endforeach; ?>
		</select></div>
	<label class="form-check"><input class="form-check-input" type="checkbox" name="hide" value="1"/>
		<span class="form-check-label"><?=gettext('Hide names and addresses (for a screen people walk past): firewalls are numbered, error texts are left out')?></span></label>
<?php
	fs_modal_form_end(gettext('Save screen'), 'save', '1', 'fa-floppy-disk');
endif; ?>
<?php include('foot.inc');
