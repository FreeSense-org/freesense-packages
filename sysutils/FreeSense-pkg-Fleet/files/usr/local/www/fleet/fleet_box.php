<?php
/*
 * fleet_box.php
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
 * One firewall in the fleet: what it last reported, its place in the fleet,
 * recent events, and "Open WebUI" (a one-time sign-in the box issues over
 * the tunnel; the browser then goes to an address the box reported).
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Firewall'));
$s = fleet_ctl_settings();
$box = ($s['enable'] && is_file(FLEET_DATA . '/fleet.db')) ? fleet_box_get((string)($_REQUEST['id'] ?? '')) : null;
if ($box === null) {
	header('Location: /fleet/fleet_dashboard.php');
	exit;
}
$st = json_decode((string)$box['status'], true) ?: array();
$manage = isAllowedPage('fleet/fleet.php');
$who = (string)($_SESSION['Username'] ?? 'admin');
$input_errors = array();

if (($_POST['open_webui'] ?? false) && $manage) {
	$base = (string)($_POST['base'] ?? '');
	$user = (string)($_POST['user'] ?? '');
	try {
		$path = fleet_box_handoff($box, $user, "{$who}@" . (string)config_get_path('system/hostname', 'controller'));
		$url = fleet_handoff_url($st, $base, $path);
		if ($url === null) {
			throw new RuntimeException(gettext('That address is not one this firewall reported. Reload the page and pick an address from the list.'));
		}
		fleet_audit($who, 'handoff', "{$box['node_id']} ({$box['label']}): WebUI as {$user} via {$base}");
		/* No Referer: the box's WebGUI refuses foreign referers, and it need not learn the controller's address. */
		header('Referrer-Policy: no-referrer');
		header('Location: ' . $url);
		exit;
	} catch (RuntimeException $e) {
		$input_errors[] = $e->getMessage();
	}
}

$state = in_array($box['state'], array('online', 'degraded', 'offline'), true) ? $box['state'] : 'new';
$state_names = array('online' => gettext('Online'), 'degraded' => gettext('Degraded'), 'offline' => gettext('Offline'), 'new' => gettext('Joining'));
$when = function ($ts) {
	return $ts ? htmlspecialchars(date('Y-m-d H:i', (int)$ts)) : '<span class="fs-muted">' . gettext('never') . '</span>';
};
$events = fleet_db()->prepare('SELECT time, who, action, detail FROM audit WHERE detail LIKE ? ORDER BY id DESC LIMIT 15');
$events->execute(array($box['node_id'] . '%'));
$events = $events->fetchAll();
$webgui = (array)($st['webgui'] ?? array());
/* Inside addresses first: WAN is rarely the one an administrator's browser reaches. */
usort($webgui, function ($x, $y) {
	return (strcasecmp((string)$x['name'], 'WAN') === 0) <=> (strcasecmp((string)$y['name'], 'WAN') === 0);
});
$users = (array)($st['handoff_users'] ?? array());
$rev = (array)($st['config_revision'] ?? array());
$asset = function ($f) {
	return '/fleet/assets/' . $f . '?v=' . (int)@filemtime('/usr/local/www/fleet/assets/' . $f);
};

include('head.inc');
?>
<link rel="stylesheet" href="<?=$asset('fleet.css')?>">
<?php
if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
?>
<a class="fs-fleet-back" href="/fleet/fleet_dashboard.php"><i class="fa-solid fa-arrow-left" aria-hidden="true"></i><?=gettext('All firewalls')?></a>

<div class="fs-fleet-box-head" data-state="<?=$state?>">
	<div class="fs-fleet-box-names">
		<h2 class="fs-fleet-headline"><?=htmlspecialchars($box['label'])?></h2>
		<div class="fs-fleet-checked"><?=htmlspecialchars((string)($st['hostname'] ?? $box['name']))?></div>
	</div>
<?php if ($state === 'online'): ?>
	<span class="fs-fleet-ok"><?=$state_names['online']?></span>
<?php else: ?>
	<?=fs_badge($state === 'new' ? 'pending' : $state, $state_names[$state])?>
<?php endif; ?>
</div>
<?php if ($state !== 'online' && (string)$box['error'] !== ''): ?>
<p class="fs-fleet-problem fs-fleet-problem--lead"><?=htmlspecialchars($box['error'])?></p>
<?php endif; ?>

<?php if ($manage): ?>
<section class="fs-fleet-block" aria-labelledby="webui-title">
	<h2 id="webui-title" class="fs-fleet-section-title"><?=gettext('Open WebUI')?></h2>
<?php if (empty($users)): ?>
	<p class="fs-fleet-lead"><?=gettext('This firewall does not allow sign-in from the controller. A local administrator turns it on, for chosen users only, on the firewall\'s console:')?></p>
	<code class="fs-fleet-command">freesense-join handoff-users admin</code>
<?php elseif (empty($webgui)): ?>
	<p class="fs-fleet-lead"><?=gettext('This firewall has not reported a WebGUI address yet. It does so with its next status check.')?></p>
<?php else: ?>
	<p class="fs-fleet-lead"><?=gettext('Signs you in on the firewall\'s own WebUI with a one-time link that is valid for 60 seconds. Works only if your browser can reach the address you choose.')?></p>
	<form method="post" class="fs-fleet-form">
		<div class="fs-fleet-field fs-fleet-field--wide"><label class="form-label" for="base"><?=gettext('Address')?></label>
			<select class="form-select" id="base" name="base">
<?php foreach ($webgui as $w): ?>
				<option value="<?=htmlspecialchars($w['url'])?>"><?=htmlspecialchars($w['name'] . ': ' . $w['url'])?></option>
<?php endforeach; ?>
			</select></div>
		<div class="fs-fleet-field"><label class="form-label" for="user"><?=gettext('Sign in as')?></label>
			<select class="form-select" id="user" name="user">
<?php foreach ($users as $u): ?>
				<option value="<?=htmlspecialchars($u)?>"><?=htmlspecialchars($u)?></option>
<?php endforeach; ?>
			</select></div>
		<div class="fs-fleet-field fs-fleet-field--button">
			<button class="btn btn-primary" type="submit" name="open_webui" value="1" <?=($state === 'offline') ? 'disabled' : ''?>><i class="fa-solid fa-arrow-up-right-from-square icon-embed-btn" aria-hidden="true"></i><?=gettext('Open WebUI')?></button>
		</div>
	</form>
<?php endif; ?>
</section>
<?php endif; ?>

<div class="fs-fleet-columns">
	<section class="fs-fleet-block" aria-labelledby="system-title">
		<h2 id="system-title" class="fs-fleet-section-title"><?=gettext('This firewall')?></h2>
		<dl class="fs-fleet-facts fs-fleet-facts--wide">
			<dt><?=gettext('Version')?></dt><dd><?=htmlspecialchars((string)($st['version'] ?? '-'))?></dd>
			<dt><?=gettext('Platform')?></dt><dd><?=htmlspecialchars((string)($st['platform'] ?? '-'))?></dd>
			<dt><?=gettext('Configuration')?></dt><dd><?=$when($rev['time'] ?? 0)?><?php if (($rev['description'] ?? '') !== ''): ?><div class="fs-muted"><?=htmlspecialchars($rev['description'])?></div><?php endif; ?></dd>
			<dt><?=gettext('Rollback protection')?></dt><dd><?php if (!isset($st['rollback_protection'])): ?>-<?php elseif ($st['rollback_protection']): ?><?=gettext('Yes (ZFS boot environments)')?><?php else: ?><?=fs_badge('warn', gettext('No rollback'))?> <span class="fs-muted"><?=gettext('A failed update cannot roll back by itself.')?></span><?php endif; ?></dd>
			<dt><?=gettext('CARP')?></dt><dd><?=(($st['carp'] ?? 'none') === 'none') ? gettext('Not used') : ((($st['carp'] ?? '') === 'ok') ? gettext('OK') : fs_badge('degraded', (string)$st['carp']))?></dd>
			<dt><?=gettext('Fleet policy')?></dt><dd><?=isset($st['policy_bundle']['version']) ? sprintf(gettext('Version %d'), (int)$st['policy_bundle']['version']) : gettext('None')?><?php if (!empty($st['breakglass'])): ?> <?=fs_badge('warn', gettext('Lock suspended'))?><?php endif; ?></dd>
		</dl>
	</section>
	<section class="fs-fleet-block" aria-labelledby="fleet-title">
		<h2 id="fleet-title" class="fs-fleet-section-title"><?=gettext('In the fleet')?></h2>
		<dl class="fs-fleet-facts fs-fleet-facts--wide">
			<dt><?=gettext('Access')?></dt><dd><?=($box['role'] === 'managed') ? gettext('Managed') : gettext('Monitor only')?></dd>
			<dt><?=gettext('Tunnel address')?></dt><dd class="fs-mono"><?=htmlspecialchars($box['overlay'])?></dd>
			<dt><?=gettext('Joined')?></dt><dd><?=$when($box['joined'])?></dd>
			<dt><?=gettext('Last seen')?></dt><dd><?=$when($box['last_seen'])?></dd>
			<dt><?=gettext('Box ID')?></dt><dd class="fs-mono"><?=htmlspecialchars($box['node_id'])?></dd>
		</dl>
	</section>
</div>

<section class="fs-fleet-block" aria-labelledby="events-title">
	<h2 id="events-title" class="fs-fleet-section-title"><?=gettext('Recent events')?></h2>
<?php if (empty($events)): ?>
	<p class="fs-fleet-lead"><?=gettext('Nothing has happened to this firewall yet.')?></p>
<?php else: ?>
	<ol class="fs-fleet-events">
<?php foreach ($events as $ev): ?>
<?php list($what, $more) = fleet_event_text($box['node_id'], $ev['action'], $ev['detail']); ?>
		<li><time class="fs-muted" datetime="<?=date('c', (int)$ev['time'])?>"><?=htmlspecialchars(date('Y-m-d H:i', (int)$ev['time']))?></time>
			<span><?=htmlspecialchars($what)?><?php if ($more !== ''): ?> <span class="fs-muted"><?=htmlspecialchars($more)?></span><?php endif; ?></span>
			<span class="fs-muted"><?=($ev['who'] === 'poll') ? '' : htmlspecialchars($ev['who'])?></span></li>
<?php endforeach; ?>
	</ol>
<?php endif; ?>
</section>
<?php include('foot.inc');
