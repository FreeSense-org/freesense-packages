<?php
/*
 * fleet_alerts.php
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
 * Alerts (a view of Activity): what happened that someone should know,
 * where each alert was sent, and the channels that send them (e-mail,
 * webhook, Slack or Teams, Telegram, ntfy, Gotify) with a test button
 * and an optional daily report. Adding and changing a channel happen in
 * a modal. The logic is fleet_alerts.inc.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$who = (string)($_SESSION['Username'] ?? 'admin');
$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$manage = isAllowedPage('fleet/fleet.php');
$view = fs_view_param(array('alerts', 'channels'), 'alerts');
$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Activity'), ($view === 'channels') ? gettext('Alert channels') : gettext('Alerts'));
$input_errors = array();
$savemsg = null;
$reopen = null;

if ($ready && $manage && ($_SERVER['REQUEST_METHOD'] === 'POST')) {
	$view = 'channels';
	try {
		if (isset($_POST['save'])) {
			$id = ((string)($_POST['id'] ?? '') === '') ? null : (int)$_POST['id'];
			if (($id !== null) && (fleet_alert_channel($id) === null)) {
				throw new InvalidArgumentException(gettext('That channel no longer exists.'));
			}
			fleet_alert_channel_save($id, $_POST, $who);
			$savemsg = gettext('Channel saved. Send a test to check it.');
		} elseif (isset($_POST['test'])) {
			$problem = fleet_alert_test((int)$_POST['test'], $who);
			if ($problem !== null) {
				throw new RuntimeException(sprintf(gettext('The test was not delivered: %s'), $problem));
			}
			$savemsg = gettext('Test sent. Check that it arrived.');
		} elseif (isset($_POST['delete'])) {
			fleet_alert_channel_delete((int)$_POST['delete'], $who);
			$savemsg = gettext('Channel deleted.');
		}
	} catch (InvalidArgumentException | RuntimeException $e) {
		$input_errors[] = $e->getMessage();
		if (isset($_POST['save'])) {
			/* Everything but the secrets comes back into the form. */
			$reopen = array_intersect_key($_POST, array_flip(array('id', 'name', 'type', 'min_severity', 'report_hour', 'cfg_telegram_chat', 'cfg_webhook_pin',
			    'cfg_ntfy_pin', 'cfg_gotify_pin')));
			$reopen['events[]'] = array_values((array)($_POST['events'] ?? array()));
			$reopen['enabled'] = !empty($_POST['enabled']);
		}
	}
}
if ($ready && $manage && ($view === 'channels')) {
	fs_page_action(gettext('Add channel'), '#', 'fa-plus', 'primary', array('data-fs-modal' => '#chan-modal', 'data-fs-modal-title' => gettext('Add an alert channel'),
	    'data-fs-fill' => json_encode(array('id' => '', 'type' => 'email', 'events[]' => array('offline', 'op_failed', 'backup_failed', 'breakglass', 'policy', 'policy_fail', 'copies', 'ha_problem', 'join_refused'),
	    'min_severity' => 'info', 'enabled' => true, 'report_hour' => ''))));
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
		array(gettext('Activity'), true, '/fleet/fleet_activity.php'),
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
}
if (!$ready): ?>
<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller')?></strong></div>
<?php include('foot.inc'); exit; endif;

echo fleet_activity_nav($view);
$channels = fleet_alert_channels();
$sev_badge = array('info' => array('info', gettext('Info')), 'warning' => array('warn', gettext('Warning')), 'critical' => array('block', gettext('Critical')));
$events = array_filter(FLEET_ALERT_EVENTS, function ($k) { return $k !== 'test'; }, ARRAY_FILTER_USE_KEY);
$event_labels = array_map(function ($e) { return $e[0]; }, $events);
?>

<?php if ($view === 'alerts'):
	$f = fleet_list_filters($_GET, array('q' => null, 'event' => $event_labels, 'severity' => array('info' => 'Info', 'warning' => 'Warning', 'critical' => 'Critical')));
	list($rows, $pg) = fleet_alerts_find($f, (int)($_GET['page'] ?? 1));
	$names = array_column($channels, 'name', 'id');
?>
<?php if (empty($channels)): ?>
<div class="fs-fleet-callout"><i class="fa-solid fa-bell-slash" aria-hidden="true"></i>
	<div><strong><?=gettext('Alerts are recorded, but nobody is told yet')?></strong>
		<p class="mb-0"><?=gettext('Add a channel to have them sent by e-mail, Slack or Teams, Telegram, ntfy, Gotify or a webhook.')?> <a href="?view=channels"><?=gettext('Add a channel')?></a></p></div></div>
<?php endif; ?>
<div class="panel panel-default">
	<div class="panel-heading"><?=fleet_list_filterbar(array(), $f, array('event' => array(gettext('Any alert'), $event_labels),
	    'severity' => array(gettext('Any severity'), array('info' => 'Info', 'warning' => 'Warning', 'critical' => 'Critical'))), gettext('Search alerts'), gettext('Firewall or text'))?></div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('When')?></th><th><?=gettext('Alert')?></th><th><?=gettext('Severity')?></th><th><?=gettext('Sent to')?></th></tr></thead>
		<tbody>
<?php if (empty($rows)): ?>
		<tr><td colspan="4" class="fs-muted"><?=empty($f) ? gettext('No alerts yet. A quiet fleet is a good fleet.') : gettext('No alert matches these filters.')?></td></tr>
<?php endif; ?>
<?php foreach ($rows as $a): list($sb, $sl) = $sev_badge[$a['severity']] ?? array('neutral', $a['severity']); $sent = json_decode((string)$a['sent'], true) ?: array(); ?>
		<tr><td class="small text-nowrap"><?=htmlspecialchars(date('Y-m-d H:i', (int)$a['time']))?><?=((int)$a['repeats'] > 0) ? '<div class="fs-muted">' . htmlspecialchars(sprintf(gettext('and %d more within 15 min'), (int)$a['repeats'])) . '</div>' : ''?></td>
			<td><strong><?=htmlspecialchars(gettext(FLEET_ALERT_EVENTS[$a['event']][0] ?? $a['event']))?></strong><?=($a['label'] !== null) ? ': <a href="/fleet/fleet_box.php?id=' . urlencode($a['node_id']) . '">' . htmlspecialchars($a['label']) . '</a>' : ''?>
				<div class="fs-muted small"><?=htmlspecialchars(mb_strimwidth((string)$a['text'], 0, 200, '...'))?></div></td>
			<td><?=fs_badge($sb, $sl)?></td>
			<td class="small"><?php
				if (empty($sent)) {
					echo '<span class="fs-muted">' . (empty($channels) ? gettext('No channels') : (((int)$a['done'] === 1) ? gettext('No channel wants it') : gettext('Waiting'))) . '</span>';
				}
				foreach ($sent as $cid => $res) {
					echo '<div>' . htmlspecialchars($names[$cid] ?? gettext('Deleted channel')) . ' ' . (($res === 'ok') ? fs_badge('pass', gettext('Sent')) : fs_badge('block', gettext('Failed'), $res)) . '</div>';
				}
				if (!empty($sent) && ((int)$a['done'] === 0) && ((int)$a['tries'] < FLEET_ALERT_TRIES)) {
					echo '<div class="fs-muted">' . gettext('Tried again next minute') . '</div>';
				} ?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
	<div class="panel-footer"><?=fleet_list_pager($pg, array(), $f)?></div>
</div>

<?php else: /* channels */ ?>
<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-bell" aria-hidden="true"></i></span>
		<div><h2><?=gettext('Alert channels')?></h2><p><?=gettext('Where alerts go. Each channel picks the alerts it wants and the lowest severity it is told about, and can send a daily report. Tokens and webhook addresses are stored encrypted and never shown again.')?></p></div></header>
<?php if (empty($channels)): ?>
	<p class="fs-fleet-hint"><?=gettext('No channels yet. Start with e-mail (it uses System > Advanced > Notifications) or a chat you already use.')?></p>
<?php else: ?>
	<div class="fs-fleet-rule-grid">
<?php foreach ($channels as $ch): list($tname, $ticon) = FLEET_ALERT_TYPES[$ch['type']]; ?>
		<div class="fs-fleet-rcard<?=empty($ch['enabled']) ? ' fs-fleet-off' : ''?>">
			<div class="fs-fleet-rcard-head">
				<span class="fs-fleet-rcard-icon"><i class="fa-solid <?=$ticon?>" aria-hidden="true"></i></span>
				<div class="fs-fleet-rcard-title"><strong><?=htmlspecialchars($ch['name'])?></strong>
					<span class="fs-muted small"><?=htmlspecialchars(gettext($tname))?><?=empty($ch['enabled']) ? ' (' . gettext('off') . ')' : ''?></span></div>
			</div>
			<p class="small mb-1"><?=htmlspecialchars(sprintf(ngettext('%d kind of alert', '%d kinds of alert', count($ch['events'])), count($ch['events'])))?>,
				<?=htmlspecialchars(sprintf(gettext('%s and above'), strtolower($sev_badge[$ch['min_severity']][1] ?? 'info')))?>.
				<?=($ch['report_hour'] !== null) ? htmlspecialchars(sprintf(gettext('Daily report at %02d:00.'), (int)$ch['report_hour'])) : ''?></p>
<?php if ($manage): ?>
			<div class="fs-fleet-rcard-actions">
				<form method="post" class="d-inline"><button class="btn btn-sm btn-link" name="test" value="<?=(int)$ch['id']?>"><?=gettext('Send test')?></button></form>
				<button type="button" class="btn btn-sm btn-link" data-fs-modal="#chan-modal" data-fs-modal-title="<?=htmlspecialchars(sprintf(gettext('Change %s'), $ch['name']))?>"
				    data-fs-fill="<?=htmlspecialchars(json_encode(array('id' => (string)$ch['id'], 'name' => $ch['name'], 'type' => $ch['type'], 'events[]' => $ch['events'],
				    'min_severity' => $ch['min_severity'], 'enabled' => !empty($ch['enabled']), 'report_hour' => ($ch['report_hour'] === null) ? '' : (string)$ch['report_hour'],
				    'cfg_telegram_chat' => (string)($ch['config']['chat'] ?? ''), 'cfg_' . $ch['type'] . '_pin' => (string)($ch['config']['pin'] ?? ''))))?>"><?=gettext('Change')?></button>
				<form method="post" class="d-inline"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="delete" value="<?=(int)$ch['id']?>"><?=gettext('Delete')?></button></form>
			</div>
<?php endif; ?>
		</div>
<?php endforeach; ?>
	</div>
<?php endif; ?>
</section>

<?php if ($manage):
	fs_modal_form_begin('chan-modal', gettext('Add an alert channel'), '/fleet/fleet_alerts.php?view=channels', array('id' => ''), $reopen);
	/* The reopened dialog covers the page's error box: repeat the error in it. */
	if (($reopen !== null) && !empty($input_errors)):
?>
	<div class="alert alert-danger" role="alert"><?=htmlspecialchars(implode(' ', $input_errors))?></div>
<?php endif; ?>
	<div class="row g-3 mb-3">
		<div class="col-sm-7"><label class="form-label" for="cname"><?=gettext('Name')?></label>
			<input class="form-control" id="cname" name="name" maxlength="60" required placeholder="<?=gettext('NOC team')?>"/></div>
		<div class="col-sm-5"><label class="form-label" for="ctype"><?=gettext('Sends by')?></label>
			<select class="form-select" id="ctype" name="type" data-fleet-chan-type>
<?php foreach (FLEET_ALERT_TYPES as $t => $def): ?>
				<option value="<?=$t?>"><?=htmlspecialchars(gettext($def[0]))?></option>
<?php endforeach; ?>
			</select></div>
	</div>
<?php foreach (FLEET_ALERT_TYPES as $t => $def): ?>
	<div class="mb-3" data-fleet-chan-fields="<?=$t?>">
<?php if ($t === 'email'): ?>
		<p class="fs-fleet-hint mb-0"><?=gettext('Sent with the e-mail settings in System > Advanced > Notifications, to the address there.')?></p>
<?php endif; ?>
<?php foreach ($def[2] as $field => $label):
	$secret = in_array($field, FLEET_ALERT_SECRETS, true);
	/* An address is not a password: a password field makes browsers offer to save it. Tokens stay masked but are never saved by the browser. */
	$attrs = ($field === 'url') ? 'type="url" autocomplete="off" spellcheck="false" inputmode="url"' :
	    (($field === 'token') ? 'type="password" autocomplete="new-password"' : 'type="text" autocomplete="off" spellcheck="false"');
?>
		<label class="form-label" for="c<?=$t . $field?>"><?=htmlspecialchars(gettext($label))?></label>
		<input class="form-control mb-2" id="c<?=$t . $field?>" name="cfg_<?=$t?>_<?=$field?>" <?=$attrs?> disabled data-fleet-secret-hint="<?=$secret ? '1' : '0'?>"
		    data-fleet-optional="<?=in_array($field, FLEET_ALERT_OPTIONAL, true) ? '1' : '0'?>"/>
<?php if ($field === 'pin'): ?>
		<p class="form-text mt-0"><?=htmlspecialchars(gettext('For a receiver with a self-signed or private-CA certificate. Get it with: openssl s_client -connect host:port </dev/null | openssl x509 -noout -fingerprint -sha256'))?></p>
<?php endif; ?>
<?php endforeach; ?>
	</div>
<?php endforeach; ?>
	<p class="form-text fs-fleet-keep-hint"><?=gettext('Leave a token or address empty to keep the stored one.')?></p>
	<fieldset class="mb-3"><legend class="form-label"><?=gettext('Alerts it gets')?></legend>
		<div class="fs-fleet-checkgrid">
<?php foreach ($events as $e => list($label, $sev)): ?>
			<label class="form-check"><input class="form-check-input" type="checkbox" name="events[]" value="<?=$e?>"/> <span class="form-check-label"><?=htmlspecialchars(gettext($label))?></span></label>
<?php endforeach; ?>
		</div></fieldset>
	<div class="row g-3 align-items-end">
		<div class="col-sm-4"><label class="form-label" for="csev"><?=gettext('At least')?></label>
			<select class="form-select" id="csev" name="min_severity">
				<option value="info"><?=gettext('Info')?></option><option value="warning"><?=gettext('Warning')?></option><option value="critical"><?=gettext('Critical')?></option>
			</select></div>
		<div class="col-sm-4"><label class="form-label" for="crep"><?=gettext('Daily report')?></label>
			<select class="form-select" id="crep" name="report_hour"><option value=""><?=gettext('None')?></option>
<?php for ($h = 0; $h < 24; $h++): ?>
				<option value="<?=$h?>"><?=sprintf('%02d:00', $h)?></option>
<?php endfor; ?>
			</select></div>
		<div class="col-sm-4"><label class="form-check"><input class="form-check-input" type="checkbox" name="enabled" value="1" checked/> <span class="form-check-label"><?=gettext('On')?></span></label></div>
	</div>
<?php
	fs_modal_form_end(gettext('Save channel'), 'save', '1', 'fa-floppy-disk');
endif; ?>
<script src="/fleet/assets/fleet-alerts.js?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet-alerts.js')?>"></script>
<?php endif; ?>
<?php include('foot.inc');
