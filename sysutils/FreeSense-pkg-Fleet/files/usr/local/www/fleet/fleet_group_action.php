<?php
/*
 * fleet_group_action.php
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
 * An action on a whole group, with a review first: which firewalls it
 * touches, in which order, which it leaves out and why, and how long it
 * may take. Starting it creates a group operation and hands it to
 * freesense-fleet-run; the Activity page follows it.
 * Actions: reboot and update (one firewall at a time, stops at the first
 * failure; an update waits until the firewall has stayed healthy).
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$who = (string)($_SESSION['Username'] ?? 'admin');
$group = fleet_group_get((int)($_REQUEST['group'] ?? 0));
$action = (string)($_REQUEST['action'] ?? '');
if (($group === null) || !in_array($action, array('reboot', 'update'), true) || !fleet_ctl_settings()['enable']) {
	header('Location: /fleet/fleet_dashboard.php');
	exit;
}

/* The page title says what is reviewed: "Reboot Canary". */
$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), sprintf(($action === 'update') ? gettext('Update %s') : gettext('Reboot %s'), $group['name']));
list($boxes, $plan, $infos) = fleet_group_plan($group, $action);
$input_errors = array();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	/* What was reviewed must still be what runs: the same firewalls, in the same order. */
	$reviewed = (string)($_POST['plan'] ?? '');
	if ($reviewed !== hash('sha256', implode(',', array_column($plan['go'], 'node_id')))) {
		$input_errors[] = gettext('The group changed while you were reviewing it. Check the list again.');
	} elseif (empty($plan['go'])) {
		$input_errors[] = ($action === 'update') ? gettext('No firewall in this group can be updated now.') : gettext('No firewall in this group can be rebooted now.');
	} else {
		$op = fleet_group_op_launch($group, $action, $plan, $who);
		header('Location: /fleet/fleet_activity.php?op=' . (int)$op);
		exit;
	}
}

include('head.inc');
if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
$tab_array = array(
	array(gettext('Dashboard'), true, '/fleet/fleet_dashboard.php'),
	array(gettext('Activity'), false, '/fleet/fleet_activity.php'),
	array(gettext('Updates'), false, '/fleet/fleet_updates.php'),
	array(gettext('Schedules'), false, '/fleet/fleet_schedules.php'),
	array(gettext('Backups'), false, '/fleet/fleet_backups.php'),
	array(gettext('Policies'), false, '/fleet/fleet_policies.php'),
	array(gettext('Templates'), false, '/fleet/fleet_templates.php'),
	array(gettext('Firewalls'), false, '/fleet/fleet.php'),
	array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
);
display_top_tabs($tab_array);
$n = count($plan['go']);
?>
<link rel="stylesheet" href="/fleet/assets/fleet.css?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet.css')?>">
<p><a class="fs-fleet-back" href="/fleet/fleet_dashboard.php?group=<?=(int)$group['id']?>"><i class="fa-solid fa-arrow-left" aria-hidden="true"></i><?=htmlspecialchars($group['name'])?></a></p>
<div class="panel panel-default fs-fleet-review" role="region" aria-labelledby="review-title">
	<div class="panel-heading"><h2 id="review-title" class="panel-title"><?=sprintf(htmlspecialchars(($action === 'update') ? gettext('Update the %s group?') : gettext('Reboot the %s group?')), htmlspecialchars($group['name']))?></h2></div>
	<div class="panel-body fs-fleet-pad">
<?php if ($n === 0): ?>
		<p class="fs-fleet-lead"><?=gettext('No firewall in this group can be changed now. The list below says why.')?></p>
<?php elseif ($action === 'update'): ?>
		<p class="fs-fleet-lead"><?=sprintf(gettext('%1$d firewalls update one at a time: the next starts only when the one before runs the new version and has stayed healthy for %2$d minutes. If one rolls back or fails, the rest are left alone. Expect about %3$s in all.'), $n, fleet_opt('update_healthy'), htmlspecialchars(fleet_op_duration((600 + 60 * fleet_opt('update_healthy')) * $n)))?></p>
<?php else: ?>
		<p class="fs-fleet-lead"><?=sprintf(gettext('%1$d firewalls restart one at a time: the next starts only when the one before is back online. If one does not come back within %3$d minutes, the rest are left alone. Expect about %2$s in all.'), $n, htmlspecialchars(fleet_op_duration(120 * $n)), fleet_opt('reboot_timeout'))?></p>
<?php endif; ?>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Order')?></th><th><?=gettext('Firewall')?></th><th><?=gettext('Version')?></th><th><?=gettext('What happens')?></th></tr></thead>
		<tbody>
<?php foreach ($plan['go'] as $i => $b): $st = json_decode((string)$b['status'], true) ?: array(); ?>
		<tr><td class="fs-mono"><?=$i + 1?></td><td><?=htmlspecialchars((string)$b['label'])?></td>
			<td><?=htmlspecialchars((string)($st['version'] ?? '-'))?></td><td><?=($action === 'update') ? fs_badge('info', sprintf(gettext('Updates to %s'), fleet_version_number((string)($infos[$b['node_id']]['latest'] ?? '')))) : fs_badge('info', gettext('Reboots'))?></td></tr>
<?php endforeach; ?>
<?php foreach ($plan['skip'] as list($b, $why)): $st = json_decode((string)$b['status'], true) ?: array(); ?>
		<tr><td class="fs-muted">-</td><td><?=htmlspecialchars((string)$b['label'])?></td><td class="fs-muted"><?=htmlspecialchars((string)($st['version'] ?? '-'))?></td>
			<td><?=fs_badge('neutral', gettext('Left alone'))?> <span class="fs-muted"><?=htmlspecialchars(gettext($why))?></span></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
	<div class="panel-footer">
		<form method="post" class="fs-fleet-review-actions">
			<input type="hidden" name="group" value="<?=(int)$group['id']?>"/>
			<input type="hidden" name="action" value="<?=htmlspecialchars($action)?>"/>
			<input type="hidden" name="plan" value="<?=hash('sha256', implode(',', array_column($plan['go'], 'node_id')))?>"/>
			<button class="btn btn-primary" type="submit"<?=($n === 0) ? ' disabled' : ''?>><i class="fa-solid <?=($action === 'update') ? 'fa-download' : 'fa-power-off'?> icon-embed-btn" aria-hidden="true"></i><?php if ($n === 0): ?><?=($action === 'update') ? gettext('Nothing to update') : gettext('Nothing to reboot')?><?php else: ?><?=($action === 'update') ? sprintf(ngettext('Update %d firewall', 'Update %d firewalls one at a time', $n), $n) : sprintf(ngettext('Reboot %d firewall', 'Reboot %d firewalls one at a time', $n), $n)?><?php endif; ?></button>
			<a class="btn btn-outline-secondary" href="/fleet/fleet_dashboard.php?group=<?=(int)$group['id']?>"><?=gettext('Cancel')?></a>
		</form>
	</div>
</div>
<?php include('foot.inc');
