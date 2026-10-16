<?php
/*
 * fleet_factory.php
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
 * Deployment Factory: batches of new firewalls. The list (with how many
 * joined), a new batch (settings, rows, preview, then generate), and a
 * batch (rows and their state, the bundle, revoke). The logic is
 * fleet_factory.inc.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$who = (string)($_SESSION['Username'] ?? 'admin');
$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$manage = isAllowedPage('fleet/fleet.php');

/* The bundle download: the file as it is (already encrypted). */
if ($ready && $manage && isset($_GET['download'])) {
	$path = fleet_batch_bundle((int)$_GET['download']);
	$b = fleet_batch_get((int)$_GET['download']);
	if (($path !== null) && ($b !== null)) {
		fleet_audit($who, 'factory', "Batch {$b['name']}: bundle downloaded");
		header('Content-Type: application/octet-stream');
		header('Content-Disposition: attachment; filename="fleet-batch-' . preg_replace('/[^A-Za-z0-9_-]+/', '-', $b['name']) . '.tar.gz.enc"');
		header('Content-Length: ' . filesize($path));
		readfile($path);
		exit;
	}
}

$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Firewalls'), gettext('Deployment Factory'));
$input_errors = array();
$savemsg = null;
$view = fs_view_param(array('list', 'new', 'batch'), 'list');
$plan = null;
$form = array('name' => '', 'mode' => 'attended', 'role' => 'managed', 'days' => '14', 'group' => '0', 'auto_approve' => '', 'rows' => '');

if ($ready && $manage && ($_SERVER['REQUEST_METHOD'] === 'POST')) {
	$form = array_merge($form, array_intersect_key($_POST, $form));
	try {
		if (isset($_POST['preview']) || isset($_POST['generate'])) {
			$view = 'new';
			$settings = fleet_factory_settings($_POST);
			$rows = fleet_factory_rows((string)($_POST['rows'] ?? ''));
			if (empty($rows)) {
				throw new InvalidArgumentException(gettext('Add at least one row.'));
			}
			list($plan) = fleet_factory_plan($rows, $settings, fleet_factory_naming($settings['group']), fleet_factory_counters(), fleet_naming_taken());
			if (isset($_POST['generate'])) {
				if ((string)($_POST['passphrase'] ?? '') !== (string)($_POST['passphrase_again'] ?? '')) {
					throw new InvalidArgumentException(gettext('The two passphrases are not the same.'));
				}
				$s = fleet_ctl_settings();
				list($bid) = fleet_factory_generate($settings, (string)$_POST['rows'], (string)$_POST['passphrase'], $who, fleet_hostport($s['public_host'], $s['enroll_port']));
				header('Location: /fleet/fleet_factory.php?view=batch&made=1&id=' . (int)$bid);
				exit;
			}
		} elseif (isset($_POST['revoke'])) {
			$view = 'batch';
			$_GET['id'] = (int)$_POST['revoke'];
			$n = fleet_batch_revoke((int)$_POST['revoke'], $who, isset($_POST['token']) ? (string)$_POST['token'] : null);
			$savemsg = sprintf(ngettext('%d invitation revoked.', '%d invitations revoked.', $n), $n);
		}
	} catch (InvalidArgumentException | RuntimeException $e) {
		$input_errors[] = $e->getMessage();
	}
}
if ($ready && $manage && ($view === 'list')) {
	fs_page_action(gettext('New batch'), '/fleet/fleet_factory.php?view=new', 'fa-plus', 'primary');
}

include('head.inc');
if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if (isset($_GET['made'])) {
	$savemsg = gettext('Batch made. Download the bundle now: it is the only copy of the seeds and keys, and it is removed when the batch is revoked.');
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
		array(gettext('Templates'), false, '/fleet/fleet_templates.php'),
		array(gettext('Users'), false, '/fleet/fleet_users.php'),
		array(gettext('Firewalls'), true, '/fleet/fleet.php'),
		array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
	);
	display_top_tabs($tab_array);
	echo fleet_firewalls_nav('factory', $ready ? (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn() : 0);
}
if (!$ready): ?>
<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller')?></strong></div>
<?php include('foot.inc'); exit; endif;

$now = time();
$state_badge = function (string $s) {
	return array('joined' => fs_badge('pass', gettext('Joined')), 'waiting' => fs_badge('info', gettext('Waiting')), 'expired' => fs_badge('neutral', gettext('Expired')),
	    'revoked' => fs_badge('neutral', gettext('Revoked')), 'burned' => fs_badge('block', gettext('Burned')))[$s] ?? htmlspecialchars($s);
};
$mode_icons = array('attended' => 'fa-keyboard', 'pin' => 'fa-hashtag', 'unattended' => 'fa-robot');
?>

<?php if ($view === 'list'):
	$batches = fleet_batches_all();
?>
<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-industry" aria-hidden="true"></i></span>
		<div><h2><?=gettext('Deployment Factory')?></h2><p><?=gettext('Prepare many new firewalls at once: one row per firewall, named by its group, each with its own invitation and a seed file for a USB stick. Track them until they have all joined.')?></p></div></header>
<?php if (empty($batches)): ?>
	<p class="fs-fleet-hint"><?=gettext('No batches yet.')?> <a href="?view=new"><?=gettext('Make the first batch')?></a></p>
<?php else: ?>
	<div class="fs-fleet-rule-grid">
<?php foreach ($batches as $b):
	$rows = fleet_batch_rows((int)$b['id']);
	$c = array('joined' => 0, 'waiting' => 0, 'expired' => 0, 'revoked' => 0, 'burned' => 0);
	foreach ($rows as $r) {
		$c[fleet_batch_row_state($r, $now)]++;
	}
	$pct = count($rows) ? (int)floor(100 * $c['joined'] / count($rows)) : 0; ?>
		<a class="fs-fleet-rcard fs-fleet-starter" href="?view=batch&amp;id=<?=(int)$b['id']?>">
			<div class="fs-fleet-rcard-head">
				<span class="fs-fleet-rcard-icon"><i class="fa-solid <?=$mode_icons[$b['settings']['mode']] ?? 'fa-box'?>" aria-hidden="true"></i></span>
				<div class="fs-fleet-rcard-title"><strong><?=htmlspecialchars($b['name'])?></strong>
					<span class="fs-muted small"><?=htmlspecialchars(date('Y-m-d', (int)$b['created']) . ' · ' . $b['who'])?></span></div>
				<i class="fa-solid fa-chevron-right fs-muted" aria-hidden="true"></i>
			</div>
			<div class="fs-fleet-batch-bar" role="img" aria-label="<?=htmlspecialchars(sprintf(gettext('%1$d of %2$d joined'), $c['joined'], count($rows)))?>"><span style="width: <?=$pct?>%"></span></div>
			<div class="small"><strong><?=sprintf(gettext('%1$d of %2$d joined'), $c['joined'], count($rows))?></strong>
				<?=($c['waiting'] > 0) ? ' · ' . sprintf(gettext('%d waiting'), $c['waiting']) : ''?><?=($c['expired'] + $c['revoked'] + $c['burned'] > 0) ? ' · ' . sprintf(gettext('%d no longer valid'), $c['expired'] + $c['revoked'] + $c['burned']) : ''?></div>
		</a>
<?php endforeach; ?>
	</div>
<?php endif; ?>
</section>

<?php elseif ($view === 'batch'):
	$b = fleet_batch_get((int)($_GET['id'] ?? 0));
	if ($b === null): ?>
<div class="fs-fleet-empty"><strong><?=gettext('That batch no longer exists.')?></strong> <a href="?"><?=gettext('All batches')?></a></div>
<?php else:
	$rows = fleet_batch_rows((int)$b['id']);
	$bundle = fleet_batch_bundle((int)$b['id']);
	$waiting = count(array_filter($rows, function ($r) use ($now) { return fleet_batch_row_state($r, $now) === 'waiting'; }));
?>
<p><a class="fs-fleet-back" href="?"><i class="fa-solid fa-arrow-left" aria-hidden="true"></i> <?=gettext('All batches')?></a></p>
<div class="panel panel-default">
	<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title"><?=htmlspecialchars($b['name'])?></h2>
		<span>
<?php if ($bundle !== null && $manage): ?>
			<a class="btn btn-sm btn-primary" href="?download=<?=(int)$b['id']?>"><i class="fa-solid fa-download icon-embed-btn" aria-hidden="true"></i><?=gettext('Download bundle')?></a>
<?php endif; ?>
<?php if ($manage && ($waiting > 0)): ?>
			<form method="post" class="d-inline"><button class="btn btn-sm btn-link fs-fleet-danger-link" name="revoke" value="<?=(int)$b['id']?>"><?=sprintf(ngettext('Revoke %d waiting', 'Revoke %d waiting', $waiting), $waiting)?></button></form>
<?php endif; ?>
		</span></div>
	<div class="panel-body fs-fleet-pad">
		<p class="fs-fleet-lead mb-2"><i class="fa-solid <?=$mode_icons[$b['settings']['mode']] ?? 'fa-box'?>" aria-hidden="true"></i> <?=htmlspecialchars(gettext(FLEET_FACTORY_MODES[$b['settings']['mode']] ?? ''))?>.
			<?=htmlspecialchars(sprintf(gettext('Access: %1$s. Invitations last %2$d days.'), ($b['settings']['role'] === 'managed') ? gettext('managed') : gettext('monitor only'), (int)$b['settings']['days']))?>
			<?=!empty($b['settings']['auto_approve']) ? htmlspecialchars(gettext('Bound firewalls are approved by themselves.')) : ''?></p>
<?php if ($bundle !== null): ?>
		<details class="small"><summary><?=gettext('How to open the bundle')?></summary>
			<p class="mb-1"><?=gettext('It is encrypted with the batch passphrase. On any computer with OpenSSL:')?></p>
			<code class="d-block fs-mono">openssl enc -d -aes-256-cbc -pbkdf2 -iter <?=FLEET_FACTORY_ITER?> -in fleet-batch.tar.gz.enc -out fleet-batch.tar.gz &amp;&amp; tar xzf fleet-batch.tar.gz</code>
			<p class="mt-1 mb-0"><?=gettext('Each firewall has a folder with its fleet-join.conf (copy it to a FAT USB stick) and a README. join-cards.html prints a card per firewall; key-sheet.html holds the keys or PINs: keep it apart.')?></p>
		</details>
<?php else: ?>
		<p class="fs-muted small mb-0"><?=gettext('The bundle is no longer kept.')?></p>
<?php endif; ?>
	</div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th>#</th><th><?=gettext('Firewall')?></th><th><?=gettext('Name')?></th><th><?=gettext('Bound to')?></th><th><?=gettext('State')?></th><th class="text-end"><span class="visually-hidden"><?=gettext('Actions')?></span></th></tr></thead>
		<tbody>
<?php foreach ($rows as $r): $st = fleet_batch_row_state($r, $now); ?>
		<tr><td class="fs-muted"><?=(int)$r['n']?></td>
			<td><?=($r['box'] !== null) ? '<a href="/fleet/fleet_box.php?id=' . urlencode($r['box']) . '">' . htmlspecialchars($r['label']) . '</a>' : htmlspecialchars($r['label'])?>
				<?=($r['site'] !== '') ? '<div class="fs-muted small">' . htmlspecialchars($r['site']) . '</div>' : ''?></td>
			<td class="fs-mono small"><?=htmlspecialchars(trim($r['hostname'] . (($r['hostname'] !== '' && $r['domain'] !== '') ? '.' . $r['domain'] : ''))) ?: '<span class="fs-muted">-</span>'?></td>
			<td class="small"><?=htmlspecialchars(trim(($r['serial'] !== '' ? $r['serial'] : '') . ($r['instance_id'] !== '' ? ' ' . $r['instance_id'] : ''))) ?: '<span class="fs-muted">-</span>'?></td>
			<td><?=$state_badge($st)?></td>
			<td class="text-end"><?php if ($manage && ($st === 'waiting')): ?><form method="post" class="d-inline"><input type="hidden" name="token" value="<?=htmlspecialchars($r['token_id'])?>"/><button class="btn btn-sm btn-link fs-fleet-danger-link" name="revoke" value="<?=(int)$b['id']?>"><?=gettext('Revoke')?></button></form><?php endif; ?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
</div>
<?php endif; ?>

<?php else: /* new */
	$groups = fleet_groups_all();
?>
<p><a class="fs-fleet-back" href="?"><i class="fa-solid fa-arrow-left" aria-hidden="true"></i> <?=gettext('All batches')?></a></p>
<form method="post" action="?view=new" autocomplete="off">
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('New batch')?></h2></div>
		<div class="panel-body fs-fleet-pad">
			<div class="row g-3">
				<div class="col-md-4"><label class="form-label" for="bname"><?=gettext('Name')?></label>
					<input class="form-control" id="bname" name="name" maxlength="60" required value="<?=htmlspecialchars($form['name'])?>" placeholder="<?=gettext('Retail rollout spring')?>"/></div>
				<div class="col-md-4"><label class="form-label" for="bgroup"><?=gettext('Group (names them)')?></label>
					<select class="form-select" id="bgroup" name="group">
						<option value="0"><?=gettext('None')?></option>
<?php foreach ($groups as $ng): ?>
						<option value="<?=(int)$ng['id']?>"<?=((int)$form['group'] === (int)$ng['id']) ? ' selected' : ''?>><?=htmlspecialchars($ng['name'] . ((($ng['naming_pattern'] ?? '') !== '') ? ' (' . $ng['naming_pattern'] . (($ng['naming_domain'] ?? '') !== '' ? '.' . $ng['naming_domain'] : '') . ')' : ''))?></option>
<?php endforeach; ?>
					</select></div>
				<div class="col-md-2"><label class="form-label" for="brole"><?=gettext('Access')?></label>
					<select class="form-select" id="brole" name="role">
						<option value="managed"<?=($form['role'] === 'managed') ? ' selected' : ''?>><?=gettext('Managed')?></option>
						<option value="monitor"<?=($form['role'] === 'monitor') ? ' selected' : ''?>><?=gettext('Monitor only')?></option>
					</select></div>
				<div class="col-md-2"><label class="form-label" for="bdays"><?=gettext('Valid for (days)')?></label>
					<input class="form-control" type="number" id="bdays" name="days" min="1" max="30" value="<?=(int)$form['days']?>"/></div>
			</div>
			<fieldset class="mt-3"><legend class="form-label"><?=gettext('How the key reaches each firewall')?></legend>
				<div class="fs-fleet-modecards">
<?php foreach (FLEET_FACTORY_MODES as $m => $text): list($head, $tail) = explode(': ', $text, 2); ?>
					<label class="fs-fleet-modecard"><input type="radio" name="mode" value="<?=$m?>"<?=($form['mode'] === $m) ? ' checked' : ''?>/>
						<span><i class="fa-solid <?=$mode_icons[$m]?>" aria-hidden="true"></i> <strong><?=htmlspecialchars(gettext($head))?></strong><small><?=htmlspecialchars(gettext(ucfirst($tail)))?></small></span></label>
<?php endforeach; ?>
				</div>
				<label class="form-check mt-2"><input class="form-check-input" type="checkbox" name="auto_approve" value="1"<?=!empty($form['auto_approve']) ? ' checked' : ''?>/>
					<span class="form-check-label"><?=gettext('Unattended: approve a firewall by itself when its serial or instance id matches (otherwise you approve each one)')?></span></label>
			</fieldset>
		</div>
	</div>
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('Firewalls')?></h2></div>
		<div class="panel-body fs-fleet-pad">
			<label class="form-label" for="brows"><?=gettext('One row per firewall: site, label, serial, instance id, hostname')?></label>
			<textarea class="form-control fs-mono" id="brows" name="rows" rows="8" placeholder="site,label,serial,instance_id,hostname&#10;cph,Copenhagen shop 1,PT-1234,,&#10;aar,Aarhus shop,PT-1240,,&#10;osl,Oslo pop-up,,,osl-popup"><?=htmlspecialchars($form['rows'])?></textarea>
			<div class="form-text"><?=gettext('Paste from a spreadsheet (comma or semicolon). Leave the hostname empty to name the firewall from the group; the serial or instance id binds an unattended seed to that firewall.')?></div>
			<button class="btn btn-sm btn-outline-secondary mt-2" name="preview" value="1"><i class="fa-solid fa-eye icon-embed-btn" aria-hidden="true"></i><?=gettext('Preview')?></button>
		</div>
<?php if ($plan !== null): $bad = count(array_filter($plan, function ($r) { return !empty($r['problems']); })); ?>
		<div class="panel-body table-responsive"><table class="table fs-table">
			<thead><tr><th><?=gettext('Line')?></th><th><?=gettext('Firewall')?></th><th><?=gettext('Name')?></th><th><?=gettext('Bound to')?></th><th><?=gettext('Check')?></th></tr></thead>
			<tbody>
<?php foreach ($plan as $r): ?>
			<tr><td class="fs-muted"><?=(int)$r['line']?></td><td><?=htmlspecialchars($r['label'])?><?=($r['site'] !== '') ? '<div class="fs-muted small">' . htmlspecialchars($r['site']) . '</div>' : ''?></td>
				<td class="fs-mono small"><?=htmlspecialchars(trim($r['hostname'] . (($r['hostname'] !== '' && $r['domain'] !== '') ? '.' . $r['domain'] : ''))) ?: '<span class="fs-muted">' . gettext('keeps its own') . '</span>'?></td>
				<td class="small"><?=htmlspecialchars(trim($r['serial'] . ' ' . $r['instance_id'])) ?: '<span class="fs-muted">-</span>'?></td>
				<td><?=empty($r['problems']) ? fs_badge('pass', gettext('OK')) : '<span class="fs-fleet-problem small">' . htmlspecialchars(implode('; ', $r['problems'])) . '</span>'?></td></tr>
<?php endforeach; ?>
			</tbody></table></div>
		<div class="panel-footer">
<?php if ($bad > 0): ?>
			<p class="fs-fleet-problem mb-0"><?=htmlspecialchars(sprintf(ngettext('FLEET-E120: %d row has a problem. Fix it and preview again.', 'FLEET-E120: %d rows have problems. Fix them and preview again.', $bad), $bad))?></p>
<?php else: ?>
			<div class="row g-2 align-items-end">
				<div class="col-sm-4"><label class="form-label" for="bpass"><?=gettext('Bundle passphrase')?></label>
					<input class="form-control" type="password" id="bpass" name="passphrase" minlength="12" autocomplete="new-password"/></div>
				<div class="col-sm-4"><label class="form-label" for="bpass2"><?=gettext('Passphrase again')?></label>
					<input class="form-control" type="password" id="bpass2" name="passphrase_again" autocomplete="new-password"/></div>
				<div class="col-sm-4"><button class="btn btn-primary" name="generate" value="1"><i class="fa-solid fa-industry icon-embed-btn" aria-hidden="true"></i><?=sprintf(ngettext('Make %d invitation', 'Make %d invitations', count($plan)), count($plan))?></button></div>
			</div>
			<p class="form-text mb-0"><?=gettext('The bundle (seeds, cards, keys) is encrypted with this passphrase. Fleet does not keep the passphrase; the names are reserved when you make the batch.')?></p>
<?php endif; ?>
		</div>
<?php endif; ?>
	</div>
</form>
<?php endif; ?>
<?php include('foot.inc');
