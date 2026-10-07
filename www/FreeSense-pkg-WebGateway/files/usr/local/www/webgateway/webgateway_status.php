<?php
/* FreeSense Secure Web Gateway: runtime status. */

require_once('guiconfig.inc');
require_once('webgateway.inc');

$input_errors = [];
$savemsg = null;
$wg_config = webgateway_config();

if ($_POST && isset($_POST['service_action'])) {
	$action = $_POST['service_action'];
	if ($action === 'start') {
		if ($wg_config['enable'] !== 'on') {
			$input_errors[] = gettext('Enable the Web Gateway on the Listeners page before starting it.');
		} elseif (!webgateway_sync_config()) {
			$input_errors[] = gettext('The Web Gateway failed to start. Check Diagnostics.');
		} else {
			$savemsg = gettext('Web Gateway started and applied to Squid.');
		}
	} elseif ($action === 'restart') {
		if ($wg_config['enable'] !== 'on') {
			$input_errors[] = gettext('Enable the Web Gateway on the Listeners page before restarting it.');
		} elseif (!webgateway_sync_config()) {
			$input_errors[] = gettext('The Web Gateway failed to restart. Check Diagnostics.');
		} else {
			$savemsg = gettext('Web Gateway restarted and configuration reloaded into Squid.');
		}
	} elseif ($action === 'stop') {
		webgateway_watchdog_action('onestop');
		webgateway_service_action('onestop');
		filter_configure();
		$savemsg = gettext('Web Gateway stopped.');
	} elseif ($action === 'emergency') {
		$wg_config['enable'] = '';
		config_set_path(WEBGATEWAY_CONFIG_PATH, webgateway_config_for_storage($wg_config));
		write_config(gettext('Web Gateway interception disabled by emergency action'));
		webgateway_watchdog_action('onestop');
		webgateway_service_action('onestop');
		filter_configure();
		$wg_config = webgateway_config();
		$savemsg = gettext('Emergency disable complete: interception rules were removed and the proxy was stopped.');
	}
}

$running = webgateway_is_running();
$enabled = ($wg_config['enable'] === 'on');
$log_lines = [];
if (is_readable(WEBGATEWAY_LOG_FILE)) {
	exec('/usr/bin/tail -n 100 ' . escapeshellarg(WEBGATEWAY_LOG_FILE), $log_lines);
}
$networks = webgateway_interface_networks($wg_config['interfaces']);
$extra_networks = webgateway_lines($wg_config['additional_client_networks'] ?? '');
$listeners = webgateway_interface_listeners($wg_config);

$pgtitle = [gettext('Status'), gettext('Web Gateway')];
fs_page_action(gettext('Diagnostics'), '/webgateway/webgateway_diagnostics.php', 'fa-stethoscope', 'secondary');
include('head.inc');
webgateway_display_tabs('status');
if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if ($savemsg !== null) {
	print_info_box($savemsg, 'success');
}
?>
<div class="fs-tiles">
<?php
fs_tile(gettext('Service'), $running ? gettext('Running') : gettext('Stopped'), $running ? 'up' : ($enabled ? 'down' : 'disabled'),
    $enabled ? gettext('Enabled') : gettext('Disabled under Listeners'));
fs_tile(gettext('Policy'), ($wg_config['policy_mode'] === 'allowlist') ? gettext('Restricted allowlist') : gettext('Standard access'));
fs_tile(gettext('TLS handling'), webgateway_tls_mode_label($wg_config['tls_mode']));
fs_tile(gettext('Client networks'), count($networks) + count($extra_networks), null, sprintf(gettext('%d listeners'), count($listeners)));
?>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Service control')?></h2></div>
	<div class="panel-body wg-pad">
		<form method="post" class="wg-service">
			<button class="btn btn-primary" name="service_action" value="start" type="submit" <?=($running || !$enabled) ? 'disabled' : ''?>><i class="fa-solid fa-play icon-embed-btn" aria-hidden="true"></i><?=gettext('Start')?></button>
			<button class="btn btn-outline-secondary" name="service_action" value="restart" type="submit" <?=!$enabled ? 'disabled' : ''?>><i class="fa-solid fa-rotate icon-embed-btn" aria-hidden="true"></i><?=gettext('Restart')?></button>
			<button class="btn btn-outline-secondary" name="service_action" value="stop" type="submit" <?=!$running ? 'disabled' : ''?>><i class="fa-solid fa-stop icon-embed-btn" aria-hidden="true"></i><?=gettext('Stop')?></button>
			<span class="fs-toolbar-spacer"></span>
			<button class="btn btn-outline-danger" name="service_action" value="emergency" type="submit"
				data-fs-confirm="<?=htmlspecialchars(gettext('Emergency disable the Web Gateway?'))?>"
				data-fs-confirm-detail="<?=htmlspecialchars(gettext('Interception rules are removed, the gateway is disabled in the configuration and the proxy is stopped.'))?>"
				data-fs-confirm-action="<?=htmlspecialchars(gettext('Emergency disable'))?>"><i class="fa-solid fa-triangle-exclamation icon-embed-btn" aria-hidden="true"></i><?=gettext('Emergency disable')?></button>
		</form>
<?php if (!$enabled): ?>
		<p class="fs-muted wg-service-note"><?=gettext('The gateway is disabled. Enable it under Listeners, then Start or Restart to apply settings to Squid.')?></p>
<?php endif; ?>
	</div>
</div>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar(['title' => gettext('Listeners'), 'search' => false, 'noun' => gettext('listeners'), 'noun_one' => gettext('listener')]); ?>
	<div class="panel-body table-responsive">
	<table class="table table-hover">
		<thead><tr>
			<th><?=gettext('Type')?></th>
			<th><?=gettext('Address')?></th>
			<th><?=gettext('Options')?></th>
		</tr></thead>
		<tbody>
<?php foreach ($listeners as $listener):
	$parts = preg_split('/\s+/', trim($listener));
	$kind = array_shift($parts);
	$address = array_shift($parts);
	$flags = array_filter($parts, function ($p) { return strpos($p, '=') === false; });
?>
			<tr>
				<td><?=fs_badge('info', ($kind === 'https_port') ? 'HTTPS' : 'HTTP')?></td>
				<td class="fs-mono"><?=htmlspecialchars((string)$address)?></td>
				<td><div class="fs-chips"><?php if (!$flags): ?><span class="fs-chip"><?=gettext('explicit')?></span><?php endif; ?><?php foreach ($flags as $flag): ?><span class="fs-chip fs-chip--mono"><?=htmlspecialchars($flag)?></span><?php endforeach; ?></div></td>
			</tr>
<?php endforeach; ?>
<?php if (empty($listeners)) fs_empty_row(3, gettext('No listener interfaces selected.'), '/webgateway/webgateway_listeners.php', gettext('Configure listeners')); ?>
		</tbody>
	</table>
	</div>
</div>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar(['title' => gettext('Permitted client networks'), 'search' => false, 'noun' => gettext('networks'), 'noun_one' => gettext('network')]); ?>
	<div class="panel-body table-responsive">
	<table class="table table-hover">
		<thead><tr>
			<th><?=gettext('Network')?></th>
			<th><?=gettext('Source')?></th>
		</tr></thead>
		<tbody>
<?php foreach ($networks as $network): ?>
			<tr><td class="fs-mono"><?=htmlspecialchars($network)?></td><td><?=gettext('Selected interface')?></td></tr>
<?php endforeach; ?>
<?php foreach ($extra_networks as $network): ?>
			<tr><td class="fs-mono"><?=htmlspecialchars($network)?></td><td><?=gettext('Additional client network')?></td></tr>
<?php endforeach; ?>
<?php if (empty($networks) && empty($extra_networks)) fs_empty_row(2, gettext('No client networks detected. Select interfaces or add routed networks under Listeners.')); ?>
		</tbody>
	</table>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext('Recent access log')?> <span class="fs-count"><?=count($log_lines)?></span></h2>
<?php if ($wg_config['access_log'] === 'on' && !empty($log_lines)): ?>
		<button type="button" class="btn btn-sm btn-outline-secondary" data-fs-copy="#wg-access-log"><i class="fa-regular fa-copy icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy')?></button>
<?php endif; ?>
	</div>
<?php if ($wg_config['access_log'] !== 'on'): ?>
	<div class="fs-tool-empty"><i class="fa-solid fa-eye-slash" aria-hidden="true"></i><span><?=gettext('Access logging is disabled.')?></span></div>
<?php elseif (empty($log_lines)): ?>
	<div class="fs-tool-empty"><i class="fa-solid fa-list" aria-hidden="true"></i><span><?=gettext('No access records are available yet.')?></span></div>
<?php else: ?>
	<pre class="fs-console" id="wg-access-log"><?=htmlspecialchars(implode("\n", $log_lines))?></pre>
<?php endif; ?>
</div>
<style>
.wg-pad { padding: var(--fs-sp-3) var(--fs-sp-4); }
.wg-service { display: flex; flex-wrap: wrap; gap: var(--fs-sp-2); align-items: center; }
.wg-service-note { margin: var(--fs-sp-3) 0 0; font-size: var(--fs-fs-sm); }
</style>
<?php include('foot.inc'); ?>
