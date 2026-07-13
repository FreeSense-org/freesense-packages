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
			$input_errors[] = gettext('Enable the Web Gateway before starting it.');
		} elseif (!webgateway_sync_config()) {
			$input_errors[] = gettext('The Web Gateway failed to start. Check Diagnostics.');
		} else {
			$savemsg = gettext('Web Gateway started.');
		}
	} elseif ($action === 'restart') {
		if (!webgateway_sync_config()) {
			$input_errors[] = gettext('The Web Gateway failed to restart. Check Diagnostics.');
		} else {
			$savemsg = gettext('Web Gateway restarted.');
		}
	} elseif ($action === 'stop') {
		webgateway_watchdog_action('onestop');
		webgateway_service_action('onestop');
		filter_configure();
		$savemsg = gettext('Web Gateway stopped.');
	} elseif ($action === 'emergency') {
		$wg_config['enable'] = '';
		config_set_path(WEBGATEWAY_CONFIG_PATH, $wg_config);
		write_config(gettext('Web Gateway interception disabled by emergency action'));
		webgateway_watchdog_action('onestop');
		webgateway_service_action('onestop');
		filter_configure();
		$savemsg = gettext('Emergency disable complete: interception rules were removed and the proxy was stopped.');
	}
}

$running = webgateway_is_running();
$log_lines = [];
if (is_readable(WEBGATEWAY_LOG_FILE)) {
	exec('/usr/bin/tail -n 100 ' . escapeshellarg(WEBGATEWAY_LOG_FILE), $log_lines);
}
$networks = webgateway_interface_networks($wg_config['interfaces']);
$listeners = webgateway_interface_listeners($wg_config);

$pgtitle = [gettext('Status'), gettext('Web Gateway')];
include('head.inc');
webgateway_display_tabs('status');
if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if ($savemsg !== null) {
	print_info_box($savemsg, 'success');
}
?>

<div class="row g-3 mb-3">
	<div class="col-md-4">
		<div class="card h-100">
			<div class="card-body">
				<div class="text-uppercase text-muted small fw-semibold mb-2"><?=gettext('Service')?></div>
				<div class="fs-4 <?= $running ? 'text-success' : 'text-danger' ?>"><i class="fa-solid <?= $running ? 'fa-circle-check' : 'fa-circle-stop' ?> me-2"></i><?= $running ? gettext('Running') : gettext('Stopped') ?></div>
			</div>
		</div>
	</div>
	<div class="col-md-4">
		<div class="card h-100"><div class="card-body"><div class="text-uppercase text-muted small fw-semibold mb-2"><?=gettext('Policy')?></div><div class="fs-4"><?=($wg_config['policy_mode'] === 'allowlist') ? gettext('Restricted allowlist') : gettext('Standard access')?></div></div></div>
	</div>
	<div class="col-md-4">
		<div class="card h-100"><div class="card-body"><div class="text-uppercase text-muted small fw-semibold mb-2"><?=gettext('TLS handling')?></div><div class="fs-4 text-info"><i class="fa-solid fa-lock me-2"></i><?=htmlspecialchars(['tunnel'=>gettext('Tunnel only'),'selective'=>gettext('Selective inspection'),'full'=>gettext('Full inspection')][$wg_config['tls_mode']])?></div></div></div>
	</div>
</div>

<div class="card mb-3">
	<div class="card-header"><h2 class="h5 mb-0"><i class="fa-solid fa-sliders me-2"></i><?=gettext('Service Control')?></h2></div>
	<div class="card-body">
		<form method="post" class="d-flex flex-wrap gap-2">
			<button class="btn btn-success" name="service_action" value="start" type="submit"><i class="fa-solid fa-play icon-embed-btn"></i><?=gettext('Start')?></button>
			<button class="btn btn-primary" name="service_action" value="restart" type="submit"><i class="fa-solid fa-rotate icon-embed-btn"></i><?=gettext('Restart')?></button>
			<button class="btn btn-danger" name="service_action" value="stop" type="submit"><i class="fa-solid fa-stop icon-embed-btn"></i><?=gettext('Stop')?></button>
			<button class="btn btn-outline-danger ms-auto" name="service_action" value="emergency" type="submit" onclick="return confirm('Remove Web Gateway interception rules and stop the service?')"><i class="fa-solid fa-triangle-exclamation icon-embed-btn"></i><?=gettext('Emergency disable')?></button>
		</form>
	</div>
</div>

<div class="row g-3 mb-3">
	<div class="col-lg-6">
		<div class="card h-100">
			<div class="card-header"><h2 class="h5 mb-0"><?=gettext('Listeners')?></h2></div>
			<ul class="list-group list-group-flush font-monospace">
				<?php foreach ($listeners as $listener): ?><li class="list-group-item"><?=htmlspecialchars(substr($listener, strlen('http_port ')))?></li><?php endforeach; ?>
				<?php if (empty($listeners)): ?><li class="list-group-item text-muted"><?=gettext('No listener interfaces selected.')?></li><?php endif; ?>
			</ul>
		</div>
	</div>
	<div class="col-lg-6">
		<div class="card h-100">
			<div class="card-header"><h2 class="h5 mb-0"><?=gettext('Permitted client networks')?></h2></div>
			<ul class="list-group list-group-flush font-monospace">
				<?php foreach ($networks as $network): ?><li class="list-group-item"><?=htmlspecialchars($network)?></li><?php endforeach; ?>
				<?php if (empty($networks)): ?><li class="list-group-item text-muted"><?=gettext('No directly connected client networks detected.')?></li><?php endif; ?>
			</ul>
		</div>
	</div>
</div>

<div class="card mb-3">
	<div class="card-header d-flex justify-content-between align-items-center"><h2 class="h5 mb-0"><i class="fa-solid fa-list me-2"></i><?=gettext('Recent access log')?></h2><span class="badge bg-secondary"><?=count($log_lines)?> <?=gettext('lines')?></span></div>
	<div class="card-body p-0">
		<pre class="m-0 p-3 bg-dark text-light overflow-auto" style="max-height:32rem"><?php if ($wg_config['access_log'] !== 'on'): ?><?=gettext('Access logging is disabled.')?><?php elseif (empty($log_lines)): ?><?=gettext('No access records are available yet.')?><?php else: ?><?=htmlspecialchars(implode("\n", $log_lines))?><?php endif; ?></pre>
	</div>
</div>

<?php include('foot.inc'); ?>
