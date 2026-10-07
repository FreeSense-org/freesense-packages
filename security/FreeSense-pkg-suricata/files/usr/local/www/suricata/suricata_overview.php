<?php
require_once('guiconfig.inc');
require_once('/usr/local/pkg/suricata/suricata.inc');

$pgtitle = [gettext('Services'), gettext('Suricata'), gettext('Overview')];
$pglinks = ['', '@self', '@self'];
$input_errors = [];
$interfaces = config_get_path('installedpackages/suricata/rule', []);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'], $_POST['uuid'])) {
	$selected = null;
	foreach ($interfaces as $entry) {
		if ((string)($entry['uuid'] ?? '') === (string)$_POST['uuid']) {
			$selected = $entry;
			break;
		}
	}
	if (!$selected) {
		$input_errors[] = gettext('The selected Suricata interface no longer exists.');
	} else {
		$real = get_real_interface($selected['interface']);
		switch ($_POST['action']) {
			case 'start':
				suricata_generate_yaml($selected);
				suricata_start($selected, $real);
				break;
			case 'restart':
				suricata_generate_yaml($selected);
				suricata_stop($selected, $real);
				suricata_start($selected, $real);
				break;
			case 'stop':
				suricata_stop($selected, $real);
				break;
			case 'validate':
				$path = SURICATADIR . "suricata_{$selected['uuid']}_{$real}/suricata.yaml";
				if (!suricata_validate_config_file($path, $validation_output)) {
					$input_errors[] = $validation_output;
				} else {
					@file_put_contents("{$path}.validated", date(DATE_ATOM) . " Suricata " . SURICATA_BIN_VERSION . "\n", LOCK_EX);
					$savemsg = gettext('The active Suricata configuration is valid.');
				}
				break;
		}
	}
}

$running = 0;
$enabled = 0;
$blocking = 0;
foreach ($interfaces as $entry) {
	$real = get_real_interface($entry['interface'] ?? '');
	if (($entry['enable'] ?? '') === 'on') {
		$enabled++;
	}
	if ($real && suricata_is_running($entry['uuid'], $real)) {
		$running++;
	}
	if (($entry['enable'] ?? '') === 'on' && ($entry['blockoffenders'] ?? '') === 'on') {
		$blocking++;
	}
}
$rules_mtime = 0;
foreach (glob(SURICATADIR . 'rules/*.rules') ?: [] as $file) {
	$rules_mtime = max($rules_mtime, filemtime($file));
}

$can_add = count($interfaces) < count(get_configured_interface_list());
if ($can_add) {
	fs_page_action(gettext('Add interface'), '/suricata/suricata_interfaces_edit.php?id=' . count($interfaces), 'fa-plus');
}
fs_page_action(gettext('Update rules'), '/suricata/suricata_download_updates.php', 'fa-download', 'secondary');

include('head.inc');
if ($input_errors) {
	print_input_errors($input_errors);
}
if (!empty($savemsg)) {
	print_info_box($savemsg, 'success');
}
suricata_display_primary_navigation('overview');
?>
<div class="fs-tiles">
<?php
fs_tile(gettext('Running'), sprintf(gettext('%1$d of %2$d'), $running, $enabled), ($enabled && $running < $enabled) ? 'warn' : null, gettext('Enabled interfaces with Suricata running'));
fs_tile(gettext('Blocking'), $blocking, null, gettext('Enabled interfaces that block offenders'));
fs_tile(gettext('Rules'), $rules_mtime ? date('Y-m-d H:i', $rules_mtime) : gettext('Not downloaded'), $rules_mtime ? null : 'warn', gettext('Last local rule change'));
fs_tile(gettext('Engine'), SURICATA_BIN_VERSION, null, sprintf(gettext('Package %s'), SURICATA_PKG_VER));
?>
</div>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('Interface health'),
	'search' => false,
	'noun' => gettext('interfaces'),
	'noun_one' => gettext('interface'),
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover">
			<thead>
				<tr>
					<th class="fs-col-status"><?=gettext('Status')?></th>
					<th><?=gettext('Interface')?></th>
					<th><?=gettext('Mode')?></th>
					<th><?=gettext('Configuration')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
foreach ($interfaces as $idx => $entry):
	$real = get_real_interface($entry['interface'] ?? '');
	$is_running = $real && suricata_is_running($entry['uuid'], $real);
	$is_enabled = (($entry['enable'] ?? '') === 'on');
	$config_path = SURICATADIR . "suricata_{$entry['uuid']}_{$real}/suricata.yaml";
	$validation_marker = "{$config_path}.validated";
	$valid = is_file($config_path) && is_file($validation_marker) && filemtime($validation_marker) >= filemtime($config_path);
	$label = $entry['descr'] ?? $entry['interface'];
	if (($entry['blockoffenders'] ?? '') === 'on') {
		$mode = (($entry['ips_mode'] ?? '') === 'ips_mode_inline') ? gettext('IPS inline') : gettext('IPS legacy');
	} else {
		$mode = gettext('IDS');
	}
	$uuid = rawurlencode($entry['uuid']);
	$actions = [];
	$actions[] = ['custom', "/suricata/suricata_overview.php?action=" . ($is_running ? 'restart' : 'start') . "&uuid={$uuid}", $label, [
		'icon' => $is_running ? 'fa-solid fa-arrow-rotate-right' : 'fa-solid fa-play',
		'label' => sprintf($is_running ? gettext('Restart Suricata on %s') : gettext('Start Suricata on %s'), $label), 'post' => true]];
	if ($is_running) {
		$actions[] = ['custom', "/suricata/suricata_overview.php?action=stop&uuid={$uuid}", $label, [
			'icon' => 'fa-solid fa-stop', 'label' => sprintf(gettext('Stop Suricata on %s'), $label), 'post' => true,
			'confirm' => sprintf(gettext('Stop Suricata on “%s”?'), $label),
			'detail' => gettext('Traffic on this interface is no longer inspected until Suricata is started again.'),
			'confirm_action' => gettext('Stop')]];
	}
	$actions[] = ['custom', "/suricata/suricata_overview.php?action=validate&uuid={$uuid}", $label, [
		'icon' => 'fa-solid fa-clipboard-check', 'label' => sprintf(gettext('Validate the configuration of %s'), $label), 'post' => true]];
	$actions[] = ['edit', "/suricata/suricata_interfaces_edit.php?id={$idx}", $label];
?>
				<tr<?=$is_enabled ? '' : ' class="fs-row-disabled"'?>>
					<td><?=$is_running ? fs_badge('up', gettext('Running')) : ($is_enabled ? fs_badge('down', gettext('Stopped')) : fs_badge('disabled'))?></td>
					<td>
						<a href="/suricata/suricata_interfaces_edit.php?id=<?=(int)$idx?>"><strong><?=htmlspecialchars($label)?></strong></a>
						<div class="fs-mono fs-muted small"><?=htmlspecialchars($real)?></div>
					</td>
					<td><span class="fs-chip fs-chip--strong"><?=htmlspecialchars($mode)?></span></td>
					<td><?=$valid ? fs_badge('pass', gettext('Valid')) : fs_badge('warn', gettext('Not validated'), gettext('Invalid, missing or changed since the last validation'))?></td>
					<td class="fs-col-actions"><?=fs_row_actions($actions)?></td>
				</tr>
<?php endforeach; ?>
<?php if (!$interfaces) {
	fs_empty_row(5, gettext('No Suricata interfaces yet.'), $can_add ? '/suricata/suricata_interfaces_edit.php?id=0' : null, $can_add ? gettext('Add interface') : null);
} ?>
			</tbody>
		</table>
	</div>
</div>
<?php include('foot.inc'); ?>
