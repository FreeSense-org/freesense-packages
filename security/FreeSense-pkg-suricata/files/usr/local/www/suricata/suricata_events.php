<?php
/*
 * suricata_events.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2004-2026 The FreeSense Project
 * All rights reserved.
 *
 * Recent EVE JSON events of the Suricata interfaces (read-only).
 */

require_once('guiconfig.inc');
require_once('/usr/local/pkg/suricata/suricata.inc');

$type = $_GET['type'] ?? 'alert';
$allowed = ['all', 'alert', 'drop', 'flow', 'dns', 'http', 'tls', 'fileinfo', 'anomaly'];
if (!in_array($type, $allowed, true)) {
	$type = 'alert';
}
$interface = $_GET['interface'] ?? 'all';
$events = [];
$have_eve = false;
$interfaces = config_get_path('installedpackages/suricata/rule', []);
foreach ($interfaces as $entry) {
	if ($interface !== 'all' && (string)$entry['uuid'] !== $interface) {
		continue;
	}
	$real = get_real_interface($entry['interface'] ?? '');
	$path = SURICATALOGDIR . "suricata_{$real}{$entry['uuid']}/eve.json";
	if (!is_file($path)) {
		continue;
	}
	$have_eve = true;
	$lines = [];
	exec('/usr/bin/tail -n 750 ' . escapeshellarg($path), $lines, $rc);
	foreach ($lines as $line) {
		$event = json_decode($line, true);
		if (!is_array($event)) {
			continue;
		}
		if ($type !== 'all' && ($event['event_type'] ?? '') !== $type) {
			continue;
		}
		$event['_interface'] = $entry['descr'] ?? $real;
		$events[] = $event;
	}
}
usort($events, fn($a, $b) => strcmp($b['timestamp'] ?? '', $a['timestamp'] ?? ''));
$events = array_slice($events, 0, 500);

$type_labels = [
	'all' => gettext('All types'),
	'alert' => gettext('Alert'),
	'drop' => gettext('Drop'),
	'flow' => gettext('Flow'),
	'dns' => gettext('DNS'),
	'http' => gettext('HTTP'),
	'tls' => gettext('TLS'),
	'fileinfo' => gettext('File info'),
	'anomaly' => gettext('Anomaly'),
];

$pgtitle = [gettext('Services'), gettext('Suricata'), gettext('Events'), gettext('EVE events')];
$pglinks = ['', '/suricata/suricata_overview.php', '', '@self'];

include('head.inc');
suricata_display_primary_navigation('events');

suricata_display_section_navigation('events', 'events');

/* Event type: badge for the actionable types, chip for the rest */
$sf_type = function ($t) use ($type_labels) {
	$label = $type_labels[$t] ?? $t;
	switch ($t) {
		case 'alert':
			return fs_badge('warn', $label);
		case 'drop':
			return fs_badge('block', $label);
		case 'anomaly':
			return fs_badge('info', $label);
		default:
			return '<span class="fs-chip fs-chip--strong">' . fs_h($label) . '</span>';
	}
};

$sf_addr = function ($ip, $port) {
	if ($ip === '' || $ip === null) {
		return '<span class="fs-muted">-</span>';
	}
	return '<span class="fs-mono sf-ip">' . fs_h($ip) . '</span>' . (($port !== null && $port !== '') ? '<span class="fs-mono fs-muted">:' . fs_h($port) . '</span>' : '');
};
?>

<style>
.sf-ip { overflow-wrap: anywhere; }
.sf-time { white-space: nowrap; }
.sf-detail { min-width: 14rem; overflow-wrap: anywhere; }
.sf-select { width: auto; max-width: 16rem; }
.sf-contents { display: contents; }
.sf-notes { display: flex; flex-wrap: wrap; gap: .4rem 1.5rem; margin: -.5rem 0 var(--fs-sp-5); color: var(--fs-text-muted); font-size: var(--fs-fs-sm); }
</style>

<div class="panel panel-default fs-table">
<?php
	$controls = '<form method="get" class="sf-contents" id="sf-eventfilter">'
	    . '<select class="form-select form-select-sm sf-select" id="type" name="type" aria-label="' . fs_h(gettext('Event type')) . '">';
	foreach ($allowed as $value) {
		$controls .= '<option value="' . fs_h($value) . '"' . (($type === $value) ? ' selected' : '') . '>' . fs_h($type_labels[$value]) . '</option>';
	}
	$controls .= '</select><select class="form-select form-select-sm sf-select" id="interface" name="interface" aria-label="' . fs_h(gettext('Interface')) . '">'
	    . '<option value="all">' . fs_h(gettext('All interfaces')) . '</option>';
	foreach ($interfaces as $entry) {
		$controls .= '<option value="' . fs_h($entry['uuid']) . '"' . (($interface === (string)$entry['uuid']) ? ' selected' : '') . '>' . fs_h($entry['descr'] ?? $entry['interface']) . '</option>';
	}
	$controls .= '</select><noscript><button class="btn btn-sm btn-primary">' . fs_h(gettext('Apply filter')) . '</button></noscript></form>';

	fs_table_toolbar([
		'search' => gettext('Search addresses, signatures, protocols…'),
		'noun' => gettext('events'),
		'noun_one' => gettext('event'),
		'custom' => $controls,
	]);
?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th data-sortable-type="alpha"><?=gettext('Time')?></th>
					<th data-fs-search><?=gettext('Interface')?></th>
					<th data-fs-search><?=gettext('Type')?></th>
					<th data-fs-search><?=gettext('Source')?></th>
					<th data-fs-search><?=gettext('Destination')?></th>
					<th data-fs-search><?=gettext('Details')?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($events as $event):
	$alert = $event['alert'] ?? [];
	$ts = (string)($event['timestamp'] ?? '');
	$tm = date_create($ts);
?>
				<tr>
					<td class="fs-mono sf-time" data-value="<?=fs_h($ts)?>"><?php if ($tm): ?><?=fs_h(date_format($tm, 'H:i:s'))?><div class="fs-muted small"><?=fs_h(date_format($tm, 'm/d/Y'))?></div><?php else: ?><?=fs_h($ts)?><?php endif; ?></td>
					<td><?=fs_h($event['_interface'])?></td>
					<td><?=$sf_type((string)($event['event_type'] ?? ''))?></td>
					<td><?=$sf_addr($event['src_ip'] ?? '', $event['src_port'] ?? null)?></td>
					<td><?=$sf_addr($event['dest_ip'] ?? '', $event['dest_port'] ?? null)?></td>
					<td class="sf-detail">
<?php if (!empty($alert['signature'])): ?>
						<div><?=fs_h($alert['signature'])?></div>
						<div class="fs-mono fs-muted small"><?=fs_h(($alert['gid'] ?? '1') . ':' . ($alert['signature_id'] ?? ''))?><?=isset($alert['severity']) ? ' · ' . fs_h(sprintf(gettext('severity %s'), $alert['severity'])) : ''?></div>
<?php else: ?>
						<div class="fs-chips">
<?php	if (!empty($event['app_proto'])): ?>
							<span class="fs-chip fs-chip--strong"><?=fs_h(strtoupper($event['app_proto']))?></span>
<?php	endif; ?>
<?php	if (!empty($event['proto'])): ?>
							<span class="fs-chip fs-chip--mono"><?=fs_h($event['proto'])?></span>
<?php	endif; ?>
						</div>
<?php endif; ?>
					</td>
				</tr>
<?php endforeach; ?>
<?php
	if (!$events) {
		fs_empty_row(6, $have_eve ? gettext('No matching events in the recent log window.') : gettext('No EVE log yet. Enable the EVE JSON log on an interface to see its events here.'));
	}
?>
			</tbody>
		</table>
	</div>
</div>

<div class="sf-notes">
	<span><?=gettext('Reads the last 750 lines of each eve.json log and shows up to 500 events, most recent first.')?></span>
</div>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	// The type and interface choices reload the page with the new filter
	$('#type, #interface').on('change', function() {
		document.getElementById('sf-eventfilter').submit();
	});
});
//]]>
</script>
<?php include('foot.inc'); ?>
