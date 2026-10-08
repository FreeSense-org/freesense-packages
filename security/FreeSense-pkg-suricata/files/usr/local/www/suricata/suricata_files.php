<?php
/*
 * suricata_files.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2006-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2025-2026 The FreeSense Project
 * Copyright (c) 2003-2004 Manuel Kasper
 * Copyright (c) 2005 Bill Marquette
 * Copyright (c) 2009 Robert Zelaya Sr. Developer
 * Copyright (c) 2025 Bill Meeks
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

require_once("guiconfig.inc");
require_once("/usr/local/pkg/suricata/suricata.inc");

global $g;
$suri_pf_table = SURICATA_PF_TABLE;

function suricata_escape_filter_regex($filtertext) {
	/* If the caller (user) has not already put a backslash before a slash, to escape it in the regex, */
	/* then this will do it. Take out any "\/" already there, then turn all ordinary "/" into "\/".  */
	return str_replace('/', '\/', str_replace('\/', '/', $filtertext));
}

function suricata_match_filter_field($flent, $fields, $exact_match = FALSE) {
	foreach ($fields as $key => $field) {
		if ($field == null)
			continue;

		// Only match whole field string when
		// performing an exact match.
		if ($exact_match) {
			if ($flent[$key] == $field) {
				return true;
			}
			else {
				return false;
			}
		}

		if ((strpos($field, '!') === 0)) {
			$field = substr($field, 1);
			$field_regex = suricata_escape_filter_regex($field);
			if (@preg_match("/{$field_regex}/i", $flent[$key]))
				return false;
		}
		else {
			$field_regex = suricata_escape_filter_regex($field);
			if (!@preg_match("/{$field_regex}/i", $flent[$key]))
				return false;
		}
	}
	return true;
}

if (isset($_POST['instance']) && is_numericint($_POST['instance']))
	$instanceid = $_POST['instance'];
// This is for the auto-refresh so we can  stay on the same interface
elseif (isset($_GET['instance']) && is_numericint($_GET['instance']))
	$instanceid = $_GET['instance'];

if (!is_numericint($instanceid))
	$instanceid = 0;

$a_instance = config_get_path("installedpackages/suricata/rule/{$instanceid}", []);
$suricata_uuid = $a_instance['uuid'];
$if_real = get_real_interface($a_instance['interface']);
$suricatalogdir = SURICATALOGDIR;

$pconfig = array();
$pconfig['frefresh'] = config_get_path('installedpackages/suricata/fileblocks/frefresh', 'on');
$pconfig['filenumber'] = config_get_path('installedpackages/suricata/fileblocks/filenumber', 250);
$fnentries = $pconfig['filenumber'];
if (!is_numeric($fnentries)) {
	$fnentries = 250;
}	

# --- AJAX REVERSE DNS RESOLVE Start ---
if (isset($_POST['resolve'])) {
	$ip = strtolower($_POST['resolve']);
	$res = (is_ipaddr($ip) ? gethostbyaddr($ip) : '');
	if (strpos($res, 'xn--') !== false) {
		$res = idn_to_utf8($res);
	}

	if ($res && $res != $ip)
		$response = array('resolve_ip' => $ip, 'resolve_text' => $res);
	else
		$response = array('resolve_ip' => $ip, 'resolve_text' => gettext("Cannot resolve"));

	echo json_encode(str_replace("\\","\\\\", $response)); // single escape chars can break JSON decode
	exit;
}
# --- AJAX REVERSE DNS RESOLVE End ---

# --- AJAX GEOIP CHECK Start ---
if (isset($_POST['geoip'])) {
	$ip = strtolower($_POST['geoip']);
	if (is_ipaddr($ip)) {
		$url = "https://api.hackertarget.com/geoip/?q={$ip}";
		$conn = curl_init("https://api.hackertarget.com/geoip/?q={$ip}");
		curl_setopt($conn, CURLOPT_SSL_VERIFYPEER, true);
		curl_setopt($conn, CURLOPT_FRESH_CONNECT,  true);
		curl_setopt($conn, CURLOPT_RETURNTRANSFER, 1);
		set_curlproxy($conn);
		$res = curl_exec($conn);
		curl_close($conn);
	} else {
		$res = '';
	}

	if ($res && $res != $ip && !preg_match('/error/', $res))
		$response = array('geoip_text' => $res);
	else
		$response = array('geoip_text' => gettext("Cannot check {$ip}"));

	echo json_encode(str_replace("\\","\\\\", $response)); // single escape chars can break JSON decode
	exit;
}
# --- AJAX GEOIP CHECK End ---

# Check for persisted filtering of alerts log entries and populate
# the required $filterfieldsarray when persisting filtered entries.
if ($_POST['persist_filter'] == "yes" && !empty($_POST['persist_filter_content'])) {
	$filterlogentries = TRUE;
	$persist_filter_log_entries = "yes";
	$filterlogentries_exact_match = $_POST['persist_filter_exact_match'];
	$filterfieldsarray = json_decode($_POST['persist_filter_content'], TRUE);
}
else {
	$filterlogentries = FALSE;
	$persist_filter_log_entries = "";
	$filterfieldsarray = array();
}

if ($_POST['filterlogentries_submit']) {
	// Set flags for filtering alert log entries
	$filterlogentries = TRUE;
	$persist_filter_log_entries = "yes";

	// Set 'exact match only' flag if enabled
	if ($_POST['filterlogentries_exact_match'] == 'on') {
		$filterlogentries_exact_match = TRUE;
	} else {
		$filterlogentries_exact_match = FALSE;
	}

	// -- IMPORTANT --
	// Note the order of these fields must match the order decoded from the alerts log
	$filterfieldsarray = array();
	$filterfieldsarray['time'] = $_POST['filterlogentries_time'] ? $_POST['filterlogentries_time'] : null;
	$filterfieldsarray['proto'] = $_POST['filterlogentries_protocol'] ? $_POST['filterlogentries_protocol'] : null;
	$filterfieldsarray['app_proto'] = null;
	// Remove any zero-length spaces added to the IP address that could creep in from a copy-paste operation
	$filterfieldsarray['src_ip'] = $_POST['filterlogentries_sourceipaddress'] ? str_replace("\xE2\x80\x8B", "", $_POST['filterlogentries_sourceipaddress']) : null;
	$filterfieldsarray['src_port'] = $_POST['filterlogentries_sourceport'] ? $_POST['filterlogentries_sourceport'] : null;
	// Remove any zero-length spaces added to the IP address that could creep in from a copy-paste operation
	$filterfieldsarray['dest_ip'] = $_POST['filterlogentries_destinationipaddress'] ? str_replace("\xE2\x80\x8B", "", $_POST['filterlogentries_destinationipaddress']) : null;
	$filterfieldsarray['dest_port'] = $_POST['filterlogentries_destinationport'] ? $_POST['filterlogentries_destinationport'] : null;
	$filterfieldsarray['size'] = $_POST['filterlogentries_size'] ? $_POST['filterlogentries_size'] : null;
	$filterfieldsarray['filename'] = $_POST['filterlogentries_filename'] ? $_POST['filterlogentries_filename'] : null;
}

if ($_POST['filterlogentries_clear']) {
	$filterfieldsarray = array();
	$filterlogentries = TRUE;
	$persist_filter_log_entries = "";
}

if ($_POST['save']) {
	config_set_path('installedpackages/suricata/fileblocks/frefresh', $_POST['frefresh'] ? 'on' : 'off');
	config_set_path('installedpackages/suricata/fileblocks/filenumber', $_POST['filenumber']);
	write_config("Suricata pkg: saved change to FILES tab configuration.");
	header("Location: /suricata/suricata_files.php?instance={$instanceid}");
	exit;
}

if ($_POST['mode']=='unblock' && $_POST['ip']) {
	if (is_ipaddr($_POST['ip'])) {
		exec("/sbin/pfctl -t {$suri_pf_table} -T delete {$_POST['ip']}");
		$savemsg = gettext("Host IP address {$_POST['ip']} has been removed from the Blocked Table.");
	}
}

function build_instance_list() {

	$list = array();

	foreach (config_get_path('installedpackages/suricata/rule', []) as $id => $instance) {
		$list[$id] = '(' . convert_friendly_interface_to_friendly_descr($instance['interface']) . ') ' . $instance['descr'];
	}

	return($list);
}

/* ---------------------------------------------------------------- read the log */

$is_filtered = ($filterlogentries && count($filterfieldsarray));
$eve_file = "{$suricatalogdir}suricata_{$if_real}{$suricata_uuid}/eve.json";
$have_eve = file_exists($eve_file);
$files = array();

if ($have_eve) {
	exec("/usr/bin/grep filename {$suricatalogdir}suricata_{$if_real}{$suricata_uuid}/eve.json | /usr/bin/tail -{$fnentries} -r > {$g['tmp_path']}/files_suricata{$suricata_uuid}");
	if (file_exists("{$g['tmp_path']}/files_suricata{$suricata_uuid}")) {
		$tmpblocked = array_flip(suricata_get_blocked_ips());

		$fd = fopen("{$g['tmp_path']}/files_suricata{$suricata_uuid}", "r");
		$buf = "";
		while (($buf = fgets($fd)) !== FALSE) {
			$fields = json_decode($buf, true);
			if (!is_array($fields)) {
				continue;
			}

			$event_tm = date_create_from_format("Y-m-d\TH:i:s.uP", $fields['timestamp']);
			@$fields['timestamp'] = date_format($event_tm, "m/d/Y") . " " . date_format($event_tm, "H:i:s");
			$fields['filename'] = $fields['fileinfo']['filename'];

			if ($filterlogentries && !suricata_match_filter_field($fields, $filterfieldsarray, $filterlogentries_exact_match)) {
				continue;
			}

			/* Size */
			if ($fields['fileinfo']['size'] > 1048576) {
				$file_size = round(intval($fields['fileinfo']['size'])/1048576) . ' M';
			} elseif ($fields['fileinfo']['size'] > 1024) {
				$file_size = round(intval($fields['fileinfo']['size'])/1024) . ' K';
			} else {
				$file_size = $fields['fileinfo']['size'] . ' B';
			}

			/* File Hash */
			if (!empty($fields['fileinfo']['sha256'])) {
				$file_hash = $fields['fileinfo']['sha256'];
			} elseif (!empty($fields['fileinfo']['sha1'])) {
				$file_hash = $fields['fileinfo']['sha1'];
			} elseif (!empty($fields['fileinfo']['md5'])) {
				$file_hash = $fields['fileinfo']['md5'];
			} else {
				$file_hash = 'none';
			}

			$files[] = array(
				'f' => $fields,
				'date' => @date_format($event_tm, "m/d/Y"),
				'clock' => @date_format($event_tm, "H:i:s"),
				'size' => $file_size,
				'bytes' => intval($fields['fileinfo']['size']),
				'hash' => $file_hash,
				'stored' => !empty($fields['fileinfo']['stored']),
				'src_blocked' => isset($tmpblocked[$fields['src_ip']]),
				'dst_blocked' => isset($tmpblocked[$fields['dest_ip']]),
			);
		}
		unset($fields, $buf);
		fclose($fd);
		unlink_if_exists("{$g['tmp_path']}/files_suricata{$suricata_uuid}");
	}
}

$total_bytes = array_sum(array_column($files, 'bytes'));
$apps = array();
foreach ($files as $x) {
	if (!empty($x['f']['app_proto'])) {
		$apps[strtolower($x['f']['app_proto'])] = strtoupper($x['f']['app_proto']);
	}
}
ksort($apps);

/* ------------------------------------------------------------------ the page */

$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_events.php", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Events"), gettext("Files"));

fs_page_action(gettext('View settings'), '#', 'fa-sliders', 'secondary', ['data-fs-modal' => '#files-settings']);

include_once("head.inc");
suricata_display_primary_navigation('events');

suricata_display_section_navigation('events', 'files');

/* refresh every 60 secs */
if ($pconfig['frefresh'] == 'on')
	print '<meta http-equiv="refresh" content="60;url=/suricata/suricata_files.php?instance=' . (int)$instanceid . '" />';

if ($savemsg) {
	print_info_box($savemsg);
}

$sf_is_public = function ($ip) {
	return !is_private_ip($ip) && (substr($ip, 0, 2) != 'fc') && (substr($ip, 0, 2) != 'fd');
};

/* Address cell: mono address and port, then the host tools that apply */
$sf_host = function ($x, $side) use ($sf_is_public) {
	$ip = ($side === 'src') ? $x['f']['src_ip'] : $x['f']['dest_ip'];
	$port = ($side === 'src') ? $x['f']['src_port'] : $x['f']['dest_port'];
	$html = '<span class="fs-mono sf-ip">' . fs_h($ip) . '</span>';
	if ($port !== '' && $port !== null) {
		$html .= '<span class="fs-mono fs-muted">:' . fs_h($port) . '</span>';
	}
	$html .= '<div class="fs-actions sf-hostactions">'
	    . '<button type="button" class="fs-action" data-sf-lookup="' . fs_h($ip) . '" data-sf-geo="' . ($sf_is_public($ip) ? '1' : '0') . '"'
	    . ' title="' . fs_h(sprintf(gettext('Look up %s'), $ip)) . '" aria-label="' . fs_h(sprintf(gettext('Look up %s'), $ip)) . '">'
	    . '<i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i></button>';
	if ($x[$side . '_blocked']) {
		$label = sprintf(gettext('Remove block for %s'), $ip);
		$html .= '<button type="submit" class="fs-action" data-sf-ip="' . fs_h($ip) . '" title="' . fs_h($label) . '" aria-label="' . fs_h($label) . '"'
		    . ' data-fs-confirm="' . fs_h(sprintf(gettext('Remove the block for %s?'), $ip)) . '"'
		    . ' data-fs-confirm-detail="' . fs_h(gettext('The address is deleted from the blocked hosts table. A new alert can block it again.')) . '"'
		    . ' data-fs-confirm-action="' . fs_h(gettext('Remove block')) . '"><i class="fa-solid fa-unlock" aria-hidden="true"></i></button>';
	}
	$html .= '</div>';
	if ($x[$side . '_blocked']) {
		$html .= ' ' . fs_badge('block', gettext('Blocked'));
	}
	return $html;
};
?>

<style>
.sf-file { min-width: 14rem; }
.sf-file-name { color: var(--fs-text-strong); font-weight: 500; overflow-wrap: anywhere; }
.sf-file-meta { display: flex; flex-wrap: wrap; align-items: center; gap: .15rem .6rem; margin-top: .15rem; font-size: var(--fs-fs-sm); }
.sf-hash { max-width: 12rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; vertical-align: bottom; }
.sf-ip { overflow-wrap: anywhere; }
.sf-hostactions { display: inline-flex; gap: 0; margin-left: .25rem; vertical-align: middle; }
.sf-hostactions .fs-action { width: 1.6rem; height: 1.6rem; }
.sf-time { white-space: nowrap; }
.sf-instance { width: auto; max-width: 18rem; }
.sf-advfilter { padding: var(--fs-sp-3) var(--fs-sp-4); border-bottom: 1px solid var(--fs-border); }
.sf-advgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(11rem, 1fr)); gap: .6rem 1rem; }
.sf-advgrid .form-label { margin-bottom: .2rem; font-size: var(--fs-fs-sm); color: var(--fs-text-muted); }
.sf-advchecks { display: flex; flex-wrap: wrap; gap: .4rem 1.25rem; margin-top: .75rem; }
.sf-advbuttons { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .75rem; }
.sf-notes { display: flex; flex-wrap: wrap; gap: .4rem 1.5rem; margin: -.5rem 0 var(--fs-sp-5); color: var(--fs-text-muted); font-size: var(--fs-fs-sm); }
.sf-lookup dl { display: grid; grid-template-columns: 8rem minmax(0, 1fr); gap: .5rem 1rem; margin: 0; }
.sf-lookup dt { color: var(--fs-text-muted); font-weight: 500; }
.sf-lookup dd { margin: 0; overflow-wrap: anywhere; white-space: pre-line; }
@media (max-width: 575.98px) { .sf-lookup dl { grid-template-columns: 1fr; gap: .15rem; } .sf-lookup dd { margin-bottom: .5rem; } }
</style>

<div class="fs-tiles">
<?php
	fs_tile(gettext('Files shown'), count($files), null, $is_filtered ? gettext('Filtered view') : sprintf(gettext('Last %s file events'), $fnentries));
	fs_tile(gettext('Total size'), format_bytes($total_bytes));
	fs_tile(gettext('Stored'), count(array_filter(array_column($files, 'stored'))), null, gettext('Kept by File-Store'));
?>
</div>

<form action="/suricata/suricata_files.php" method="post" name="formfile" id="formfile">
	<input type="hidden" name="ip" id="ip" value="">
	<input type="hidden" name="mode" id="mode" value="">
<?php if ($persist_filter_log_entries == "yes"): ?>
	<input type="hidden" name="persist_filter" id="persist_filter" value="<?=fs_h($persist_filter_log_entries)?>">
	<input type="hidden" name="persist_filter_exact_match" id="persist_filter_exact_match" value="<?=fs_h($filterlogentries_exact_match)?>">
	<input type="hidden" name="persist_filter_content" id="persist_filter_content" value="<?=fs_h(json_encode($filterfieldsarray))?>">
<?php endif; ?>

<div class="panel panel-default fs-table">
<?php
	$instance_select = '<select class="form-select form-select-sm sf-instance" name="instance" id="instance" aria-label="' . fs_h(gettext('Interface')) . '">';
	foreach (build_instance_list() as $k => $v) {
		$instance_select .= '<option value="' . fs_h($k) . '"' . (((string)$k === (string)$instanceid) ? ' selected' : '') . '>' . fs_h($v) . '</option>';
	}
	$instance_select .= '</select>';

	$active_filters = count(array_filter($filterfieldsarray, function ($v) { return $v !== null && $v !== ''; }));
	$filter_btn = '<button type="button" class="btn btn-sm btn-outline-secondary" data-bs-toggle="collapse" data-bs-target="#sf-advfilter" aria-expanded="' . ($is_filtered ? 'true' : 'false') . '" aria-controls="sf-advfilter">'
	    . '<i class="fa-solid fa-filter icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('Advanced filter'))
	    . ($active_filters ? ' <span class="badge text-bg-secondary">' . (int)$active_filters . '</span>' : '') . '</button>';

	$filters = array();
	if (count($apps) > 1) {
		$filters['app'] = array(gettext('All applications')) + $apps;
	}
	fs_table_toolbar(array(
		'search' => gettext('Search file names, hashes, addresses…'),
		'noun' => gettext('files'),
		'noun_one' => gettext('file'),
		'filters' => $filters,
		'custom' => $instance_select,
		'actions' => $filter_btn,
	));
?>
	<div class="collapse sf-advfilter<?=$is_filtered ? ' show' : ''?>" id="sf-advfilter">
		<p class="fs-muted small mb-2"><?=gettext('Matches the whole log window on the server. Prefix a value with ! to exclude it; values are regular expressions unless exact match is on.')?></p>
		<div class="sf-advgrid">
<?php
	foreach (array(
		array('filterlogentries_time', gettext('Date'), 'time'),
		array('filterlogentries_filename', gettext('File name'), 'filename'),
		array('filterlogentries_size', gettext('Size'), 'size'),
		array('filterlogentries_protocol', gettext('Protocol'), 'proto'),
		array('filterlogentries_sourceipaddress', gettext('Source address'), 'src_ip'),
		array('filterlogentries_sourceport', gettext('Source port'), 'src_port'),
		array('filterlogentries_destinationipaddress', gettext('Destination address'), 'dest_ip'),
		array('filterlogentries_destinationport', gettext('Destination port'), 'dest_port'),
	) as $ff):
?>
			<div>
				<label class="form-label" for="<?=$ff[0]?>"><?=fs_h($ff[1])?></label>
				<input type="text" class="form-control form-control-sm<?=in_array($ff[2], array('src_ip', 'dest_ip', 'src_port', 'dest_port')) ? ' fs-mono' : ''?>" name="<?=$ff[0]?>" id="<?=$ff[0]?>" value="<?=fs_h($filterfieldsarray[$ff[2]] ?? '')?>">
			</div>
<?php endforeach; ?>
		</div>
		<div class="sf-advchecks">
			<div class="form-check"><input class="form-check-input" type="checkbox" name="filterlogentries_exact_match" id="filterlogentries_exact_match" value="on"<?=$filterlogentries_exact_match == "on" ? ' checked' : ''?>><label class="form-check-label" for="filterlogentries_exact_match"><?=gettext('Exact match only')?></label></div>
		</div>
		<div class="sf-advbuttons">
			<button type="submit" class="btn btn-sm btn-primary" name="filterlogentries_submit" id="filterlogentries_submit" value="Apply Filter"><i class="fa-solid fa-filter icon-embed-btn" aria-hidden="true"></i><?=gettext('Apply filter')?></button>
			<button type="submit" class="btn btn-sm btn-outline-secondary no-confirm" name="filterlogentries_clear" id="filterlogentries_clear" value="Clear Filter"><?=gettext('Clear filter')?></button>
		</div>
	</div>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th data-sortable-type="alpha"><?=gettext("Time")?></th>
					<th data-fs-search><?=gettext("File")?></th>
					<th data-fs-search><?=gettext("Application")?></th>
					<th data-fs-search><?=gettext("Source")?></th>
					<th data-fs-search><?=gettext("Destination")?></th>
					<th data-fs-search><?=gettext("Protocol")?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($files as $x):
	$f = $x['f'];
	$name = (string)$f['fileinfo']['filename'];
	$check = '/suricata/suricata_filecheck.php?' . http_build_query(array('filehash' => $x['hash'], 'uuid' => $suricata_uuid, 'filename' => $name, 'filesize' => $x['size']), '', '&', PHP_QUERY_RFC3986);
?>
				<tr data-fs-filter-app="<?=fs_h(strtolower((string)$f['app_proto']))?>">
					<td class="fs-mono sf-time" data-value="<?=fs_h($f['timestamp'])?>"><?=fs_h($x['clock'])?><div class="fs-muted small"><?=fs_h($x['date'])?></div></td>
					<td class="sf-file">
						<div class="sf-file-name"><?=fs_h($name)?></div>
						<div class="sf-file-meta">
							<span class="fs-mono"><?=fs_h($x['size'])?></span>
<?php if ($x['hash'] !== 'none'): ?>
							<span class="fs-mono fs-muted sf-hash" title="<?=fs_h($x['hash'])?>"><?=fs_h($x['hash'])?></span>
<?php endif; ?>
<?php if ($x['stored']): ?>
							<span class="fs-chip is-on"><?=gettext('Stored')?></span>
<?php endif; ?>
						</div>
					</td>
					<td><span class="fs-chip fs-chip--strong"><?=fs_h(strtoupper((string)$f['app_proto']))?></span></td>
					<td><?=$sf_host($x, 'src')?></td>
					<td><?=$sf_host($x, 'dst')?></td>
					<td class="fs-mono"><?=fs_h($f['proto'])?></td>
					<td class="fs-col-actions"><div class="fs-actions">
						<a class="fs-action" href="<?=fs_h($check)?>" target="_blank" rel="noopener" title="<?=fs_h(sprintf(gettext('Check %s'), $name))?>" aria-label="<?=fs_h(sprintf(gettext('Check %s'), $name))?>"><i class="fa-solid fa-file-shield" aria-hidden="true"></i></a>
					</div></td>
				</tr>
<?php endforeach; ?>
<?php
	if (empty($files)) {
		if (!$have_eve) {
			fs_empty_row(7, gettext('No file events yet. Enable the EVE JSON log with the File output type on this interface.'));
		} else {
			fs_empty_row(7, $is_filtered ? gettext('No files match the advanced filter.') : gettext('No files were logged on this interface.'));
		}
	}
?>
			</tbody>
		</table>
	</div>
</div>
</form>

<div class="sf-notes">
	<span><?=gettext('Needs the EVE JSON log with the File output type and tracked-file checksums. Enable File-Store to keep the files. Supported protocols: HTTP, SMTP, FTP, NFS and SMB.')?></span>
<?php if ($pconfig['frefresh'] == 'on'): ?>
	<span><?=gettext('The page refreshes every 60 seconds.')?></span>
<?php endif; ?>
</div>

<?php
fs_modal_form_begin('files-settings', gettext('Files view settings'), '/suricata/suricata_files.php', array('instance' => $instanceid));
?>
	<div class="mb-3 form-check">
		<input class="form-check-input" type="checkbox" name="frefresh" id="frefresh" value="on"<?=($pconfig['frefresh'] == 'on') ? ' checked' : ''?>>
		<label class="form-check-label" for="frefresh"><?=gettext('Refresh the page every 60 seconds')?></label>
	</div>
	<div class="mb-1">
		<label class="form-label" for="filenumber"><?=gettext('Files to show')?></label>
		<input class="form-control" type="number" min="1" name="filenumber" id="filenumber" value="<?=fs_h($fnentries)?>">
		<div class="form-text"><?=gettext('Number of most recent file events to read. Default is 250.')?></div>
	</div>
<?php
fs_modal_form_end(gettext('Save'), 'save', 'Save', 'fa-floppy-disk');
?>

<div class="modal fade" id="sf-lookup" tabindex="-1" aria-labelledby="sf-lookup-title" aria-hidden="true">
	<div class="modal-dialog modal-dialog-centered">
		<div class="modal-content">
			<div class="modal-header">
				<h2 class="modal-title" id="sf-lookup-title"><?=gettext('Host lookup')?></h2>
				<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?=gettext('Close')?>"></button>
			</div>
			<div class="modal-body sf-lookup">
				<dl>
					<dt><?=gettext('Address')?></dt><dd class="fs-mono" id="sf-lookup-ip"></dd>
					<dt><?=gettext('Reverse DNS')?></dt><dd id="sf-lookup-dns"></dd>
					<dt><?=gettext('GeoIP')?></dt><dd id="sf-lookup-geo"></dd>
				</dl>
			</div>
			<div class="modal-footer">
				<button type="button" class="btn btn-primary" data-bs-dismiss="modal"><?=gettext('Close')?></button>
			</div>
		</div>
	</div>
</div>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	var page = "/suricata/suricata_files.php";
	var loading = <?=json_encode(gettext('Loading…'))?>;

	function parse(req) {
		try { return JSON.parse(req.responseText); } catch (e) { return {}; }
	}

	// Pick another interface: post the form so an active filter is kept
	$('#instance').on('change', function() {
		document.getElementById('formfile').submit();
	});

	// Remove block: the confirmed click fills the hidden fields, then the form posts
	document.addEventListener('click', function(e) {
		var btn = e.target.closest('button[data-sf-ip]');
		if (!btn || e.defaultPrevented) {
			return;
		}
		$('#ip').val(btn.getAttribute('data-sf-ip'));
		$('#mode').val('unblock');
	});

	// Host lookup: reverse DNS, and GeoIP for public addresses
	document.addEventListener('click', function(e) {
		var btn = e.target.closest('[data-sf-lookup]');
		if (!btn) {
			return;
		}
		var ip = btn.getAttribute('data-sf-lookup');
		$('#sf-lookup-ip').text(ip);
		$('#sf-lookup-dns').text(loading);
		bootstrap.Modal.getOrCreateInstance(document.getElementById('sf-lookup')).show();
		$.ajax(page, {type: 'post', dataType: 'json', data: {resolve: ip}, complete: function(req) {
			$('#sf-lookup-dns').text(parse(req).resolve_text || <?=json_encode(gettext('Cannot resolve'))?>);
		}});
		if (btn.getAttribute('data-sf-geo') === '1') {
			$('#sf-lookup-geo').text(loading);
			$.ajax(page, {type: 'post', dataType: 'json', data: {geoip: ip}, complete: function(req) {
				$('#sf-lookup-geo').text(parse(req).geoip_text || <?=json_encode(gettext('Not available'))?>);
			}});
		} else {
			$('#sf-lookup-geo').text(<?=json_encode(gettext('Private address'))?>);
		}
	});
});
//]]>
</script>
<?php
include("foot.inc");
?>
