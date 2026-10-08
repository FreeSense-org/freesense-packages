<?php
/*
 * suricata_blocked.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2006-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2025-2026 The FreeSense Project
 * Copyright (c) 2003-2004 Manuel Kasper
 * Copyright (c) 2005 Bill Marquette
 * Copyright (c) 2009 Robert Zelaya Sr. Developer
 * Copyright (c) 2024 Bill Meeks
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

$suricatalogdir = SURICATALOGDIR;
$suri_pf_table = SURICATA_PF_TABLE;

$pconfig['brefresh'] = config_get_path('installedpackages/suricata/alertsblocks/brefresh', 'on');
$pconfig['blertnumber'] = config_get_path('installedpackages/suricata/alertsblocks/blertnumber', 500);
$bnentries = $pconfig['blertnumber'];

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

if ($_POST['mode'] == 'todelete') {
	$ip = "";
	if ($_POST['ip'])
		$ip = $_POST['ip'];
	if (is_ipaddr($ip))
		exec("/sbin/pfctl -t {$suri_pf_table} -T delete {$ip}");
	else
		$input_errors[] = gettext("An invalid IP address was provided as a parameter.");
}

if ($_POST['remove']) {
	exec("/sbin/pfctl -t {$suri_pf_table} -T flush");
	header("Location: /suricata/suricata_blocked.php");
	exit;
}

/* TODO: build a file with block ip and disc */
if ($_POST['download'])
{
	$blocked_ips_array_save = "";
	exec("/sbin/pfctl -t {$suri_pf_table} -T show", $blocked_ips_array_save);
	/* build the list */
	if (is_array($blocked_ips_array_save) && count($blocked_ips_array_save) > 0) {
		$save_date = date("Y-m-d-H-i-s");
		$file_name = "suricata_blocked_{$save_date}.tar.gz";
		safe_mkdir("{$g['tmp_path']}/suricata_blocked");
		file_put_contents("{$g['tmp_path']}/suricata_blocked/suricata_block.pf", "");
		foreach($blocked_ips_array_save as $counter => $fileline) {
			if (empty($fileline))
				continue;
			$fileline = trim($fileline, " \n\t");
			file_put_contents("{$g['tmp_path']}/suricata_blocked/suricata_block.pf", "{$fileline}\n", FILE_APPEND);
		}

		// Create a tar gzip archive of blocked host IP addresses
		exec("/usr/bin/tar -czf {$g['tmp_path']}/{$file_name} -C{$g['tmp_path']}/suricata_blocked suricata_block.pf");

		// If we successfully created the archive, send it to the browser.
		if(file_exists("{$g['tmp_path']}/{$file_name}")) {
			ob_start(); //important or other posts will fail
			if (isset($_SERVER['HTTPS'])) {
				header('Pragma: ');
				header('Cache-Control: ');
			} else {
				header("Pragma: private");
				header("Cache-Control: private, must-revalidate");
			}
			header("Content-Type: application/octet-stream");
			header("Content-length: " . filesize("{$g['tmp_path']}/{$file_name}"));
			header("Content-disposition: attachment; filename = {$file_name}");
			ob_end_clean(); //important or other post will fail
			readfile("{$g['tmp_path']}/{$file_name}");

			// Clean up the temp files and directory
			unlink_if_exists("{$g['tmp_path']}/{$file_name}");
			rmdir_recursive("{$g['tmp_path']}/suricata_blocked");
		} else
			$savemsg = gettext("An error occurred while creating archive");
	} else
		$savemsg = gettext("No content on suricata block list");
}

if ($_POST['save'])
{
	/* no errors */
	if (!$input_errors) {
		config_set_path('installedpackages/suricata/alertsblocks/brefresh', $_POST['brefresh'] ? 'on' : 'off');
		config_set_path('installedpackages/suricata/alertsblocks/blertnumber', $_POST['blertnumber']);
		write_config("Suricata pkg: updated BLOCKED tab settings.");
		header("Location: /suricata/suricata_blocked.php");
		exit;
	}
}

/* ------------------------------------------------- blocked hosts and their alerts */

$blocked_ips_array = suricata_get_blocked_ips();
$src_ip_list = array();

if (!empty($blocked_ips_array)) {
	/* Change IP from presentation to network form for use as array key */
	foreach ($blocked_ips_array as &$ip) {
		$ip = inet_pton($ip);
	}
	unset($ip);

	$tmpblocked = array_flip($blocked_ips_array);

	foreach (glob("{$suricatalogdir}*/block.log") as $alertfile) {
		$fd = fopen($alertfile, "r");
		if ($fd) {
			/*************** FORMAT for file -- BLOCK -- **************************************************************************/
			/* Line format: timestamp  action [**] [gid:sid:rev] msg [**] [Classification: class] [Priority: pri] {proto} ip:port */
			/**********************************************************************************************************************/
			$buf = "";
			while (($buf = fgets($fd)) !== FALSE) {
				$fields = array();
				$tmp = array();

				if (empty(trim($buf)))
					continue;

				$fields['time'] = substr($buf, 0, strpos($buf, '  '));
				try {
					$event_tm = date_create_from_format("m/d/Y-H:i:s.u", $fields['time']);
				} catch (Exception $e) {
					logger(LOG_WARNING, localize_text("found invalid timestamp entry in current blocks.log, the line will be ignored and skipped."), LOG_PREFIX_PKG_SURICATA);
					continue;
				}

				// [2] => GID, [3] => SID, [4] => REV, [5] => MSG, [6] => CLASSIFICATION, [7] = PRIORITY
				preg_match('/\[\*{2}\]\s\[((\d+):(\d+):(\d+))\]\s(.*)\[\*{2}\]\s\[Classification:\s(.*)\]\s\[Priority:\s(\d+)\]\s/', $buf, $tmp);
				$fields['gid'] = trim($tmp[2]);
				$fields['sid'] = trim($tmp[3]);
				$fields['msg'] = trim($tmp[5]);

				// [1] = PROTO, [2] => IP:PORT
				if (preg_match('/\{(.*)\}\s(.*)/', $buf, $tmp)) {
					$fields['ip'] = trim(substr($tmp[2], 0, strrpos($tmp[2], ':')));
					if (is_ipaddrv6($fields['ip']))
						$fields['ip'] = inet_ntop(inet_pton($fields['ip']));
				}

				// Skip records without a usable address (old log formats)
				if (empty($fields['ip']))
					continue;
				$fields['ip'] = inet_pton($fields['ip']);
				if (isset($tmpblocked[$fields['ip']])) {
					$src_ip_list[$fields['ip']][] = array(
						'time' => @date_format($event_tm, "m/d/Y") . " " . @date_format($event_tm, "H:i:s"),
						'msg' => $fields['msg'],
						'rule' => "{$fields['gid']}:{$fields['sid']}",
					);
				}
			}
			fclose($fd);
		}
	}

	/* Blocked addresses without a matching block.log entry are listed too */
	foreach ($blocked_ips_array as $blocked_ip) {
		if (!isset($src_ip_list[$blocked_ip])) {
			$src_ip_list[$blocked_ip] = array();
		}
	}
}

$hosts = array();
$counter = 0;
foreach ($src_ip_list as $blocked_ip => $blocked) {
	if ($counter > $bnentries)
		break;
	$counter++;
	$hosts[] = array('ip' => inet_ntop($blocked_ip), 'events' => array_reverse($blocked));
}

/* ------------------------------------------------------------------ the page */

$pglinks = array("", "/suricata/suricata_overview.php", "/suricata/suricata_events.php", "@self");
$pgtitle = array(gettext("Services"), gettext("Suricata"), gettext("Events"), gettext("Blocked hosts"));

fs_page_action(gettext('View settings'), '#', 'fa-sliders', 'secondary', ['data-fs-modal' => '#blocked-settings']);
fs_page_action(gettext('Download list'), 'suricata_blocked.php?download=Download', 'fa-download', 'secondary', ['usepost' => true]);
if (!empty($blocked_ips_array)) {
	fs_page_action(gettext('Remove all blocks'), 'suricata_blocked.php?remove=Clear', 'fa-unlock', 'danger', [
		'usepost' => true,
		'data-fs-confirm' => gettext('Remove every blocked host?'),
		'data-fs-confirm-detail' => gettext('The Suricata blocked hosts table is flushed. Hosts that trigger a blocking rule again are blocked again.'),
		'data-fs-confirm-action' => gettext('Remove all'),
	]);
}

include_once("head.inc");
suricata_display_primary_navigation('events');

suricata_display_section_navigation('events', 'blocked');

/* refresh every 60 secs */
if ($pconfig['brefresh'] == 'on') {
	print '<meta http-equiv="refresh" content="60;url=/suricata/suricata_blocked.php" />';
}

/* Display Alert message */
if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg);
}

$sf_is_public = function ($ip) {
	return !is_private_ip($ip) && (substr($ip, 0, 2) != 'fc') && (substr($ip, 0, 2) != 'fd');
};
$with_alerts = count(array_filter($hosts, function ($h) { return !empty($h['events']); }));
?>

<style>
.sf-reason { min-width: 16rem; overflow-wrap: anywhere; }
.sf-reason-msg { color: var(--fs-text-strong); }
.sf-more summary { color: var(--fs-text-muted); font-size: var(--fs-fs-sm); cursor: pointer; }
.sf-more ul { margin: .35rem 0 0; padding-left: 1rem; font-size: var(--fs-fs-sm); }
.sf-ip { overflow-wrap: anywhere; }
.sf-notes { display: flex; flex-wrap: wrap; gap: .4rem 1.5rem; margin: -.5rem 0 var(--fs-sp-5); color: var(--fs-text-muted); font-size: var(--fs-fs-sm); }
.sf-lookup dl { display: grid; grid-template-columns: 8rem minmax(0, 1fr); gap: .5rem 1rem; margin: 0; }
.sf-lookup dt { color: var(--fs-text-muted); font-weight: 500; }
.sf-lookup dd { margin: 0; overflow-wrap: anywhere; white-space: pre-line; }
@media (max-width: 575.98px) { .sf-lookup dl { grid-template-columns: 1fr; gap: .15rem; } .sf-lookup dd { margin-bottom: .5rem; } }
</style>

<div class="fs-tiles">
<?php
	fs_tile(gettext('Blocked hosts'), count($blocked_ips_array), count($blocked_ips_array) ? 'block' : null);
	fs_tile(gettext('With alert details'), $with_alerts, null, gettext('Found in the block logs'));
?>
</div>

<form action="/suricata/suricata_blocked.php" method="post" id="formblock">
	<input type="hidden" name="id" id="id" value="">
	<input type="hidden" name="ip" id="ip" value="">
	<input type="hidden" name="mode" id="mode" value="">

<div class="panel panel-default fs-table">
<?php
	fs_table_toolbar(array(
		'search' => gettext('Search addresses, alerts, rules…'),
		'noun' => gettext('hosts'),
		'noun_one' => gettext('host'),
		'filters' => array('family' => array(gettext('IPv4 and IPv6'), 'v4' => gettext('IPv4'), 'v6' => gettext('IPv6'))),
	));
?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th class="fs-col-status"><?=gettext('Status')?></th>
					<th data-fs-search><?=gettext('Host')?></th>
					<th data-sortable-type="alpha"><?=gettext('Last blocked')?></th>
					<th data-fs-search><?=gettext('Reason')?></th>
					<th data-fs-search><?=gettext('Rule')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($hosts as $h):
	$ev = $h['events'];
	$last = $ev[0] ?? null;
	$rules = array_values(array_unique(array_column($ev, 'rule')));
?>
				<tr data-fs-filter-family="<?=is_ipaddrv6($h['ip']) ? 'v6' : 'v4'?>">
					<td><?=fs_badge('block', gettext('Blocked'))?></td>
					<td class="fs-mono sf-ip"><?=fs_h($h['ip'])?></td>
					<td class="fs-mono"><?=$last ? fs_h($last['time']) : '<span class="fs-muted">' . gettext('Unknown') . '</span>'?></td>
					<td class="sf-reason">
<?php if ($last): ?>
						<span class="sf-reason-msg"><?=fs_h($last['msg'])?></span>
<?php	if (count($ev) > 1): ?>
						<details class="sf-more">
							<summary><?=fs_h(sprintf(gettext('%d earlier events'), count($ev) - 1))?></summary>
							<ul>
<?php		foreach (array_slice($ev, 1) as $e): ?>
								<li><span class="fs-mono fs-muted"><?=fs_h($e['time'])?></span> <?=fs_h($e['msg'])?> <span class="fs-mono fs-muted"><?=fs_h($e['rule'])?></span></li>
<?php		endforeach; ?>
							</ul>
						</details>
<?php	endif; ?>
<?php else: ?>
						<span class="fs-muted"><?=gettext('No entry in the block logs')?></span>
<?php endif; ?>
					</td>
					<td><div class="fs-chips">
<?php foreach ($rules as $r): ?>
						<span class="fs-chip fs-chip--mono"><?=fs_h($r)?></span>
<?php endforeach; ?>
					</div></td>
					<td class="fs-col-actions"><div class="fs-actions">
						<button type="button" class="fs-action" data-sf-lookup="<?=fs_h($h['ip'])?>" data-sf-geo="<?=$sf_is_public($h['ip']) ? '1' : '0'?>" title="<?=fs_h(sprintf(gettext('Look up %s'), $h['ip']))?>" aria-label="<?=fs_h(sprintf(gettext('Look up %s'), $h['ip']))?>"><i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i></button>
						<button type="submit" class="fs-action fs-action--delete" data-sf-ip="<?=fs_h($h['ip'])?>" title="<?=fs_h(sprintf(gettext('Remove block for %s'), $h['ip']))?>" aria-label="<?=fs_h(sprintf(gettext('Remove block for %s'), $h['ip']))?>"
							data-fs-confirm="<?=fs_h(sprintf(gettext('Remove the block for %s?'), $h['ip']))?>" data-fs-confirm-detail="<?=fs_h(gettext('The address is deleted from the blocked hosts table. A new alert can block it again.'))?>" data-fs-confirm-action="<?=fs_h(gettext('Remove block'))?>"><i class="fa-solid fa-unlock" aria-hidden="true"></i></button>
					</div></td>
				</tr>
<?php endforeach; ?>
<?php
	if (empty($hosts)) {
		fs_empty_row(6, gettext('Suricata is not blocking any hosts.'));
	}
?>
			</tbody>
		</table>
	</div>
</div>
</form>

<div class="sf-notes">
	<span><?=gettext('Only hosts blocked by Legacy mode interfaces are listed. Inline IPS mode drops packets instead; those alerts are marked on the Alerts page.')?></span>
<?php if ($pconfig['brefresh'] == 'on'): ?>
	<span><?=gettext('The page refreshes every 60 seconds.')?></span>
<?php endif; ?>
</div>

<?php
fs_modal_form_begin('blocked-settings', gettext('Blocked hosts view settings'), '/suricata/suricata_blocked.php');
?>
	<div class="mb-3 form-check">
		<input class="form-check-input" type="checkbox" name="brefresh" id="brefresh" value="on"<?=($pconfig['brefresh'] == 'on' || $pconfig['brefresh'] == '') ? ' checked' : ''?>>
		<label class="form-check-label" for="brefresh"><?=gettext('Refresh the page every 60 seconds')?></label>
	</div>
	<div class="mb-1">
		<label class="form-label" for="blertnumber"><?=gettext('Hosts to show')?></label>
		<input class="form-control" type="number" min="1" name="blertnumber" id="blertnumber" value="<?=fs_h($bnentries)?>">
		<div class="form-text"><?=gettext('Default is 500.')?></div>
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
	var page = "/suricata/suricata_blocked.php";
	var loading = <?=json_encode(gettext('Loading…'))?>;

	function parse(req) {
		try { return JSON.parse(req.responseText); } catch (e) { return {}; }
	}

	// Remove block: the confirmed click fills the hidden fields, then the form posts
	document.addEventListener('click', function(e) {
		var btn = e.target.closest('button[data-sf-ip]');
		if (!btn || e.defaultPrevented) {
			return;
		}
		$('#ip').val(btn.getAttribute('data-sf-ip'));
		$('#mode').val('todelete');
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
