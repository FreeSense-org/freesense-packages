<?php
/*
 * syslog-ng_log_viewer.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2004-2026 The FreeSense Project
 * Copyright (c) 2012 Lance Leger
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
require("guiconfig.inc");
require_once("status_logs_common.inc");
require("/usr/local/pkg/syslog-ng.inc");

$objects = config_get_path('installedpackages/syslogngadvanced/config', []);
$default_logdir = config_get_path('installedpackages/syslogng/config/0/default_logdir');
$default_logfile = config_get_path('installedpackages/syslogng/config/0/default_logfile');
$compress_archives = config_get_path('installedpackages/syslogng/config/0/compress_archives');
$compress_type = config_get_path('installedpackages/syslogng/config/0/compress_type');

/* Only the log files of the configured file destinations can be read. */
$log_files = syslogng_get_log_files(is_array($objects) ? $objects : []);
$default_path = $default_logdir . "/" . $default_logfile;
if (($default_logdir != '') && ($default_logfile != '') && !in_array($default_path, $log_files, true)) {
	array_unshift($log_files, $default_path);
}
$logfile = $default_path;
if (!empty($_POST['logfile']) && in_array($_POST['logfile'], $log_files, true)) {
	$logfile = $_POST['logfile'];
}

$limits = array("10", "20", "50", "100", "250", "500");
$limit = "50";
if (!empty($_POST['limit']) && in_array((string)intval($_POST['limit']), $limits, true)) {
	$limit = (string)intval($_POST['limit']);
}

$archives = !empty($_POST['archives']);
$filter = isset($_POST['filter']) ? (string)$_POST['filter'] : '';
$not = !empty($_POST['not']);

$log_messages = array();
$log_lines = 0;
if (file_exists($logfile) && (filesize($logfile) > 0)) {
	$grep = "/usr/bin/grep -ih";

	if (($compress_archives == 'on') && glob($logfile . "*" . $compress_type) && $archives) {
		if ($compress_type == 'bz2') {
			$grep = "/usr/bin/bzgrep -ih";
		} else {
			$grep = "/usr/bin/zgrep -ih";
		}
	}

	$target = escapeshellarg($logfile) . ($archives ? "*" : "");
	if (($filter !== '') && $not) {
		$grepcmd = "{$grep} -v " . escapeshellarg($filter) . " {$target}";
	} else {
		$grepcmd = "{$grep} " . escapeshellarg($filter) . " {$target}";
	}

	$log_lines = (int)trim((string)shell_exec("{$grepcmd} | /usr/bin/wc -l"));
	$log_output = trim((string)shell_exec("{$grepcmd} | /usr/bin/sort -M | /usr/bin/tail -n {$limit}"));

	if ($log_output !== '') {
		$log_messages = explode("\n", $log_output);
	}
}
$shown = count($log_messages);
$filter_active = ($filter !== '') || $archives || $not || ($limit !== "50") || ($logfile !== $default_path);

/* "Oct  7 15:37:13 host program[pid]: message" or an ISO 8601 timestamp; null when not parseable */
$parse_line = function ($line) {
	if (preg_match('/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+([^\s\[:]+)(?:\[([^\]]*)\])?:\s?(.*)$/', $line, $m)) {
		return ['time' => $m[1], 'host' => $m[2], 'process' => $m[3], 'pid' => $m[4], 'message' => $m[5]];
	}
	return null;
};

/* Mono time cell; the date part is muted */
$time_cell = function ($time) {
	if (preg_match('/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})$/', $time, $m)) {
		return '<td class="fs-log-time" title="' . fs_h($time) . '"><span class="fs-log-date">' . fs_h($m[1] . ' ' . $m[2]) . '</span> ' . fs_h($m[3]) . '</td>';
	}
	return status_logs_time_cell(str_replace('T', ' ', $time));
};

$pgtitle = array(gettext("Services"), gettext("Syslog-ng"), gettext("Log viewer"));
$pglinks = array("", "/pkg_edit.php?xml=syslogng.xml&amp;id=0", "@self");

require_once("head.inc");

if ($savemsg) {
	print_info_box($savemsg);
}

$tab_array = array();
$tab_array[] = array(gettext("General"), false, "/pkg_edit.php?xml=syslogng.xml&amp;id=0");
$tab_array[] = array(gettext("Advanced"), false, "/pkg.php?xml=syslog-ng_advanced.xml");
$tab_array[] = array(gettext("Log Viewer"), true, "/syslog-ng_log_viewer.php");
display_top_tabs($tab_array);

status_logs_styles();
?>
<style>
.fs-sng-file { width: 16rem; }
.fs-sng-host { white-space: nowrap; color: var(--fs-text-muted); font-family: var(--fs-font-mono); font-size: var(--fs-fs-sm); }
@media (max-width: 575.98px) {
	.fs-sng-file { flex: 1 1 100%; width: auto; }
	.fs-sng-host, .fs-sng-hosth { display: none; }
}
</style>

<div class="panel panel-default fs-table" data-fs-table="syslog-ng">
<?php
$custom = '';
$custom .= '<select class="form-select form-select-sm fs-logfilter-field fs-sng-file" id="logfile" name="logfile" form="fs-logfilter" aria-label="' . fs_h(gettext('Log file')) . '">';
foreach ($log_files as $file) {
	$custom .= '<option value="' . fs_h($file) . '"' . (($file === $logfile) ? ' selected' : '') . '>' . fs_h($file) . '</option>';
}
$custom .= '</select>';
$custom .= status_logs_filter_field(['name' => 'filter', 'label' => gettext('Filter'), 'value' => $filter,
    'placeholder' => gettext('Filter (grep pattern)')], true);
$custom .= status_logs_filter_field(['name' => 'limit', 'label' => gettext('Limit'), 'type' => 'select', 'value' => $limit,
    'options' => array_combine($limits, array_map(function ($n) { return sprintf(gettext('Last %s'), $n); }, $limits)), 'small' => true], true);
$custom .= status_logs_filter_field(['name' => 'not', 'label' => gettext('Inverse (NOT)'), 'type' => 'check', 'check_value' => 'yes', 'checked' => $not], true);
$custom .= status_logs_filter_field(['name' => 'archives', 'label' => gettext('Include archives'), 'type' => 'check', 'check_value' => 'yes', 'checked' => $archives], true);
$custom .= '<button type="submit" class="btn btn-sm btn-primary" name="submit" value="Refresh" form="fs-logfilter">'
    . '<i class="fa-solid fa-arrows-rotate icon-embed-btn" aria-hidden="true"></i>' . fs_h(gettext('Refresh')) . '</button>';
if ($filter_active) {
	$custom .= '<a class="btn btn-sm btn-link" href="/syslog-ng_log_viewer.php">' . fs_h(gettext('Reset')) . '</a>';
}

fs_table_toolbar([
	'search' => gettext('Search shown entries…'),
	'noun' => gettext('entries'),
	'noun_one' => gettext('entry'),
	'filters' => ['level' => [gettext('All levels'), 'error' => gettext('Errors'), 'warn' => gettext('Warnings')]],
	'custom' => $custom,
]);
?>
	<form id="fs-logfilter" method="post" action="/syslog-ng_log_viewer.php" hidden></form>
	<div class="panel-body table-responsive">
		<table class="table table-hover fs-logtable" data-sortable>
			<thead>
				<tr>
					<th><?=gettext("Time")?></th>
					<th data-fs-search class="fs-sng-hosth"><?=gettext("Host")?></th>
					<th data-fs-search><?=gettext("Program")?></th>
					<th data-fs-search><?=gettext("Message")?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($log_messages as $line):
	$entry = $parse_line($line);
	if ($entry === null): ?>
				<tr<?=status_logs_row_attrs($line)?>><td class="fs-log-raw" colspan="4"><?=fs_h($line)?></td></tr>
<?php else: ?>
				<tr<?=status_logs_row_attrs($entry['message'])?>>
					<?=$time_cell($entry['time'])?>
					<td class="fs-sng-host"><?=fs_h($entry['host'])?></td>
					<td><?=status_logs_process_chip($entry['process'], $entry['pid'])?></td>
					<td class="fs-log-msg"><?=fs_h($entry['message'])?></td>
				</tr>
<?php endif;
endforeach;
if (empty($log_messages)) {
	fs_empty_row(4, ($filter !== '') ? gettext('No log messages match the filter.') : gettext('No log messages found, or the log file is empty.'));
}
?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer fs-logcard-foot">
		<span><?=fs_h(sprintf(gettext('Showing %1$d of %2$d matching messages'), $shown, $log_lines))?></span>
		<span><?=fs_h(gettext('The filter is a case-insensitive grep pattern; Inverse shows the lines that do not match.'))?></span>
	</div>
</div>

<?php include("foot.inc"); ?>
