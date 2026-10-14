<?php
/*
 * threatshield_querylog.php
 * FreeSense Threat Shield - query log with server-side search, paging and
 * one-click unblock / block
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Status: Threat Shield Query Log
##|*DESCR=Inspect live DNS queries and threat blocks
##|*MATCH=threatshield/threatshield_querylog.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');
require_once('/usr/local/pkg/threatshield/threatshield_ui.inc');

$cfg = threatshield_config();
$statuses = ['all' => gettext('All queries'), 'blocked' => gettext('Blocked'), 'whitelisted' => gettext('Allowed by allowlist'),
    'rewritten' => gettext('Rewritten'), 'processed' => gettext('Answered normally')];
$search = trim((string)($_GET['search'] ?? ''));
$status = array_key_exists($_GET['status'] ?? '', $statuses) ? $_GET['status'] : 'all';
$limit = in_array((int)($_GET['limit'] ?? 50), [50, 100, 250], true) ? (int)$_GET['limit'] : 50;
$older = (string)($_GET['older_than'] ?? '');
if ($older !== '' && !preg_match('/^[0-9T:.+\-Z]{10,40}$/', $older)) $older = '';
$query = array_filter(['search' => $search, 'status' => ($status !== 'all') ? $status : '', 'limit' => ($limit !== 50) ? (string)$limit : ''], 'strlen');
$self = 'threatshield_querylog.php' . (empty($query) ? '' : '?' . http_build_query($query));

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$domain = (string)($_POST['domain'] ?? '');
	$message = null;
	if (isset($_POST['unblock'])) {
		if (threatshield_allowlist_add($cfg, $domain, true, 'querylog', '', $message)) {
			threatshield_apply($cfg, gettext('Threat Shield: allowed a domain from the query log'), $message);
		} else {
			threatshield_flash('warn', $message);
		}
	} elseif (isset($_POST['block'])) {
		if (threatshield_block_domain($cfg, $domain, $message)) {
			threatshield_apply($cfg, gettext('Threat Shield: blocked a domain from the query log'), $message);
		} else {
			threatshield_flash('warn', $message);
		}
	}
	threatshield_redirect($self);
}

$running = threatshield_is_running();
$params = ['limit' => $limit, 'response_status' => ($status === 'blocked') ? 'filtered' : $status];
if ($search !== '') $params['search'] = $search;
if ($older !== '') $params['older_than'] = $older;
$raw_log = $running ? threatshield_api_request('querylog?' . http_build_query($params), 'GET', null, 3) : null;
$entries = (array)($raw_log['data'] ?? []);
$oldest = (string)($raw_log['oldest'] ?? '');
$dhcp_hosts = threatshield_get_dhcp_hostnames();

/* AdGuard Home filtering reasons (internal/filtering Reason). Safe search answers with a rewrite. */
$blocked_reasons = ['FilteredBlackList', 'FilteredSafeBrowsing', 'FilteredParental', 'FilteredInvalid', 'FilteredBlockedService'];
$rewrite_reasons = ['Rewrite', 'RewriteEtcHosts', 'RewriteRule', 'FilteredSafeSearch'];
$reason_labels = ['FilteredSafeBrowsing' => gettext('Safe browsing'), 'FilteredParental' => gettext('Parental control'),
    'FilteredBlockedService' => gettext('Blocked service'), 'FilteredInvalid' => gettext('Invalid request')];

/* which list a rule came from: AdGuard reports the filter id */
$list_names = [0 => gettext('Custom rules')];
$feeds = array_values(array_filter(threatshield_normalize_list($cfg['feeds'] ?? []), fn($f) => is_array($f) && (string)($f['url'] ?? '') !== ''));
foreach (threatshield_filter_ids($feeds) as $i => $id) $list_names[$id] = (string)($feeds[$i]['name'] ?? '');

$count_blocked = 0;
$latency_sum = 0.0;
foreach ($entries as $e) {
	if (in_array($e['reason'] ?? '', $blocked_reasons, true)) $count_blocked++;
	$latency_sum += (float)($e['elapsedMs'] ?? 0);
}
$filtered = ($search !== '' || $status !== 'all');

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Query log')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];
fs_page_action(gettext('Refresh'), $self, 'fa-arrows-rotate', 'secondary');
fs_page_action(gettext('Allowlist'), 'threatshield_allowlist.php', 'fa-circle-check', 'secondary');

include('head.inc');
threatshield_print_messages();
threatshield_display_tabs('querylog');

if (!$running) {
	print_callout(htmlspecialchars(gettext('Threat Shield is not running, so the query log cannot be read.')), 'warning');
} elseif (($cfg['querylog_enabled'] ?? 'on') !== 'on') {
	print_callout(htmlspecialchars(gettext('The query log is turned off under Settings, so no new queries are recorded.')), 'info');
}
?>

<div class="fs-tiles">
<?php
fs_tile(gettext('Queries shown'), number_format(count($entries)), null, $filtered ? gettext('Matching the filter') : gettext('Newest first'));
fs_tile(gettext('Blocked'), number_format($count_blocked));
fs_tile(gettext('Average latency'), (count($entries) > 0 ? round($latency_sum / count($entries), 1) : 0) . ' ms');
?>
</div>

<?php
ob_start();
?>
<form method="get" action="threatshield_querylog.php" class="ts-log-filter">
	<div class="fs-search"><i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
		<input type="search" class="form-control" name="search" value="<?=htmlspecialchars($search)?>"
		    placeholder="<?=gettext('Domain or client…')?>" aria-label="<?=gettext('Filter by domain or client')?>" autocomplete="off">
	</div>
	<select name="status" class="form-select form-select-sm" aria-label="<?=gettext('Status')?>" data-ts-autosubmit>
<?php foreach ($statuses as $k => $label): ?>
		<option value="<?=$k?>"<?=($status === $k) ? ' selected' : ''?>><?=htmlspecialchars($label)?></option>
<?php endforeach; ?>
	</select>
	<select name="limit" class="form-select form-select-sm" aria-label="<?=gettext('Rows')?>" data-ts-autosubmit>
<?php foreach ([50, 100, 250] as $n): ?>
		<option value="<?=$n?>"<?=($limit === $n) ? ' selected' : ''?>><?=sprintf(gettext('%d rows'), $n)?></option>
<?php endforeach; ?>
	</select>
	<button type="submit" class="btn btn-sm btn-outline-secondary"><i class="fa-solid fa-filter icon-embed-btn" aria-hidden="true"></i><?=gettext('Filter')?></button>
<?php if ($filtered): ?>
	<a class="btn btn-sm btn-link" href="threatshield_querylog.php"><?=gettext('Clear')?></a>
<?php endif; ?>
</form>
<?php
$filterform = ob_get_clean();
?>

<div class="panel panel-default fs-table">
<?php fs_table_toolbar(['search' => false, 'noun' => gettext('queries'), 'noun_one' => gettext('query'), 'custom' => $filterform]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover table-sm ts-log">
			<thead>
				<tr>
					<th><?=gettext('Time')?></th>
					<th><?=gettext('Client')?></th>
					<th><?=gettext('Domain')?></th>
					<th><?=gettext('Type')?></th>
					<th><?=gettext('Status')?></th>
					<th class="ts-num"><?=gettext('Latency')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php
foreach ($entries as $e):
	$time = isset($e['time']) ? date('H:i:s', strtotime($e['time'])) : '-';
	$client_ip = (string)($e['client'] ?? '-');
	$hostname = (string)($dhcp_hosts[$client_ip] ?? ($e['client_info']['name'] ?? ''));
	$domain = (string)($e['question']['name'] ?? '-');
	$type = (string)($e['question']['type'] ?? 'A');
	$reason = (string)($e['reason'] ?? 'NotFilteredNotFound');
	$elapsed = round((float)($e['elapsedMs'] ?? 0), 1);
	$is_blocked = in_array($reason, $blocked_reasons, true);
	$rule = (array)(($e['rules'] ?? [])[0] ?? []);
	$by = isset($rule['filter_list_id']) ? ($list_names[(int)$rule['filter_list_id']] ?? gettext('A list')) : ($reason_labels[$reason] ?? '');
	if ($reason === 'NotFilteredWhiteList') $by = isset($rule['filter_list_id']) && (int)$rule['filter_list_id'] === 0 ? gettext('Allowlist') : $by;
	$domain_q = rawurlencode($domain);
	$action = $is_blocked
	    ? ['custom', $self . (empty($query) ? '?' : '&') . 'unblock=1&domain=' . $domain_q, $domain, [
		'icon' => 'fa-solid fa-circle-check', 'post' => true, 'label' => sprintf(gettext('Unblock %s'), $domain),
		'confirm' => sprintf(gettext('Always allow “%s”?'), $domain),
		'detail' => gettext('It is added to the allowlist with its subdomains and applied at once.'),
		'confirm_action' => gettext('Unblock')]]
	    : ['custom', $self . (empty($query) ? '?' : '&') . 'block=1&domain=' . $domain_q, $domain, [
		'icon' => 'fa-solid fa-ban', 'post' => true, 'label' => sprintf(gettext('Block %s'), $domain),
		'confirm' => sprintf(gettext('Block “%s”?'), $domain),
		'detail' => gettext('A block rule for the domain and its subdomains is added to the custom rules and applied.'),
		'confirm_action' => gettext('Block')]];
?>
				<tr>
					<td class="fs-mono ts-nowrap"><?=htmlspecialchars((string)$time)?></td>
					<td>
						<span class="fs-mono"><?=htmlspecialchars($client_ip)?></span>
<?php	if ($hostname !== ''): ?>
						<div class="fs-muted small"><?=htmlspecialchars($hostname)?></div>
<?php	endif; ?>
					</td>
					<td class="fs-mono ts-domain"><?=htmlspecialchars($domain)?></td>
					<td><span class="fs-chip fs-chip--mono"><?=htmlspecialchars($type)?></span></td>
					<td>
<?php	if ($is_blocked): ?>
						<?=fs_badge('block', gettext('Blocked'), (string)($rule['text'] ?? $reason))?>
<?php	elseif ($reason === 'NotFilteredWhiteList'): ?>
						<?=fs_badge('pass', gettext('Allowlisted'), (string)($rule['text'] ?? ''))?>
<?php	elseif (in_array($reason, $rewrite_reasons, true)): ?>
						<?=fs_badge('info', gettext('Rewritten'))?>
<?php	else: ?>
						<?=fs_badge('neutral', gettext('Answered'))?>
<?php	endif; ?>
<?php	if ($by !== ''): ?>
						<div class="fs-muted small"><?=htmlspecialchars($by)?></div>
<?php	endif; ?>
					</td>
					<td class="ts-num"><?=$elapsed?> ms</td>
					<td class="fs-col-actions"><?=fs_row_actions([$action])?></td>
				</tr>
<?php
endforeach;
if (empty($entries)) {
	fs_empty_row(7, $filtered ? gettext('No queries match the filter.') :
	    ($running ? gettext('No queries logged yet.') : gettext('No query log while Threat Shield is not running.')));
}
?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer ts-pager small">
		<span class="fs-muted me-auto"><?=gettext('Unblock adds the domain to the allowlist; block adds a custom rule. Both include subdomains.')?></span>
<?php if ($older !== ''): ?>
		<a class="btn btn-sm btn-outline-secondary" href="<?=htmlspecialchars($self)?>"><?=gettext('Newest')?></a>
<?php endif; ?>
<?php if ($oldest !== '' && count($entries) >= $limit): ?>
		<a class="btn btn-sm btn-outline-secondary" href="threatshield_querylog.php?<?=htmlspecialchars(http_build_query($query + ['older_than' => $oldest]))?>"><?=gettext('Older')?> <i class="fa-solid fa-angle-right" aria-hidden="true"></i></a>
<?php endif; ?>
	</div>
</div>

<?php threatshield_ui_styles(); ?>
<style>
.ts-log-filter { display: flex; flex-wrap: wrap; align-items: center; gap: var(--fs-sp-2); flex: 1 1 32rem; }
.ts-log-filter .fs-search { flex: 1 1 14rem; }
.ts-log-filter .form-select { width: auto; }
.ts-log .ts-domain { word-break: break-all; min-width: 12rem; }
</style>
<script>
//<![CDATA[
events.push(function () {
	document.querySelectorAll('[data-ts-autosubmit]').forEach(function (sel) {
		sel.addEventListener('change', function () { sel.form.submit(); });
	});
});
//]]>
</script>

<?php include('foot.inc'); ?>
