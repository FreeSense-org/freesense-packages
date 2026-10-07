<?php
/*
 * threatshield_querylog.php
 * FreeSense Threat Shield - Live Interactive Query & Threat Inspector
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Status: Threat Shield Query Log
##|*DESCR=Inspect live DNS queries and threat blocks
##|*MATCH=threatshield/threatshield_querylog.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

$savemsg = null;
$input_errors = [];
$ts_config = threatshield_config();

// Handle instant block / whitelist actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	if (isset($_POST['quick_block']) && !empty($_POST['domain'])) {
		$dom = strtolower(rtrim(trim($_POST['domain']), '.'));
		if (!filter_var($dom, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
			$input_errors[] = gettext('The selected domain is invalid.');
		} else {
		$rule = "||{$dom}^";
		$existing = $ts_config['custom_rules'] ?? '';
		$ts_config['custom_rules'] = trim($existing . "\n" . $rule);
		if (threatshield_save_and_apply($ts_config, gettext('Threat Shield: blocked a domain.'), $input_errors)) $savemsg = sprintf(gettext('Domain %s added to custom block rules.'), htmlspecialchars($dom));
		}
	} elseif (isset($_POST['quick_allow']) && !empty($_POST['domain'])) {
		$dom = strtolower(rtrim(trim($_POST['domain']), '.'));
		if (!filter_var($dom, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
			$input_errors[] = gettext('The selected domain is invalid.');
		} else {
		$rule = "@@||{$dom}^";
		$existing = $ts_config['custom_rules'] ?? '';
		$ts_config['custom_rules'] = trim($existing . "\n" . $rule);
		if (threatshield_save_and_apply($ts_config, gettext('Threat Shield: whitelisted a domain.'), $input_errors)) $savemsg = sprintf(gettext('Domain %s added to custom whitelist rules.'), htmlspecialchars($dom));
		}
	}
}

$running = threatshield_is_running();
$raw_log = threatshield_api_request('querylog?limit=100');
$entries = $raw_log['data'] ?? [];
$dhcp_hosts = threatshield_get_dhcp_hostnames();
$blocked_reasons = ['FilteredBlocked', 'BlockedParental', 'BlockedSafeBrowsing'];

$search = trim($_GET['search'] ?? '');
$filter_status = $_GET['filter'] ?? 'all';
if (!in_array($filter_status, ['all', 'blocked', 'allowed'], true)) {
	$filter_status = 'all';
}

if ($search !== '' || $filter_status !== 'all') {
	$entries = array_filter($entries, function($item) use ($search, $filter_status, $blocked_reasons) {
		$domain = $item['question']['name'] ?? '';
		$client = $item['client'] ?? '';
		$reason = $item['reason'] ?? '';

		if ($search !== '') {
			if (stripos($domain, $search) === false && stripos($client, $search) === false) {
				return false;
			}
		}

		if ($filter_status === 'blocked') {
			return in_array($reason, $blocked_reasons, true);
		} elseif ($filter_status === 'allowed') {
			return !in_array($reason, $blocked_reasons, true);
		}

		return true;
	});
}

/* numbers for the tiles, over the entries shown */
$count_blocked = 0;
$count_rewritten = 0;
$latency_sum = 0.0;
foreach ($entries as $e) {
	$reason = $e['reason'] ?? '';
	if (in_array($reason, $blocked_reasons, true)) $count_blocked++;
	elseif ($reason === 'Rewrite') $count_rewritten++;
	$latency_sum += (float)($e['elapsedMs'] ?? 0);
}
$filtered = ($search !== '' || $filter_status !== 'all');

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Query log')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];

$refresh_query = http_build_query(array_filter(['search' => $search, 'filter' => ($filter_status !== 'all') ? $filter_status : ''], 'strlen'));
fs_page_action(gettext('Refresh'), 'threatshield_querylog.php' . (($refresh_query !== '') ? '?' . $refresh_query : ''), 'fa-arrows-rotate', 'secondary');
fs_page_action(gettext('Custom rules'), 'threatshield_rules.php', 'fa-code', 'secondary');

include('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('querylog');

if (!$running) {
	print_callout(gettext('Threat Shield is not running, so the query log cannot be read.'), 'warning');
} elseif (($ts_config['querylog_enabled'] ?? 'on') !== 'on') {
	print_callout(gettext('The query log is turned off under Settings, so no new queries are recorded.'), 'info');
}
?>

<div class="fs-tiles">
<?php
fs_tile(gettext('Queries shown'), number_format(count($entries)), null, $filtered ? gettext('Filtered, of the last 100') : gettext('The last 100 queries'));
fs_tile(gettext('Blocked'), number_format($count_blocked));
fs_tile(gettext('Rewritten'), number_format($count_rewritten));
fs_tile(gettext('Average latency'), (count($entries) > 0 ? round($latency_sum / count($entries), 1) : 0) . ' ms');
?>
</div>

<?php
/* server-side filter in the list toolbar (GET, so filtered views can be linked) */
ob_start();
?>
<form method="get" action="threatshield_querylog.php" class="ts-log-filter">
	<div class="fs-search"><i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
		<input type="search" class="form-control" name="search" value="<?=htmlspecialchars($search)?>"
		    placeholder="<?=gettext('Domain or client IP…')?>" aria-label="<?=gettext('Filter by domain or client IP')?>" autocomplete="off">
	</div>
	<select name="filter" class="form-select form-select-sm" aria-label="<?=gettext('Status')?>">
		<option value="all"<?=($filter_status === 'all') ? ' selected' : ''?>><?=gettext('All queries')?></option>
		<option value="blocked"<?=($filter_status === 'blocked') ? ' selected' : ''?>><?=gettext('Blocked only')?></option>
		<option value="allowed"<?=($filter_status === 'allowed') ? ' selected' : ''?>><?=gettext('Allowed only')?></option>
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
<?php fs_table_toolbar([
	'search' => false,
	'noun' => gettext('queries'),
	'noun_one' => gettext('query'),
	'custom' => $filterform,
]); ?>
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
	$hostname = (string)($dhcp_hosts[$client_ip] ?? '');
	$domain = (string)($e['question']['name'] ?? '-');
	$type = (string)($e['question']['type'] ?? 'A');
	$reason = $e['reason'] ?? 'NotFilteredNotFound';
	$elapsed = round((float)($e['elapsedMs'] ?? 0), 1);
	$is_blocked = in_array($reason, $blocked_reasons, true);
	$domain_q = rawurlencode($domain);
	if ($is_blocked) {
		$action = ['custom', 'threatshield_querylog.php?quick_allow=1&domain=' . $domain_q, $domain, [
			'icon' => 'fa-solid fa-circle-check', 'post' => true,
			'label' => sprintf(gettext('Allow %s'), $domain),
			'confirm' => sprintf(gettext('Always allow “%s”?'), $domain),
			'detail' => gettext('An allow rule for the domain and its subdomains is added to the custom rules and applied.'),
			'confirm_action' => gettext('Allow')]];
	} else {
		$action = ['custom', 'threatshield_querylog.php?quick_block=1&domain=' . $domain_q, $domain, [
			'icon' => 'fa-solid fa-ban', 'post' => true,
			'label' => sprintf(gettext('Block %s'), $domain),
			'confirm' => sprintf(gettext('Block “%s”?'), $domain),
			'detail' => gettext('A block rule for the domain and its subdomains is added to the custom rules and applied.'),
			'confirm_action' => gettext('Block')]];
	}
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
						<?=fs_badge('block', gettext('Blocked'), (string)$reason)?>
<?php	elseif ($reason === 'Rewrite'): ?>
						<?=fs_badge('info', gettext('Rewritten'))?>
<?php	else: ?>
						<?=fs_badge('pass', gettext('Allowed'))?>
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
	<div class="panel-footer small fs-muted">
		<i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('Shows the last 100 queries. Block and allow add a rule to the custom rules, for the domain and all its subdomains.')?>
	</div>
</div>

<style>
.ts-log-filter { display: flex; flex-wrap: wrap; align-items: center; gap: var(--fs-sp-2); flex: 1 1 32rem; }
.ts-log-filter .fs-search { flex: 1 1 14rem; }
.ts-log-filter .form-select { width: auto; }
.ts-log .ts-domain { word-break: break-all; min-width: 12rem; }
.ts-log .ts-nowrap { white-space: nowrap; }
.ts-log .ts-num { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
</style>
<script>
//<![CDATA[
events.push(function () {
	/* a new status choice applies at once, like the search button */
	var sel = document.querySelector('.ts-log-filter select[name="filter"]');
	if (sel) {
		sel.addEventListener('change', function () { sel.form.submit(); });
	}
});
//]]>
</script>

<?php include('foot.inc'); ?>
