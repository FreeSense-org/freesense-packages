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

$raw_log = threatshield_api_request('querylog?limit=100');
$entries = $raw_log['data'] ?? [];
$dhcp_hosts = threatshield_get_dhcp_hostnames();

$search = trim($_GET['search'] ?? '');
$filter_status = $_GET['filter'] ?? 'all';

if ($search !== '' || $filter_status !== 'all') {
	$entries = array_filter($entries, function($item) use ($search, $filter_status) {
		$domain = $item['question']['name'] ?? '';
		$client = $item['client'] ?? '';
		$reason = $item['reason'] ?? '';

		if ($search !== '') {
			if (stripos($domain, $search) === false && stripos($client, $search) === false) {
				return false;
			}
		}

		if ($filter_status === 'blocked') {
			return in_array($reason, ['FilteredBlocked', 'BlockedParental', 'BlockedSafeBrowsing'], true);
		} elseif ($filter_status === 'allowed') {
			return !in_array($reason, ['FilteredBlocked', 'BlockedParental', 'BlockedSafeBrowsing'], true);
		}

		return true;
	});
}

$pgtitle = [gettext('Status'), gettext('Threat Shield'), gettext('Live Query Inspector')];
$pglinks = ['', '@self', '@self'];

include('head.inc');

if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('querylog');
?>

<div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3">
	<div>
		<h2 class="h3 mb-1"><i class="fa-solid fa-list-check text-primary me-2"></i><?=gettext('Live Query Inspector')?></h2>
		<p class="text-muted mb-0"><?=gettext('Real-time inspection of DNS traffic with instant one-click block and allow actions.')?></p>
	</div>
	<div class="d-flex gap-2">
		<a href="threatshield_querylog.php" class="btn btn-outline-secondary"><i class="fa-solid fa-arrows-rotate me-2"></i><?=gettext('Refresh Log')?></a>
	</div>
</div>

<div class="card shadow-sm mb-4">
	<div class="card-header">
		<form method="get" class="row g-2 align-items-center">
			<div class="col-md-6">
				<div class="input-group">
					<span class="input-group-text"><i class="fa-solid fa-magnifying-glass"></i></span>
					<input type="text" name="search" class="form-control" placeholder="<?=gettext('Filter by domain name or client IP...')?>" value="<?=htmlspecialchars($search)?>">
				</div>
			</div>
			<div class="col-md-4">
				<select name="filter" class="form-select" onchange="this.form.submit()">
					<option value="all" <?=$filter_status === 'all' ? 'selected' : ''?>><?=gettext('All Queries')?></option>
					<option value="blocked" <?=$filter_status === 'blocked' ? 'selected' : ''?>><?=gettext('Blocked Threats & Ads Only')?></option>
					<option value="allowed" <?=$filter_status === 'allowed' ? 'selected' : ''?>><?=gettext('Allowed Queries Only')?></option>
				</select>
			</div>
			<div class="col-md-2 text-end">
				<button type="submit" class="btn btn-primary w-100"><i class="fa-solid fa-filter me-2"></i><?=gettext('Filter')?></button>
			</div>
		</form>
	</div>
	<div class="card-body p-0">
		<div class="table-responsive">
			<table class="table table-striped table-hover align-middle mb-0">
				<thead>
					<tr>
						<th><?=gettext('Time')?></th>
						<th><?=gettext('Client')?></th>
						<th><?=gettext('Domain Queried')?></th>
						<th><?=gettext('Type')?></th>
						<th><?=gettext('Status')?></th>
						<th><?=gettext('Latency')?></th>
						<th class="text-end"><?=gettext('Actions')?></th>
					</tr>
				</thead>
				<tbody>
					<?php if (empty($entries)): ?>
						<tr>
							<td colspan="7" class="text-center text-muted py-4">
								<?=gettext('No matching DNS query log entries found.')?>
							</td>
						</tr>
					<?php else: ?>
						<?php foreach ($entries as $e): ?>
							<?php
								$time = isset($e['time']) ? date('H:i:s', strtotime($e['time'])) : '-';
								$client_ip = $e['client'] ?? '-';
								$hostname = $dhcp_hosts[$client_ip] ?? '';
								$domain = $e['question']['name'] ?? '-';
								$type = $e['question']['type'] ?? 'A';
								$reason = $e['reason'] ?? 'NotFilteredNotFound';
								$elapsed = round((float)($e['elapsedMs'] ?? 0), 1);
								$is_blocked = in_array($reason, ['FilteredBlocked', 'BlockedParental', 'BlockedSafeBrowsing'], true);
							?>
							<tr>
								<td class="text-nowrap text-muted small"><?=htmlspecialchars((string)$time)?></td>
								<td>
									<div class="font-monospace fw-bold"><?=htmlspecialchars((string)$client_ip)?></div>
									<?php if ($hostname !== ''): ?>
										<span class="badge bg-secondary"><?=htmlspecialchars((string)$hostname)?></span>
									<?php endif; ?>
								</td>
								<td class="font-monospace text-break">
									<strong class="<?=$is_blocked ? 'text-danger' : ''?>"><?=htmlspecialchars((string)$domain)?></strong>
								</td>
								<td><span class="badge border"><?=htmlspecialchars((string)$type)?></span></td>
								<td>
									<?php if ($is_blocked): ?>
										<span class="badge bg-danger"><i class="fa-solid fa-ban me-1"></i><?=gettext('BLOCKED')?></span>
									<?php elseif ($reason === 'Rewrite'): ?>
										<span class="badge bg-info"><i class="fa-solid fa-arrow-right-arrow-left me-1"></i><?=gettext('REWRITTEN')?></span>
									<?php else: ?>
										<span class="badge bg-success"><i class="fa-solid fa-check me-1"></i><?=gettext('ALLOWED')?></span>
									<?php endif; ?>
								</td>
								<td class="text-muted small"><?=$elapsed?> ms</td>
								<td class="text-end text-nowrap">
									<form method="post" class="d-inline">
										<input type="hidden" name="domain" value="<?=htmlspecialchars((string)$domain)?>">
										<?php if ($is_blocked): ?>
											<button type="submit" name="quick_allow" value="1" class="btn btn-sm btn-outline-success" title="<?=gettext('Whitelist Domain')?>">
												<i class="fa-solid fa-check me-1"></i><?=gettext('Allow')?>
											</button>
										<?php else: ?>
											<button type="submit" name="quick_block" value="1" class="btn btn-sm btn-outline-danger" title="<?=gettext('Block Domain')?>">
												<i class="fa-solid fa-ban me-1"></i><?=gettext('Block')?>
											</button>
										<?php endif; ?>
									</form>
								</td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>
		</div>
	</div>
</div>

<?php include('foot.inc'); ?>
