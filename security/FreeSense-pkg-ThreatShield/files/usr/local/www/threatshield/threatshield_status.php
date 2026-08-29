<?php
/*
 * threatshield_status.php
 * FreeSense Threat Shield - Real-Time Dashboard & Analytics
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Status: Threat Shield
##|*DESCR=View FreeSense Threat Shield dashboard and metrics
##|*MATCH=threatshield/threatshield_status.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

$savemsg = null;
$running = threatshield_is_running();
$cfg = threatshield_config();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
	$act = $_POST['action'];
	if ($act === 'restart') {
		threatshield_service_control('restart');
		$savemsg = gettext('Threat Shield daemon restarted.');
	} elseif ($act === 'update_feeds') {
		mwexec_bg('/usr/local/sbin/freesense-threatshield-update all force');
		$savemsg = gettext('Threat feeds and GeoIP update started in the background.');
	}
}

$stats = threatshield_get_stats();
$dhcp_hosts = threatshield_get_dhcp_hostnames();

$total_queries = (int)($stats['num_dns_queries'] ?? 0);
$blocked_queries = (int)($stats['num_blocked_filtering'] ?? 0);
$blocked_pct = ($total_queries > 0) ? round(($blocked_queries / $total_queries) * 100, 1) : 0;
$latency = round((float)($stats['avg_processing_time'] ?? 0) * 1000, 2);

$top_queried = $stats['top_queried_domains'] ?? [];
$top_blocked = $stats['top_blocked_domains'] ?? [];
$top_clients = $stats['top_clients'] ?? [];

$pgtitle = [gettext('Status'), gettext('Threat Shield'), gettext('Dashboard & Metrics')];
$pglinks = ['', '@self', '@self'];

include('head.inc');

if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('status');
?>

<div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3">
	<div>
		<h2 class="h3 mb-1"><i class="fa-solid fa-chart-line text-primary me-2"></i><?=gettext('Threat Shield Live Analytics')?></h2>
		<p class="text-muted mb-0"><?=gettext('Real-time DNS query statistics, threat block rates, latency, and client activity.')?></p>
	</div>
	<div class="d-flex gap-2">
		<form method="post" class="d-inline">
			<input type="hidden" name="action" value="update_feeds">
			<button type="submit" class="btn btn-outline-primary"><i class="fa-solid fa-cloud-arrow-down me-2"></i><?=gettext('Sync Feeds')?></button>
		</form>
		<form method="post" class="d-inline">
			<input type="hidden" name="action" value="restart">
			<button type="submit" class="btn btn-outline-secondary"><i class="fa-solid fa-arrows-rotate me-2"></i><?=gettext('Restart Daemon')?></button>
		</form>
	</div>
</div>

<div class="row g-3 mb-3">
	<div class="col-sm-6 col-xl-3">
		<div class="card h-100 shadow-sm">
			<div class="card-body">
				<div class="text-uppercase text-muted small fw-semibold mb-2"><?=gettext('Total Queries (24h)')?></div>
		<div class="fs-4 fw-bold"><i class="fa-solid fa-server text-primary me-2"></i><?=number_format($total_queries)?></div>
			</div>
		</div>
	</div>
	<div class="col-sm-6 col-xl-3">
		<div class="card h-100 shadow-sm">
			<div class="card-body">
				<div class="text-uppercase text-muted small fw-semibold mb-2"><?=gettext('Threats & Ads Blocked')?></div>
				<div class="fs-4 text-danger fw-bold"><i class="fa-solid fa-ban me-2"></i><?=number_format($blocked_queries)?> <span class="fs-6 text-muted fw-normal">(<?=$blocked_pct?>%)</span></div>
			</div>
		</div>
	</div>
	<div class="col-sm-6 col-xl-3">
		<div class="card h-100 shadow-sm">
			<div class="card-body">
				<div class="text-uppercase text-muted small fw-semibold mb-2"><?=gettext('Average Latency')?></div>
				<div class="fs-4 text-info fw-bold"><i class="fa-solid fa-stopwatch me-2"></i><?=$latency?> ms</div>
			</div>
		</div>
	</div>
	<div class="col-sm-6 col-xl-3">
		<div class="card h-100 shadow-sm">
			<div class="card-body">
				<div class="text-uppercase text-muted small fw-semibold mb-2"><?=gettext('Engine Status')?></div>
				<div class="fs-4 fw-bold">
					<?php if ($running): ?>
						<span class="text-success"><i class="fa-solid fa-circle-check me-2"></i><?=gettext('Running')?></span>
					<?php else: ?>
						<span class="text-secondary"><i class="fa-solid fa-circle-stop me-2"></i><?=gettext('Stopped')?></span>
					<?php endif; ?>
				</div>
			</div>
		</div>
	</div>
</div>

<div class="row g-3 mb-3">
	<div class="col-lg-6">
		<div class="card h-100 shadow-sm">
			<div class="card-header">
				<h2 class="h5 mb-0"><i class="fa-solid fa-globe text-primary me-2"></i><?=gettext('Top Queried Domains')?></h2>
			</div>
			<div class="card-body p-0">
				<div class="table-responsive">
					<table class="table table-striped table-hover mb-0">
						<thead>
							<tr>
								<th><?=gettext('Domain')?></th>
								<th class="text-end"><?=gettext('Queries')?></th>
							</tr>
						</thead>
						<tbody>
							<?php if (empty($top_queried)): ?>
								<tr><td colspan="2" class="text-center text-muted py-3"><?=gettext('No query data recorded yet.')?></td></tr>
							<?php else: ?>
								<?php foreach ($top_queried as $item): ?>
									<?php 
										$domain = is_array($item) ? ($item['name'] ?? key($item)) : $item;
										$count = is_array($item) ? ($item['count'] ?? current($item)) : 1;
									?>
									<tr>
										<td class="font-monospace"><?=htmlspecialchars((string)$domain)?></td>
										<td class="text-end fw-semibold"><?=number_format((int)$count)?></td>
									</tr>
								<?php endforeach; ?>
							<?php endif; ?>
						</tbody>
					</table>
				</div>
			</div>
		</div>
	</div>

	<div class="col-lg-6">
		<div class="card h-100 shadow-sm">
			<div class="card-header">
				<h2 class="h5 mb-0"><i class="fa-solid fa-shield-virus text-danger me-2"></i><?=gettext('Top Blocked Threats & Domains')?></h2>
			</div>
			<div class="card-body p-0">
				<div class="table-responsive">
					<table class="table table-striped table-hover mb-0">
						<thead>
							<tr>
								<th><?=gettext('Blocked Domain')?></th>
								<th class="text-end"><?=gettext('Hits')?></th>
							</tr>
						</thead>
						<tbody>
							<?php if (empty($top_blocked)): ?>
								<tr><td colspan="2" class="text-center text-muted py-3"><?=gettext('No blocked domains recorded.')?></td></tr>
							<?php else: ?>
								<?php foreach ($top_blocked as $item): ?>
									<?php 
										$domain = is_array($item) ? ($item['name'] ?? key($item)) : $item;
										$count = is_array($item) ? ($item['count'] ?? current($item)) : 1;
									?>
									<tr>
										<td class="font-monospace text-danger"><?=htmlspecialchars((string)$domain)?></td>
										<td class="text-end fw-semibold text-danger"><?=number_format((int)$count)?></td>
									</tr>
								<?php endforeach; ?>
							<?php endif; ?>
						</tbody>
					</table>
				</div>
			</div>
		</div>
	</div>
</div>

<div class="card shadow-sm mb-3">
	<div class="card-header">
		<h2 class="h5 mb-0"><i class="fa-solid fa-laptop-code text-primary me-2"></i><?=gettext('Top Requesting LAN Clients')?></h2>
	</div>
	<div class="card-body p-0">
		<div class="table-responsive">
			<table class="table table-striped table-hover mb-0">
				<thead>
					<tr>
						<th><?=gettext('Client IP')?></th>
						<th><?=gettext('Hostname / Device')?></th>
						<th class="text-end"><?=gettext('Total Queries')?></th>
					</tr>
				</thead>
				<tbody>
					<?php if (empty($top_clients)): ?>
						<tr><td colspan="3" class="text-center text-muted py-3"><?=gettext('No client traffic logged yet.')?></td></tr>
					<?php else: ?>
						<?php foreach ($top_clients as $item): ?>
							<?php 
								$ip = is_array($item) ? ($item['name'] ?? key($item)) : $item;
								$count = is_array($item) ? ($item['count'] ?? current($item)) : 1;
								$hostname = $dhcp_hosts[$ip] ?? gettext('Unknown Host');
							?>
							<tr>
								<td class="font-monospace fw-bold"><?=htmlspecialchars((string)$ip)?></td>
								<td>
									<span class="badge bg-secondary"><?=htmlspecialchars((string)$hostname)?></span>
								</td>
								<td class="text-end fw-semibold"><?=number_format((int)$count)?></td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>
		</div>
	</div>
</div>

<?php include('foot.inc'); ?>
