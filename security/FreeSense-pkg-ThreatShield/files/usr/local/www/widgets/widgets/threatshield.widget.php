<?php
/*
 * threatshield.widget.php
 * FreeSense Dashboard Widget for Threat Shield
 */

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

$running = threatshield_is_running();
$stats = threatshield_get_stats();
$cfg = threatshield_config();

$total_queries = (int)($stats['num_dns_queries'] ?? 0);
$blocked_queries = (int)($stats['num_blocked_filtering'] ?? 0);
$blocked_pct = ($total_queries > 0) ? round(($blocked_queries / $total_queries) * 100, 1) : 0;
$latency = round((float)($stats['avg_processing_time'] ?? 0) * 1000, 1);
$geoip_count = count($cfg['geoip_countries'] ?? []);
?>

<div class="table-responsive">
	<table class="table table-striped table-hover table-condensed">
		<tbody>
			<tr>
				<td><strong><?=gettext('Threat Shield Status')?></strong></td>
				<td>
					<?php if ($running): ?>
						<span class="badge bg-success"><?=gettext('Active & Protecting')?></span>
					<?php else: ?>
						<span class="badge bg-secondary"><?=gettext('Stopped')?></span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<td><strong><?=gettext('DNS Queries (24h)')?></strong></td>
				<td><?=number_format($total_queries)?></td>
			</tr>
			<tr>
				<td><strong><?=gettext('Threats & Ads Blocked')?></strong></td>
				<td>
					<span class="badge bg-danger"><?=number_format($blocked_queries)?> (<?=$blocked_pct?>%)</span>
				</td>
			</tr>
			<tr>
				<td><strong><?=gettext('Average Query Latency')?></strong></td>
				<td><?=$latency?> ms</td>
			</tr>
			<tr>
				<td><strong><?=gettext('GeoIP Shield')?></strong></td>
				<td>
					<?php if ($cfg['geoip_enable'] === 'on'): ?>
						<span class="badge bg-primary"><?=$geoip_count?> <?=gettext('Countries Filtered')?></span>
					<?php else: ?>
						<span class="badge bg-secondary"><?=gettext('Disabled')?></span>
					<?php endif; ?>
				</td>
			</tr>
		</tbody>
	</table>
</div>
<div class="text-end mt-2">
	<a href="/threatshield/threatshield_status.php" class="btn btn-sm btn-outline-primary"><?=gettext('View Analytics')?></a>
	<a href="/threatshield/threatshield_querylog.php" class="btn btn-sm btn-outline-secondary"><?=gettext('Query Log')?></a>
</div>
