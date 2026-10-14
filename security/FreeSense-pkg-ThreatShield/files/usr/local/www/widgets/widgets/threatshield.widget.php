<?php
/*
 * threatshield.widget.php
 * FreeSense Dashboard Widget for Threat Shield
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

$cfg = threatshield_config();
$enabled = ($cfg['enable'] ?? 'off') === 'on';
$running = threatshield_is_running();
$pause = threatshield_pause_state();
$stats = threatshield_get_stats();
$checks = $enabled ? threatshield_health() : [];
$worst = threatshield_health_worst($checks);
$dnsbl = threatshield_dnsbl_status();

$total_queries = (int)($stats['num_dns_queries'] ?? 0);
$blocked_queries = (int)($stats['num_blocked_filtering'] ?? 0);
$blocked_pct = ($total_queries > 0) ? round(($blocked_queries / $total_queries) * 100, 1) : 0;
$geo_policies = array_filter(threatshield_normalize_list($cfg['geoip_policies'] ?? []), fn($p) => is_array($p) && ($p['enable'] ?? 'on') === 'on');
$geo_countries = 0;
foreach ($geo_policies as $p) $geo_countries += count(threatshield_normalize_list($p['countries'] ?? []));
$problems = array_values(array_filter($checks, fn($c) => $c['state'] === 'fail' || $c['state'] === 'warn'));
$flood = (int)threatshield_pf_table_count(THREATSHIELD_T_FLOOD);
?>
<div class="table-responsive">
	<table class="table table-striped table-hover table-condensed">
		<tbody>
			<tr>
				<td><strong><?=gettext('Status')?></strong></td>
				<td>
<?php if (!$enabled): ?>
					<?=fs_badge('disabled', gettext('Off'))?>
<?php elseif (!$running): ?>
					<?=fs_badge('down', gettext('Stopped'))?>
<?php elseif ($pause['active']): ?>
					<?=fs_badge('pending', ($pause['until'] > 0) ? sprintf(gettext('Paused until %s'), date('H:i', $pause['until'])) : gettext('Paused'))?>
<?php elseif ($worst === 'fail'): ?>
					<?=fs_badge('error', gettext('Needs attention'))?>
<?php elseif ($worst === 'warn'): ?>
					<?=fs_badge('warn', gettext('Check'))?>
<?php else: ?>
					<?=fs_badge('up', gettext('Protecting'))?>
<?php endif; ?>
				</td>
			</tr>
<?php foreach (array_slice($problems, 0, 3) as $c): ?>
			<tr>
				<td class="ps-4 small"><?=htmlspecialchars($c['label'])?></td>
				<td class="small"><?=htmlspecialchars($c['detail'])?></td>
			</tr>
<?php endforeach; ?>
			<tr>
				<td><strong><?=gettext('DNS queries (24 h)')?></strong></td>
				<td><?=number_format($total_queries)?></td>
			</tr>
			<tr>
				<td><strong><?=gettext('Blocked')?></strong></td>
				<td><?=number_format($blocked_queries)?> (<?=$blocked_pct?>%)</td>
			</tr>
			<tr>
				<td><strong><?=gettext('GeoIP')?></strong></td>
				<td><?=(($cfg['geoip_enable'] ?? 'off') === 'on' && $geo_countries > 0) ? htmlspecialchars(sprintf(gettext('%d countries'), $geo_countries)) : gettext('Off')?></td>
			</tr>
<?php if (($cfg['dnsbl_enable'] ?? 'off') === 'on'): ?>
			<tr>
				<td><strong><?=gettext('Reputation')?></strong></td>
				<td>
					<?=htmlspecialchars(sprintf(gettext('%s sources blocked'), number_format((int)($dnsbl['cached_listed'] ?? 0))))?>
<?php	if (($dnsbl['breaker'] ?? 'closed') === 'open'): ?>
					<?=fs_badge('degraded', gettext('Lookups failing'))?>
<?php	endif; ?>
				</td>
			</tr>
<?php endif; ?>
<?php if ($flood > 0): ?>
			<tr>
				<td><strong><?=gettext('Flood offenders')?></strong></td>
				<td><?=number_format($flood)?></td>
			</tr>
<?php endif; ?>
		</tbody>
	</table>
</div>
<div class="text-end mt-2">
	<a href="/threatshield/threatshield_status.php" class="btn btn-sm btn-outline-primary"><?=gettext('Overview')?></a>
	<a href="/threatshield/threatshield_querylog.php" class="btn btn-sm btn-outline-secondary"><?=gettext('Query log')?></a>
</div>
