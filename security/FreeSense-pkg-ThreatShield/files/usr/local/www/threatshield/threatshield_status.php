<?php
/*
 * threatshield_status.php
 * FreeSense Threat Shield - Overview: engine state, headline numbers and top lists
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Status: Threat Shield
##|*DESCR=View FreeSense Threat Shield dashboard and metrics
##|*MATCH=threatshield/threatshield_status.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

$input_errors = [];
$savemsg = null;
$cfg = threatshield_config();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
	$act = $_POST['action'];
	if ($act === 'restart') {
		if (threatshield_service_control('restart')) $savemsg = gettext('Threat Shield daemon restarted.');
		else $input_errors[] = gettext('Threat Shield could not be restarted. Check the service log and generated configuration.');
	} elseif ($act === 'update_feeds') {
		mwexec_bg('/usr/local/sbin/freesense-threatshield-update all force');
		$savemsg = gettext('Threat feeds and GeoIP update started in the background.');
	}
}

$running = threatshield_is_running();
$stats = threatshield_get_stats();
$dhcp_hosts = threatshield_get_dhcp_hostnames();

$total_queries = (int)($stats['num_dns_queries'] ?? 0);
$blocked_queries = (int)($stats['num_blocked_filtering'] ?? 0);
$blocked_pct = ($total_queries > 0) ? round(($blocked_queries / $total_queries) * 100, 1) : 0;
$latency = round((float)($stats['avg_processing_time'] ?? 0) * 1000, 2);
$threat_hits = (int)($stats['num_replaced_safebrowsing'] ?? 0) + (int)($stats['num_replaced_parental'] ?? 0);

/* AdGuard Home returns top lists as [{"name": count}, ...]; older builds as
 * [{"name": ..., "count": ...}]. Normalise both to [label, count]. */
$top_rows = function ($list) {
	$rows = [];
	foreach ((array)$list as $item) {
		$name = is_array($item) ? ($item['name'] ?? key($item)) : $item;
		$count = is_array($item) ? ($item['count'] ?? current($item)) : 1;
		$rows[] = [(string)$name, (int)$count];
	}
	return $rows;
};
$top_queried = $top_rows($stats['top_queried_domains'] ?? []);
$top_blocked = $top_rows($stats['top_blocked_domains'] ?? []);
$top_clients = $top_rows($stats['top_clients'] ?? []);

/* saved configuration facts for the summary card */
$enabled = ($cfg['enable'] ?? 'off') === 'on';
$mode_labels = [
	'primary' => gettext('Primary DNS'),
	'proxy' => gettext('Proxy behind the DNS Resolver'),
	'standalone' => gettext('Standalone'),
];
$feeds = threatshield_normalize_list($cfg['feeds'] ?? []);
$feeds_on = count(array_filter($feeds, function ($f) { return is_array($f) && ($f['enabled'] ?? '') === 'on'; }));
$policy = threatshield_normalize_list($cfg['geoip_policies'] ?? [])[0] ?? [];
$geo_countries = count(threatshield_normalize_list($cfg['geoip_countries'] ?? []));
$geo_text = (($cfg['geoip_enable'] ?? 'off') === 'on')
    ? sprintf((($policy['action'] ?? 'block_selected') === 'allow_selected') ? gettext('Allow %d countries only') : gettext('Block %d countries'), $geo_countries)
    : gettext('Off');
$protection = [];
foreach ([
	'enable_dnssec' => gettext('DNSSEC'),
	'safebrowsing_enabled' => gettext('Safe browsing'),
	'enable_safesearch' => gettext('SafeSearch'),
	'enable_parental' => gettext('Parental control'),
	'block_doh_canary' => gettext('Browser DoH canary'),
	'block_icloud_private_relay' => gettext('iCloud Private Relay'),
	'catch_rogue_dns' => gettext('DNS redirection'),
] as $key => $label) {
	if (($cfg[$key] ?? 'off') === 'on') $protection[] = $label;
}

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Overview')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];

fs_page_action(gettext('Update feeds'), 'threatshield_status.php?action=update_feeds', 'fa-cloud-arrow-down', 'secondary', ['usepost' => true]);
fs_page_action(gettext('Restart'), 'threatshield_status.php?action=restart', 'fa-arrows-rotate', 'secondary', [
	'usepost' => true,
	'data-fs-confirm' => gettext('Restart Threat Shield?'),
	'data-fs-confirm-detail' => gettext('DNS answers from Threat Shield pause for a few seconds while the daemon restarts.'),
	'data-fs-confirm-action' => gettext('Restart'),
]);

include('head.inc');

if ($input_errors) print_input_errors($input_errors);
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

threatshield_display_tabs('status');

if (!$enabled) {
	print_callout(gettext('Threat Shield is disabled. Turn it on under Settings to filter DNS and apply the GeoIP policy.'), 'warning');
} elseif (!$running) {
	print_callout(gettext('Threat Shield is enabled but not running, so there are no live numbers. Check the service log or restart it.'), 'warning');
}

fs_summary_card([
	'icon' => 'fa-shield-halved',
	'title' => gettext('Threat Shield'),
	'subtitle' => gettext('DNS filtering and GeoIP country policy'),
	'badges' => [
		$enabled ? fs_badge('enabled') : fs_badge('disabled'),
		$running ? fs_badge('up', gettext('Running')) : fs_badge($enabled ? 'down' : 'neutral', gettext('Stopped')),
	],
	'label' => gettext('Threat Shield summary'),
	'facts' => [
		[gettext('DNS mode'), $mode_labels[$cfg['dns_coordination_mode'] ?? 'primary'] ?? (string)($cfg['dns_coordination_mode'] ?? '')],
		[gettext('Listening port'), (string)($cfg['listen_port'] ?? ''), 'mono' => true],
		[gettext('Feeds'), sprintf(gettext('%1$d of %2$d enabled'), $feeds_on, count($feeds)), 'href' => 'threatshield_feeds.php',
		    'note' => sprintf(gettext('Updated %s'), threatshield_age(threatshield_last_update('feeds')))],
		[gettext('GeoIP'), $geo_text, 'href' => 'threatshield_geoip.php'],
		[gettext('Protection'), '', 'chips' => $protection, 'empty' => gettext('No extra protection enabled')],
	],
	'actions' => [[gettext('Settings'), 'threatshield.php', 'fa-sliders']],
]);
?>

<div class="fs-tiles">
<?php
fs_tile(gettext('DNS queries (24 h)'), number_format($total_queries));
fs_tile(gettext('Blocked by filters'), number_format($blocked_queries), null, sprintf(gettext('%s %% of all queries'), $blocked_pct));
fs_tile(gettext('Safe browsing & parental'), number_format($threat_hits), null, gettext('Answers replaced'));
fs_tile(gettext('Average latency'), $latency . ' ms');
?>
</div>

<?php
/* one compact ranking card: label column, share bar, count */
$ranking = function ($title, $noun, array $rows, $empty, $kind) use ($dhcp_hosts) {
	$max = 0;
	foreach ($rows as $r) $max = max($max, $r[1]);
?>
	<div class="panel panel-default fs-table ts-rank">
<?php	fs_table_toolbar(['title' => $title, 'search' => false, 'noun' => $noun]); ?>
		<div class="panel-body table-responsive">
			<table class="table table-hover">
				<thead>
					<tr>
						<th><?=($kind === 'client') ? gettext('Client') : gettext('Domain')?></th>
						<th class="ts-rank-count"><?=($kind === 'blocked') ? gettext('Hits') : gettext('Queries')?></th>
					</tr>
				</thead>
				<tbody>
<?php	foreach ($rows as list($name, $count)):
		$share = ($max > 0) ? max(2, (int)round($count / $max * 100)) : 0;
?>
					<tr>
						<td class="ts-rank-name">
							<span class="fs-mono"><?=htmlspecialchars($name)?></span>
<?php		if ($kind === 'client' && isset($dhcp_hosts[$name])): ?>
							<span class="fs-muted small"><?=htmlspecialchars((string)$dhcp_hosts[$name])?></span>
<?php		endif; ?>
							<span class="ts-bar<?=($kind === 'blocked') ? ' ts-bar--block' : ''?>" aria-hidden="true"><span style="width: <?=$share?>%"></span></span>
						</td>
						<td class="ts-rank-count"><?=number_format($count)?></td>
					</tr>
<?php	endforeach;
	if (empty($rows)) {
		fs_empty_row(2, $empty);
	}
?>
				</tbody>
			</table>
		</div>
	</div>
<?php
};
?>
<div class="ts-rank-grid">
<?php
$ranking(gettext('Top queried domains'), gettext('domains'), $top_queried, gettext('No queries recorded yet.'), 'queried');
$ranking(gettext('Top blocked domains'), gettext('domains'), $top_blocked, gettext('No blocked domains recorded yet.'), 'blocked');
?>
</div>
<?php
$ranking(gettext('Top clients'), gettext('clients'), $top_clients, gettext('No client traffic recorded yet.'), 'client');
?>

<style>
.ts-rank-grid { display: grid; grid-template-columns: minmax(0, 1fr); gap: 0 var(--fs-sp-4); }
@media (min-width: 992px) { .ts-rank-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.ts-rank-name { word-break: break-all; }
.ts-rank-name .fs-muted { margin-left: var(--fs-sp-2); word-break: normal; }
.ts-rank-count { width: 7rem; text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.ts-bar { display: block; height: 3px; margin-top: .3rem; border-radius: 2px; background: color-mix(in srgb, var(--fs-border) 60%, transparent); }
.ts-bar > span { display: block; height: 100%; border-radius: 2px; background: var(--fs-series-1); }
.ts-bar--block > span { background: var(--fs-block); }
</style>

<?php include('foot.inc'); ?>
