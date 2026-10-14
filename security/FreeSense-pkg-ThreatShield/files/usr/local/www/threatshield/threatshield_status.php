<?php
/*
 * threatshield_status.php
 * FreeSense Threat Shield - Overview: quick setup, health, pause, numbers and top lists
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Status: Threat Shield
##|*DESCR=View FreeSense Threat Shield dashboard and metrics
##|*MATCH=threatshield/threatshield_status.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');
require_once('/usr/local/pkg/threatshield/threatshield_ui.inc');

$cfg = threatshield_config();
$self = 'threatshield_status.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	if (isset($_POST['quick_setup'])) {
		$errors = [];
		$messages = [];
		if (threatshield_quick_setup(isset($_POST['qs_block_dot']), isset($_POST['qs_block_doh']), $errors, $messages)) {
			threatshield_flash('ok', gettext('DNS blocking is on. Clients on the LAN now get filtered answers, and other DNS servers are redirected to Threat Shield.'));
			threatshield_flash('warn', $messages);
		} else {
			threatshield_flash('error', $errors);
		}
	} elseif (isset($_POST['fix'])) {
		threatshield_flash('ok', threatshield_run_fix((string)$_POST['fix']));
	} elseif (isset($_POST['pause'])) {
		$minutes = (int)$_POST['pause'];
		if (in_array($minutes, [0, 5, 30, 60, 240], true) && threatshield_pause($minutes * 60)) {
			threatshield_flash('ok', ($minutes > 0) ? sprintf(gettext('Blocking is paused for %d minutes.'), $minutes) : gettext('Blocking is paused until you resume it.'));
		} else {
			threatshield_flash('error', gettext('Blocking could not be paused: Threat Shield does not answer.'));
		}
	} elseif (isset($_POST['resume'])) {
		threatshield_resume();
		threatshield_flash('ok', gettext('Blocking resumed.'));
	} elseif (isset($_POST['unblock'])) {
		$message = null;
		if (threatshield_allowlist_add($cfg, (string)$_POST['unblock'], true, 'overview', '', $message)) {
			threatshield_apply($cfg, gettext('Threat Shield: allowed a domain from the overview'), $message);
		} else {
			threatshield_flash('warn', $message);
		}
	} elseif (isset($_POST['action']) && $_POST['action'] === 'restart') {
		threatshield_flash('ok', threatshield_run_fix('restart'));
	} elseif (isset($_POST['action']) && $_POST['action'] === 'update_feeds') {
		threatshield_flash('ok', threatshield_run_fix('update_feeds'));
	}
	@unlink(THREATSHIELD_CACHE_DIR . '/health.json');
	threatshield_redirect($self);
}

$enabled = ($cfg['enable'] ?? 'off') === 'on';
$running = threatshield_is_running();
$pause = threatshield_pause_state();
$stats = threatshield_get_stats();
$dhcp_hosts = threatshield_get_dhcp_hostnames();
$labels = threatshield_label_counters();
$dnsbl = threatshield_dnsbl_status();

$total_queries = (int)($stats['num_dns_queries'] ?? 0);
$blocked_queries = (int)($stats['num_blocked_filtering'] ?? 0);
$blocked_pct = ($total_queries > 0) ? round(($blocked_queries / $total_queries) * 100, 1) : 0;
$latency = round((float)($stats['avg_processing_time'] ?? 0) * 1000, 1);

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

$mode_labels = [
	'primary' => gettext('Primary DNS'),
	'proxy' => gettext('Proxy behind the DNS Resolver'),
	'standalone' => gettext('Standalone'),
];
$level_labels = ['custom' => gettext('Custom')] + array_map(fn($l) => $l[0], threatshield_feed_levels());
$feeds = array_filter(threatshield_normalize_list($cfg['feeds'] ?? []), fn($f) => is_array($f) && ($f['kind'] ?? 'block') === 'block');
$feeds_on = count(array_filter($feeds, fn($f) => ($f['enabled'] ?? '') === 'on'));
$allow_on = count(array_filter(threatshield_normalize_list($cfg['allowlist'] ?? []), fn($e) => is_array($e) && ($e['enabled'] ?? 'on') === 'on'));
$policy = threatshield_normalize_list($cfg['geoip_policies'] ?? [])[0] ?? [];
$geo_countries = count(threatshield_normalize_list($policy['countries'] ?? []));
$geo_text = (($cfg['geoip_enable'] ?? 'off') === 'on' && $geo_countries > 0)
    ? sprintf((($policy['action'] ?? 'block_selected') === 'allow_selected') ? gettext('Allow %d countries only') : gettext('Block %d countries'), $geo_countries)
    : gettext('Off');
$inbound = array_filter(threatshield_normalize_list($cfg['inbound_policies'] ?? []), fn($p) => is_array($p) && ($p['enable'] ?? 'on') === 'on');
$protection = [];
foreach ([
	'enable_dnssec' => gettext('DNSSEC'),
	'safebrowsing_enabled' => gettext('Safe browsing'),
	'enable_safesearch' => gettext('SafeSearch'),
	'enable_parental' => gettext('Parental control'),
	'catch_rogue_dns' => gettext('DNS redirection'),
	'block_dot' => gettext('DoT blocking'),
	'block_doh_ips' => gettext('DoH blocking'),
	'ipbl_enable' => gettext('IP lists'),
	'dnsbl_enable' => gettext('Reputation checks'),
] as $key => $label) {
	if (($cfg[$key] ?? 'off') === 'on') $protection[] = $label;
}

$pgtitle = [gettext('Services'), gettext('Threat Shield'), gettext('Overview')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];

if ($enabled) {
	fs_page_action(gettext('Download lists'), $self . '?action=update_feeds', 'fa-cloud-arrow-down', 'secondary', ['usepost' => true]);
	fs_page_action(gettext('Restart'), $self . '?action=restart', 'fa-arrows-rotate', 'secondary', [
		'usepost' => true,
		'data-fs-confirm' => gettext('Restart Threat Shield?'),
		'data-fs-confirm-detail' => gettext('DNS answers from Threat Shield pause for a few seconds while the daemon restarts.'),
		'data-fs-confirm-action' => gettext('Restart'),
	]);
}

include('head.inc');

threatshield_print_messages();
threatshield_display_tabs('status');

if (!$enabled):
?>
<div class="panel panel-default ts-quick">
	<div class="panel-body">
		<div class="ts-quick-icon"><i class="fa-solid fa-shield-halved" aria-hidden="true"></i></div>
		<div class="ts-quick-text">
			<h2><?=gettext('Block ads, trackers and malware for the whole network')?></h2>
			<p class="fs-muted"><?=gettext('One switch turns on DNS filtering with the recommended lists on every LAN interface. Devices that use their own DNS server are redirected to Threat Shield. Your DNS Resolver keeps answering local host names. Everything can be changed later under Settings.')?></p>
			<form method="post" action="<?=$self?>" class="ts-quick-form">
				<label class="form-check"><input class="form-check-input" type="checkbox" name="qs_block_doh" checked> <?=gettext('Also block known DNS-over-HTTPS servers, so browsers and apps cannot bypass the filter')?></label>
				<label class="form-check"><input class="form-check-input" type="checkbox" name="qs_block_dot" checked> <?=gettext('Also block DNS-over-TLS (port 853); turns off Android "Private DNS" on the LAN')?></label>
				<button type="submit" name="quick_setup" value="1" class="btn btn-primary"><i class="fa-solid fa-power-off icon-embed-btn" aria-hidden="true"></i><?=gettext('Enable DNS blocking')?></button>
			</form>
			<p class="small fs-muted mb-0"><?=gettext('Before anything changes, Threat Shield checks for port conflicts and other DNS services. If a test query fails afterwards, DNS redirection stays off so the LAN keeps working.')?></p>
		</div>
	</div>
</div>
<?php
elseif ($pause['active']):
	ob_start();
?>
	<form method="post" action="<?=$self?>" class="ts-inline-form">
		<?=($pause['until'] > 0) ? htmlspecialchars(sprintf(gettext('Blocking is paused until %s; every domain resolves.'), date('H:i', $pause['until']))) : htmlspecialchars(gettext('Blocking is paused until you resume it; every domain resolves.'))?>
		<button type="submit" name="resume" value="1" class="btn btn-sm btn-primary"><i class="fa-solid fa-play icon-embed-btn" aria-hidden="true"></i><?=gettext('Resume now')?></button>
	</form>
<?php
	print_callout(ob_get_clean(), 'warning', gettext('Blocking paused'));
elseif (!$running):
	print_callout(htmlspecialchars(gettext('Threat Shield is enabled but not running, so there are no live numbers. See the checks below.')), 'warning');
endif;

if ($enabled):
	fs_summary_card([
		'icon' => 'fa-shield-halved',
		'title' => gettext('Threat Shield'),
		'subtitle' => gettext('DNS filtering, IP reputation and country policy'),
		'badges' => [
			fs_badge('enabled'),
			$running ? ($pause['active'] ? fs_badge('pending', gettext('Paused')) : fs_badge('up', gettext('Protecting'))) : fs_badge('down', gettext('Stopped')),
		],
		'label' => gettext('Threat Shield summary'),
		'facts' => [
			[gettext('DNS mode'), $mode_labels[$cfg['dns_coordination_mode'] ?? 'primary'] ?? (string)($cfg['dns_coordination_mode'] ?? '')],
			[gettext('Blocklists'), sprintf(gettext('%1$s level, %2$d of %3$d lists'), $level_labels[$cfg['feed_level'] ?? 'custom'] ?? '', $feeds_on, count($feeds)),
			    'href' => 'threatshield_feeds.php', 'note' => sprintf(gettext('Updated %s'), threatshield_age(threatshield_last_update('feeds')))],
			[gettext('Allowlist'), sprintf(gettext('%d domains'), $allow_on), 'href' => 'threatshield_allowlist.php'],
			[gettext('GeoIP'), $geo_text, 'href' => 'threatshield_geoip.php'],
			[gettext('Inbound protection'), empty($inbound) ? '' : sprintf(gettext('%d policies'), count($inbound)), 'href' => 'threatshield_inbound.php', 'empty' => gettext('Off')],
			[gettext('Protection'), '', 'chips' => $protection, 'empty' => gettext('Filtering only')],
		],
		'actions' => [[gettext('Settings'), 'threatshield.php', 'fa-sliders']],
	]);
?>
<div class="ts-overview-grid">
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('Health')?></h2>
			<a class="btn btn-sm btn-link ts-recheck" href="threatshield_ajax.php?what=health&amp;deep=1" data-ts-health-deep><?=gettext('Run all checks')?></a>
		</div>
		<div class="panel-body p-0" id="ts-health" data-ts-health="threatshield_ajax.php?what=health">
			<p class="ts-health-loading fs-muted"><i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> <?=gettext('Checking…')?></p>
			<noscript><?=threatshield_health_html(threatshield_health())?></noscript>
		</div>
	</div>
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('Pause blocking')?></h2></div>
		<div class="panel-body">
			<p class="fs-muted small"><?=gettext('Lets every domain resolve for a while, for example to test whether Threat Shield breaks a site. IP lists, GeoIP and inbound protection keep working.')?></p>
			<form method="post" action="<?=$self?>" class="ts-pause">
<?php	foreach ([5 => gettext('5 min'), 30 => gettext('30 min'), 60 => gettext('1 hour'), 240 => gettext('4 hours'), 0 => gettext('Until resumed')] as $m => $label): ?>
				<button type="submit" name="pause" value="<?=$m?>" class="btn btn-sm btn-outline-secondary"<?=($running && !$pause['active']) ? '' : ' disabled'?>><?=htmlspecialchars($label)?></button>
<?php	endforeach; ?>
<?php	if ($pause['active']): ?>
				<button type="submit" name="resume" value="1" class="btn btn-sm btn-primary"><?=gettext('Resume')?></button>
<?php	endif; ?>
			</form>
		</div>
	</div>
</div>

<div class="fs-tiles">
<?php
	fs_tile(gettext('DNS queries (24 h)'), number_format($total_queries), null, sprintf(gettext('Average %s ms'), $latency));
	fs_tile(gettext('Blocked by DNS'), number_format($blocked_queries), null, sprintf(gettext('%s %% of all queries'), $blocked_pct));
	fs_tile(gettext('Blocked by IP lists & GeoIP'), number_format(threatshield_label_sum($labels, 'ThreatShield IP list') + threatshield_label_sum($labels, 'ThreatShield GeoIP')),
	    null, gettext('Packets since the last filter reload'));
	fs_tile(gettext('Bypass attempts stopped'), number_format(threatshield_label_sum($labels, 'ThreatShield anti-bypass')), null, gettext('DoT, DoH and IPv6 DNS'));
	if (!empty($inbound)) {
		fs_tile(gettext('Sources blocked by reputation'), number_format((int)($dnsbl['cached_listed'] ?? 0)),
		    (($dnsbl['breaker'] ?? 'closed') === 'open') ? 'degraded' : null, sprintf(gettext('%s lookups'), number_format((int)($dnsbl['lookups'] ?? 0))));
	}
?>
</div>

<?php
/* one compact ranking card: label column, share bar, count */
$ranking = function ($title, $noun, array $rows, $empty, $kind) use ($dhcp_hosts, $self) {
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
<?php	if ($kind === 'blocked'): ?>
						<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
<?php	endif; ?>
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
<?php		if ($kind === 'blocked'): ?>
						<td class="fs-col-actions"><?=fs_row_actions([['custom', $self . '?unblock=' . rawurlencode($name), $name, [
							'icon' => 'fa-solid fa-circle-check', 'post' => true, 'label' => sprintf(gettext('Unblock %s'), $name),
							'confirm' => sprintf(gettext('Always allow “%s”?'), $name),
							'detail' => gettext('It is added to the allowlist with its subdomains and applied at once.'),
							'confirm_action' => gettext('Unblock')]]])?></td>
<?php		endif; ?>
					</tr>
<?php	endforeach;
	if (empty($rows)) {
		fs_empty_row(($kind === 'blocked') ? 3 : 2, $empty);
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
	$ranking(gettext('Top blocked domains'), gettext('domains'), $top_blocked, gettext('No blocked domains recorded yet.'), 'blocked');
	$ranking(gettext('Top queried domains'), gettext('domains'), $top_queried, gettext('No queries recorded yet.'), 'queried');
?>
</div>
<?php
	$ranking(gettext('Top clients'), gettext('clients'), $top_clients, gettext('No client traffic recorded yet.'), 'client');
endif;

threatshield_ui_styles();
?>
<style>
.ts-quick .panel-body { display: flex; gap: var(--fs-sp-4); align-items: flex-start; padding: var(--fs-sp-5); }
.ts-quick-icon { flex: none; display: inline-flex; align-items: center; justify-content: center; width: 3.5rem; height: 3.5rem;
	border-radius: var(--fs-r-md); background: color-mix(in srgb, var(--fs-coral) 14%, transparent); color: var(--fs-coral); font-size: 1.6rem; }
.ts-quick-text h2 { margin: 0 0 var(--fs-sp-2); font-size: var(--fs-fs-lg); }
.ts-quick-form { display: flex; flex-direction: column; gap: var(--fs-sp-2); align-items: flex-start; margin: var(--fs-sp-3) 0; }
.ts-quick-form .form-check { margin: 0; font-weight: 400; }
.ts-inline-form { display: flex; flex-wrap: wrap; align-items: center; gap: var(--fs-sp-3); }
.ts-overview-grid { display: grid; grid-template-columns: minmax(0, 1fr); gap: 0 var(--fs-sp-4); }
@media (min-width: 992px) { .ts-overview-grid { grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); } }
.ts-overview-grid .panel-heading { display: flex; align-items: center; justify-content: space-between; }
.ts-health-loading { padding: var(--fs-sp-3) var(--fs-sp-4); margin: 0; }
.ts-pause { display: flex; flex-wrap: wrap; gap: var(--fs-sp-2); }
.ts-rank-grid { display: grid; grid-template-columns: minmax(0, 1fr); gap: 0 var(--fs-sp-4); }
@media (min-width: 992px) { .ts-rank-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.ts-rank-name { word-break: break-all; }
.ts-rank-name .fs-muted { margin-left: var(--fs-sp-2); word-break: normal; }
.ts-rank-count { width: 7rem; text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.ts-bar { display: block; height: 3px; margin-top: .3rem; border-radius: 2px; background: color-mix(in srgb, var(--fs-border) 60%, transparent); }
.ts-bar > span { display: block; height: 100%; border-radius: 2px; background: var(--fs-series-1); }
.ts-bar--block > span { background: var(--fs-block); }
@media (max-width: 575px) { .ts-quick .panel-body { flex-direction: column; } }
</style>
<script>
//<![CDATA[
events.push(function () {
	var box = document.getElementById('ts-health');
	if (!box) {
		return;
	}
	function load(url) {
		box.setAttribute('aria-busy', 'true');
		fetch(url, {credentials: 'same-origin'}).then(function (r) {
			return r.ok ? r.text() : Promise.reject(r.status);
		}).then(function (html) {
			box.innerHTML = html;
		}).catch(function () {
			box.innerHTML = '<p class="ts-health-loading fs-muted"><?=gettext('The checks could not be loaded. Reload the page to try again.')?></p>';
		}).finally(function () {
			box.removeAttribute('aria-busy');
		});
	}
	load(box.getAttribute('data-ts-health'));
	var deep = document.querySelector('[data-ts-health-deep]');
	if (deep) {
		deep.addEventListener('click', function (e) {
			e.preventDefault();
			box.innerHTML = '<p class="ts-health-loading fs-muted"><i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> <?=gettext('Checking, including the upstream servers…')?></p>';
			load(deep.getAttribute('href'));
		});
	}
});
//]]>
</script>

<?php include('foot.inc'); ?>
