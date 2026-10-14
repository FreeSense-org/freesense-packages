<?php
/*
 * threatshield_status.php
 * FreeSense Threat Shield - Overview: one summary, a health pill, a small live
 * map, the key numbers and one explorer instead of stacked tables
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
	} elseif (isset($_POST['block'])) {
		$message = null;
		if (threatshield_block_domain($cfg, (string)$_POST['block'], $message)) {
			threatshield_apply($cfg, gettext('Threat Shield: blocked a domain from the overview'), $message);
		} else {
			threatshield_flash('warn', $message);
		}
	} elseif (isset($_POST['action']) && $_POST['action'] === 'restart') {
		threatshield_flash('ok', threatshield_run_fix('restart'));
	} elseif (isset($_POST['action']) && $_POST['action'] === 'update_feeds') {
		threatshield_flash('ok', threatshield_run_fix('update_feeds'));
	}
	@unlink(THREATSHIELD_CACHE_DIR . '/health.json');
	threatshield_redirect($self . (isset($_POST['unblock']) || isset($_POST['block']) ? '#explore' : ''));
}

$enabled = ($cfg['enable'] ?? 'off') === 'on';
$running = threatshield_is_running();
$pause = threatshield_pause_state();
$labels = threatshield_label_counters();
$dnsbl = threatshield_dnsbl_status();
$stats = $running ? threatshield_get_stats() : [];

$total_queries = (int)($stats['num_dns_queries'] ?? 0);
$blocked_queries = (int)($stats['num_blocked_filtering'] ?? 0);
$blocked_pct = ($total_queries > 0) ? round(($blocked_queries / $total_queries) * 100, 1) : 0;
$latency = round((float)($stats['avg_processing_time'] ?? 0) * 1000, 1);

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
$show_map = $enabled && ($cfg['map_overview'] ?? 'on') === 'on' && isAllowedPage('threatshield/threatshield_map.php');

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
if ($show_map) {
	echo '<link rel="stylesheet" href="/threatshield/assets/threatshield_map.css?v=' . (int)@filemtime('/usr/local/www/threatshield/assets/threatshield_map.css') . '">';
}

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
else:
	/* header controls: health pill and pause menu */
	$health_pill = '<button type="button" class="ts-pill" data-ts-pill aria-expanded="false" aria-controls="ts-health-panel">'
	    . '<i class="ts-pill-dot" aria-hidden="true"></i><span data-ts-pill-text>' . htmlspecialchars(gettext('Checking…')) . '</span>'
	    . '<i class="fa-solid fa-chevron-down ts-pill-chev" aria-hidden="true"></i></button>';
	ob_start();
	if ($pause['active']):
?>
	<form method="post" action="<?=$self?>" class="ts-inline">
		<span class="ts-paused"><?=htmlspecialchars(($pause['until'] > 0) ? sprintf(gettext('Paused until %s'), date('H:i', $pause['until'])) : gettext('Paused'))?></span>
		<button type="submit" name="resume" value="1" class="btn btn-sm btn-primary"><i class="fa-solid fa-play icon-embed-btn" aria-hidden="true"></i><?=gettext('Resume')?></button>
	</form>
<?php
	else:
?>
	<div class="dropdown ts-inline">
		<button type="button" class="btn btn-sm btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false"<?=$running ? '' : ' disabled'?>>
			<i class="fa-solid fa-pause icon-embed-btn" aria-hidden="true"></i><?=gettext('Pause')?></button>
		<form method="post" action="<?=$self?>" class="dropdown-menu dropdown-menu-end ts-pause-menu">
			<h6 class="dropdown-header"><?=gettext('Let every domain resolve for')?></h6>
<?php	foreach ([5 => gettext('5 minutes'), 30 => gettext('30 minutes'), 60 => gettext('1 hour'), 240 => gettext('4 hours'), 0 => gettext('Until I resume')] as $m => $label): ?>
			<button type="submit" name="pause" value="<?=$m?>" class="dropdown-item"><?=htmlspecialchars($label)?></button>
<?php	endforeach; ?>
			<p class="ts-pause-note"><?=gettext('IP lists, GeoIP and inbound protection keep working.')?></p>
		</form>
	</div>
<?php
	endif;
	$pause_html = ob_get_clean();

	fs_summary_card([
		'icon' => 'fa-shield-halved',
		'title' => gettext('Threat Shield'),
		'subtitle' => gettext('DNS filtering, IP reputation and country policy'),
		'badges' => [
			$running ? ($pause['active'] ? fs_badge('pending', gettext('Paused')) : fs_badge('up', gettext('Protecting'))) : fs_badge('down', gettext('Stopped')),
			$health_pill,
			$pause_html,
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
<div class="panel panel-default ts-health-panel" id="ts-health-panel" hidden>
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Health checks')?></h2>
		<a class="btn btn-sm btn-link" href="threatshield_ajax.php?what=health&amp;deep=1" data-ts-health-deep><?=gettext('Run all checks, including upstream servers')?></a>
	</div>
	<div class="panel-body p-0" data-ts-health-body>
		<noscript><?=threatshield_health_html(threatshield_health())?></noscript>
	</div>
</div>

<?php if ($show_map): ?>
<div class="panel panel-default ts-mini">
	<div class="ts-mini-head">
		<h2 class="panel-title"><?=gettext('Threat map')?> <span class="fs-muted"><?=gettext('last hour')?></span></h2>
		<span class="tsm-key tsm-key--block"><span><?=gettext('Blocked')?> <b data-ts-mini="block">0</b></span></span>
		<span class="tsm-key tsm-key--pass"><span><?=gettext('Allowed')?> <b data-ts-mini="pass">0</b></span></span>
		<span class="tsm-key tsm-key--dns"><span><?=gettext('DNS blocked')?> <b data-ts-mini="dns">0</b></span></span>
		<span class="ts-mini-links">
			<a class="btn btn-sm btn-link" href="threatshield_map.php"><?=gettext('Open map')?></a>
			<a class="btn btn-sm btn-link" href="threatshield_map.php?view=kiosk" target="_blank"><i class="fa-solid fa-expand icon-embed-btn" aria-hidden="true"></i><?=gettext('Full screen')?></a>
		</span>
	</div>
	<div id="ts-mini-map"></div>
</div>
<?php endif; ?>

<div class="fs-tiles ts-tiles">
<?php
	$tile = function (string $view, string $label, string $value, ?string $state, string $hint) {
		echo '<a class="ts-tile" href="#explore" data-ts-goto="' . $view . '">';
		fs_tile($label, $value, $state, $hint);
		echo '</a>';
	};
	$tile('queried_domains', gettext('DNS queries'), number_format($total_queries), null, sprintf(gettext('Average %s ms'), $latency));
	$tile('blocked_domains', gettext('Blocked by DNS'), number_format($blocked_queries), null, sprintf(gettext('%s %% of all queries'), $blocked_pct));
	$tile('sources', gettext('Blocked by IP lists & GeoIP'), number_format(threatshield_label_sum($labels, 'ThreatShield IP list') + threatshield_label_sum($labels, 'ThreatShield GeoIP')),
	    null, gettext('Packets since the last filter reload'));
	$tile('rules', gettext('Bypass attempts stopped'), number_format(threatshield_label_sum($labels, 'ThreatShield anti-bypass')), null, gettext('DoT, DoH and IPv6 DNS'));
	if (!empty($inbound)) {
		$tile('countries', gettext('Sources blocked by reputation'), number_format((int)($dnsbl['cached_listed'] ?? 0)),
		    (($dnsbl['breaker'] ?? 'closed') === 'open') ? 'degraded' : null, sprintf(gettext('%s lookups'), number_format((int)($dnsbl['lookups'] ?? 0))));
	}
?>
</div>

<?php
	$views = [
		'blocked_domains' => gettext('Blocked domains'), 'queried_domains' => gettext('Queried domains'), 'clients' => gettext('Clients'),
		'sources' => gettext('Blocked sources'), 'countries' => gettext('Countries'), 'networks' => gettext('Networks'),
		'ports' => gettext('Ports'), 'rules' => gettext('Rules'),
	];
?>
<div class="panel panel-default ts-explore" id="explore">
	<div class="ts-explore-bar">
		<nav class="fs-viewswitch" aria-label="<?=gettext('Show')?>" data-ts-views>
<?php	foreach ($views as $k => $l): ?>
			<a href="#explore" data-v="<?=$k?>"><?=htmlspecialchars($l)?></a>
<?php	endforeach; ?>
		</nav>
		<span class="ts-explore-tools">
			<select class="form-select form-select-sm" data-ts-window aria-label="<?=gettext('Time window')?>">
				<option value="1h"><?=gettext('Last hour')?></option>
				<option value="24h" selected><?=gettext('Last 24 hours')?></option>
				<option value="7d"><?=gettext('Last 7 days')?></option>
			</select>
			<span class="fs-search"><i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
				<input type="search" class="form-control" data-ts-q placeholder="<?=gettext('Filter…')?>" aria-label="<?=gettext('Filter the list')?>"></span>
		</span>
	</div>
	<ol class="ts-explore-list" data-ts-rows aria-live="polite"></ol>
	<div class="panel-footer small fs-muted ts-explore-foot"><span data-ts-note></span><button type="button" class="btn btn-sm btn-link" data-ts-more hidden></button></div>
</div>
<form method="post" action="<?=$self?>" id="ts-explore-act" hidden><input type="hidden" name="" value=""></form>
<?php
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
@media (max-width: 575px) { .ts-quick .panel-body { flex-direction: column; } }

/* header controls */
.ts-inline { display: inline-flex; align-items: center; gap: var(--fs-sp-2); }
.ts-paused { font-size: var(--fs-fs-sm); color: var(--fs-warn); font-weight: 600; }
.ts-pill { display: inline-flex; align-items: center; gap: .4rem; height: 1.6rem; padding: 0 .6rem; border: 1px solid var(--fs-border);
	border-radius: 999px; background: var(--fs-surface-raised); color: var(--fs-text); font-size: var(--fs-fs-sm); cursor: pointer; }
.ts-pill:hover { border-color: var(--fs-text-muted); }
.ts-pill-dot { width: .55rem; height: .55rem; border-radius: 50%; background: var(--fs-text-muted); }
.ts-pill[data-state="ok"] .ts-pill-dot { background: var(--fs-pass); }
.ts-pill[data-state="warn"] .ts-pill-dot { background: var(--fs-warn); }
.ts-pill[data-state="fail"] .ts-pill-dot { background: var(--fs-block); }
.ts-pill[data-state="fail"] { border-color: color-mix(in srgb, var(--fs-block) 50%, transparent); }
.ts-pill-chev { font-size: .65rem; color: var(--fs-text-muted); transition: transform .15s; }
.ts-pill[aria-expanded="true"] .ts-pill-chev { transform: rotate(180deg); }
.ts-pause-menu { min-width: 14rem; }
.ts-pause-note { margin: .4rem 1rem .2rem; font-size: var(--fs-fs-xs); color: var(--fs-text-muted); }

/* health: compact two-column checklist */
.ts-health-panel .panel-heading { display: flex; align-items: center; justify-content: space-between; }
@media (min-width: 992px) {
	.ts-health-panel .ts-health { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); }
	.ts-health-panel .ts-health li:nth-child(2) { border-top: 0; }
}
.ts-health-panel .ts-health li { padding: .4rem var(--fs-sp-4); }
.ts-health-panel .ts-health .fs-badge { flex-basis: 5rem; }

/* mini map */
.ts-mini { overflow: hidden; }
.ts-mini-head { display: flex; flex-wrap: wrap; align-items: center; gap: .3rem 1rem; padding: .6rem var(--fs-sp-4); border-bottom: 1px solid var(--fs-border); }
.ts-mini-head .panel-title { margin: 0 .5rem 0 0; }
.ts-mini-head .panel-title .fs-muted { font-weight: 400; font-size: var(--fs-fs-sm); }
.ts-mini-head .tsm-key { font-size: var(--fs-fs-sm); }
.ts-mini-head .tsm-key b { color: var(--fs-text); font-variant-numeric: tabular-nums; }
.ts-mini-links { margin-left: auto; }
#ts-mini-map { border-radius: 0; }

/* tiles as shortcuts into the explorer */
.ts-tiles .ts-tile { display: block; color: inherit; text-decoration: none; border-radius: var(--fs-r-md); }
.ts-tiles .ts-tile .fs-tile { height: 100%; transition: border-color .15s; }
.ts-tiles .ts-tile:hover .fs-tile, .ts-tiles .ts-tile:focus-visible .fs-tile { border-color: var(--fs-coral); }
.ts-tiles .ts-tile.is-current .fs-tile { box-shadow: inset 0 -2px 0 var(--fs-coral); }

/* explorer */
.ts-explore-bar { display: flex; flex-wrap: wrap; align-items: center; gap: var(--fs-sp-2) var(--fs-sp-3); padding: .6rem var(--fs-sp-4); border-bottom: 1px solid var(--fs-border); }
.ts-explore-bar .fs-viewswitch { margin: 0; flex-wrap: wrap; }
.ts-explore-tools { display: flex; align-items: center; gap: var(--fs-sp-2); margin-left: auto; }
.ts-explore-tools .form-select { width: auto; }
.ts-explore-tools .fs-search { width: 14rem; }
.ts-explore-list { list-style: none; margin: 0; padding: 0; counter-reset: ts-rank; }
.ts-explore-list li { position: relative; display: grid; grid-template-columns: 2rem minmax(0, 1fr) 7rem 2.5rem; align-items: center; gap: var(--fs-sp-3);
	min-height: 2.4rem; padding: .3rem var(--fs-sp-4); border-top: 1px solid var(--fs-border); counter-increment: ts-rank; }
.ts-explore-list li:first-child { border-top: 0; }
.ts-explore-list li::before { content: counter(ts-rank); color: var(--fs-text-muted); font-size: var(--fs-fs-sm); font-variant-numeric: tabular-nums; }
.ts-explore-list li.ts-none::before { content: none; }
.ts-explore-list li.ts-none { display: block; color: var(--fs-text-muted); padding: var(--fs-sp-3) var(--fs-sp-4); }
.ts-x-label { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ts-x-label small { margin-left: .5rem; color: var(--fs-text-muted); }
.ts-x-count { text-align: right; font-variant-numeric: tabular-nums; font-weight: 600; }
.ts-x-bar { position: absolute; left: calc(var(--fs-sp-4) + 2rem + var(--fs-sp-3)); right: calc(var(--fs-sp-4) + 2.5rem + 7rem + 2 * var(--fs-sp-3)); bottom: .25rem; height: 3px;
	border-radius: 2px; background: color-mix(in srgb, var(--fs-border) 60%, transparent); }
.ts-x-bar > span { display: block; height: 100%; border-radius: 2px; background: var(--fs-series-1); }
.ts-x-block .ts-x-bar > span { background: var(--fs-block); }
.ts-x-act { justify-self: end; }
.ts-explore-list:not(.is-all) li:nth-child(n+11) { display: none; }
.ts-explore-foot { display: flex; align-items: center; justify-content: space-between; gap: var(--fs-sp-3); }
.ts-x-act .btn { padding: .1rem .4rem; }
@media (max-width: 767px) {
	.ts-explore-tools { margin-left: 0; width: 100%; }
	.ts-explore-tools .fs-search { flex: 1 1 auto; width: auto; }
	.ts-explore-list li { grid-template-columns: 1.5rem minmax(0, 1fr) 4.5rem 2.2rem; }
}
</style>
<?php if ($show_map): ?>
<script src="/threatshield/assets/ts-world.js?v=<?=(int)@filemtime('/usr/local/www/threatshield/assets/ts-world.js')?>"></script>
<script src="/threatshield/assets/threatshield_map.js?v=<?=(int)@filemtime('/usr/local/www/threatshield/assets/threatshield_map.js')?>"></script>
<?php endif; ?>
<script>
//<![CDATA[
events.push(function () {
	var T = <?=json_encode([
		'checking' => gettext('Checking…'), 'ok' => gettext('All %d checks passed'), 'warn' => gettext('%d need attention'),
		'fail' => gettext('%d problems'), 'failed' => gettext('Checks could not run'), 'unblock' => gettext('Unblock'), 'block' => gettext('Block'),
		'details' => gettext('Details'), 'none' => gettext('Nothing in this period.'), 'nomatch' => gettext('Nothing matches the filter.'),
		'unblockConfirm' => gettext('Always allow “%s”? It is added to the allowlist with its subdomains.'),
		'more' => gettext('Show all %d'), 'less' => gettext('Show top 10'),
		'blockConfirm' => gettext('Block “%s” and its subdomains?'),
	])?>;

	/* ------------------------------------------------ health pill */
	/* forms that arrive with fetch() miss the token csrf-magic adds at page load */
	function addToken(root) {
		if (!window.csrfMagicName || !window.csrfMagicToken) {
			return;
		}
		root.querySelectorAll('form[method="post"], form[method="POST"]').forEach(function (f) {
			if (!f.querySelector('input[name="' + window.csrfMagicName + '"]')) {
				var i = document.createElement('input');
				i.type = 'hidden';
				i.name = window.csrfMagicName;
				i.value = window.csrfMagicToken;
				f.appendChild(i);
			}
		});
	}
	var pill = document.querySelector('[data-ts-pill]');
	var panel = document.getElementById('ts-health-panel');
	function loadHealth(url) {
		if (!pill) {
			return;
		}
		pill.removeAttribute('data-state');
		pill.querySelector('[data-ts-pill-text]').textContent = T.checking;
		fetch(url, {credentials: 'same-origin'}).then(function (r) {
			return r.ok ? r.json() : Promise.reject(r.status);
		}).then(function (j) {
			var bad = (j.counts.warn || 0) + (j.counts.fail || 0);
			pill.setAttribute('data-state', j.worst);
			pill.querySelector('[data-ts-pill-text]').textContent = (j.worst === 'ok') ? T.ok.replace('%d', j.total)
				: (j.worst === 'fail' ? T.fail.replace('%d', j.counts.fail) : T.warn.replace('%d', bad));
			panel.querySelector('[data-ts-health-body]').innerHTML = j.html;
			addToken(panel);
			if (j.worst !== 'ok') {
				panel.hidden = false;
				pill.setAttribute('aria-expanded', 'true');
			}
		}).catch(function () {
			pill.setAttribute('data-state', 'warn');
			pill.querySelector('[data-ts-pill-text]').textContent = T.failed;
		});
	}
	if (pill) {
		pill.addEventListener('click', function () {
			panel.hidden = !panel.hidden;
			pill.setAttribute('aria-expanded', panel.hidden ? 'false' : 'true');
		});
		loadHealth('threatshield_ajax.php?what=health&format=json');
		var deep = document.querySelector('[data-ts-health-deep]');
		deep.addEventListener('click', function (e) {
			e.preventDefault();
			loadHealth(deep.getAttribute('href') + '&format=json');
		});
	}

	/* -------------------------------------------------- mini map */
	var mini = document.getElementById('ts-mini-map');
	if (mini && window.TSMap) {
		var t = <?=json_encode(['geoOff' => '<p>' . htmlspecialchars(gettext('Turn on location data in the map settings to see where connections come from.')) . '</p><a class="btn btn-sm btn-primary" href="threatshield_map.php">' . htmlspecialchars(gettext('Open the threat map')) . '</a>',
		    'geoMissing' => htmlspecialchars(gettext('The location database is downloading.')), 'noHome' => '', 'hits' => gettext('%d connections')])?>;
		var map = new TSMap(mini, {data: '/threatshield/threatshield_map_data.php', mode: 'mini', lite: true, poll: 5000, window: '1h',
			style: <?=json_encode((string)$cfg['map_style'] === 'hacker' ? 'hacker' : 'freesense')?>, animations: <?=json_encode((string)$cfg['map_animations'])?>,
			mask: <?=json_encode(($cfg['map_mask_ips'] ?? 'off') === 'on')?>, t: t});
		map.on(function (d) {
			if (!d.counters) {
				return;
			}
			var c = d.counters, set = function (k, v) {
				var el = document.querySelector('[data-ts-mini="' + k + '"]');
				if (el) {
					el.textContent = (+v || 0).toLocaleString();
				}
			};
			set('block', (c.block || 0) + (c.listed || 0));
			set('pass', (c.pass || 0) + (c.clean || 0));
			set('dns', c.dns_block || 0);
		});
	}

	/* --------------------------------------------------- explorer */
	var box = document.getElementById('explore');
	if (!box) {
		return;
	}
	var nav = box.querySelector('[data-ts-views]'), list = box.querySelector('[data-ts-rows]'), note = box.querySelector('[data-ts-note]');
	var win = box.querySelector('[data-ts-window]'), q = box.querySelector('[data-ts-q]');
	var actForm = document.getElementById('ts-explore-act');
	var more = box.querySelector('[data-ts-more]');
	more.addEventListener('click', function () {
		var all = list.classList.toggle('is-all');
		more.textContent = all ? T.less : T.more.replace('%d', list.children.length);
	});
	var view = 'blocked_domains', timer = null;
	try {
		view = localStorage.getItem('ts-explore-view') || view;
	} catch (e) { /* storage blocked */ }
	if (!nav.querySelector('[data-v="' + view + '"]')) {
		view = 'blocked_domains';
	}
	function esc(s) {
		var d = document.createElement('div');
		d.textContent = s == null ? '' : String(s);
		return d.innerHTML;
	}
	function select(v) {
		view = v;
		try {
			localStorage.setItem('ts-explore-view', v);
		} catch (e) { /* storage blocked */ }
		nav.querySelectorAll('a').forEach(function (a) {
			if (a.getAttribute('data-v') === v) {
				a.setAttribute('aria-current', 'page');
			} else {
				a.removeAttribute('aria-current');
			}
		});
		document.querySelectorAll('[data-ts-goto]').forEach(function (t) {
			t.classList.toggle('is-current', t.getAttribute('data-ts-goto') === v);
		});
		/* the DNS statistics have their own period */
		win.disabled = ['blocked_domains', 'queried_domains', 'clients'].indexOf(v) >= 0;
		load();
	}
	function act(name, value, confirmText, button) {
		var go = function () {
			var input = actForm.querySelector('input[type="hidden"]:not([name="__csrf_magic"])');
			input.name = name;
			input.value = value;
			actForm.submit();
		};
		var question = confirmText.replace('%s', value);
		if (window.fsConfirm) {
			window.fsConfirm({title: question, action: name === 'unblock' ? T.unblock : T.block, returnFocus: button}).then(function (ok) {
				if (ok) {
					go();
				}
			});
		} else if (window.confirm(question)) {
			go();
		}
	}
	function load() {
		list.setAttribute('aria-busy', 'true');
		var url = '/threatshield/threatshield_map_data.php?what=explore&view=' + view + '&window=' + win.value + '&q=' + encodeURIComponent(q.value.trim());
		fetch(url, {credentials: 'same-origin'}).then(function (r) {
			return r.json();
		}).then(function (j) {
			var max = 0;
			j.rows.forEach(function (r) {
				max = Math.max(max, r.n);
			});
			var blocks = ['blocked_domains', 'sources', 'countries', 'networks', 'ports', 'rules'].indexOf(view) >= 0;
			list.innerHTML = j.rows.length ? j.rows.map(function (r) {
				var action = '';
				if (view === 'blocked_domains') {
					action = '<button type="button" class="btn btn-sm btn-outline-secondary" data-act="unblock" data-val="' + esc(r.label) + '" title="' + esc(T.unblock) + '"><i class="fa-solid fa-circle-check" aria-hidden="true"></i><span class="visually-hidden">' + esc(T.unblock) + '</span></button>';
				} else if (view === 'queried_domains') {
					action = '<button type="button" class="btn btn-sm btn-outline-secondary" data-act="block" data-val="' + esc(r.label) + '" title="' + esc(T.block) + '"><i class="fa-solid fa-ban" aria-hidden="true"></i><span class="visually-hidden">' + esc(T.block) + '</span></button>';
				} else if (r.ip) {
					action = '<a class="btn btn-sm btn-outline-secondary" href="threatshield_map.php?ip=' + encodeURIComponent(r.ip) + '" title="' + esc(T.details) + '"><i class="fa-solid fa-location-dot" aria-hidden="true"></i><span class="visually-hidden">' + esc(T.details) + '</span></a>';
				}
				var share = max ? Math.max(2, Math.round(r.n / max * 100)) : 0;
				return '<li class="' + (blocks ? 'ts-x-block' : '') + '"><span class="ts-x-label' + (r.ip || view.indexOf('domains') > 0 ? ' fs-mono' : '') + '">' + esc(r.label) +
					(r.sub ? '<small>' + esc(r.sub) + '</small>' : '') + '</span><span class="ts-x-count">' + r.n.toLocaleString() + '</span><span class="ts-x-act">' + action +
					'</span><span class="ts-x-bar" aria-hidden="true"><span style="width:' + share + '%"></span></span></li>';
			}).join('') : '<li class="ts-none">' + esc(q.value.trim() ? T.nomatch : T.none) + '</li>';
			note.textContent = j.note || '';
			more.hidden = j.rows.length <= 10;
			list.classList.remove('is-all');
			more.textContent = T.more.replace('%d', j.rows.length);
			list.querySelectorAll('[data-act]').forEach(function (b) {
				b.addEventListener('click', function () {
					var a = b.getAttribute('data-act');
					act(a, b.getAttribute('data-val'), a === 'unblock' ? T.unblockConfirm : T.blockConfirm, b);
				});
			});
		}).finally(function () {
			list.removeAttribute('aria-busy');
		});
	}
	nav.querySelectorAll('a').forEach(function (a) {
		a.addEventListener('click', function (e) {
			e.preventDefault();
			select(a.getAttribute('data-v'));
		});
	});
	document.querySelectorAll('[data-ts-goto]').forEach(function (t) {
		t.addEventListener('click', function (e) {
			e.preventDefault();
			select(t.getAttribute('data-ts-goto'));
			box.scrollIntoView({behavior: 'smooth', block: 'start'});
		});
	});
	win.addEventListener('change', load);
	q.addEventListener('input', function () {
		clearTimeout(timer);
		timer = setTimeout(load, 250);
	});
	select(view);
});
//]]>
</script>

<?php include('foot.inc'); ?>
