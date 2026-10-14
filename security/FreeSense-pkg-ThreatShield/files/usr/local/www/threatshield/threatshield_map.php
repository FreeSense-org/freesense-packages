<?php
/*
 * threatshield_map.php
 * FreeSense Threat Shield - live threat map: Status page and full-screen view
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 *
 * ?view=kiosk shows the full-screen version (wall screens); URL parameters
 * style, theme, layout, window and mask override the saved defaults per screen.
 */

##|+PRIV
##|*IDENT=page-status-threatshield-map
##|*NAME=Status: Threat Shield threat map
##|*DESCR=View the Threat Shield threat map (read only)
##|*MATCH=threatshield/threatshield_map.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');
require_once('/usr/local/pkg/threatshield/threatshield_ui.inc');

$cfg = threatshield_config();
$can_configure = isAllowedPage('threatshield/threatshield.php');
$self = 'threatshield_map.php';

$styles = ['freesense' => gettext('FreeSense'), 'pro' => gettext('Professional'), 'hacker' => gettext('Hacker')];
$windows = ['15m' => gettext('15 min'), '1h' => gettext('1 hour'), '6h' => gettext('6 hours'), '24h' => gettext('24 hours'), '7d' => gettext('7 days')];
$layouts = ['wall' => gettext('Wall'), 'side' => gettext('Map and side panel'), 'map' => gettext('Map only')];
$panel_names = ['kpis' => gettext('Counters'), 'mix' => gettext('Attack types'), 'timeline' => gettext('Timeline'), 'countries' => gettext('Top countries'),
    'sources' => gettext('Top sources'), 'asns' => gettext('Top networks'), 'ports' => gettext('Targeted ports'), 'rules' => gettext('Rules hit'),
    'domains' => gettext('Blocked domains'), 'feed' => gettext('Live feed'), 'spotlight' => gettext('Top attacker spotlight'), 'status' => gettext('Protection status')];

/* ---------------------------------------------------------------- settings */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	if (!$can_configure) {
		threatshield_flash('error', gettext('You may only view the threat map.'));
		threatshield_redirect($self);
	}
	if (isset($_POST['enable_geodb'])) {
		$cfg['map_geodb'] = 'country_asn';
		if (threatshield_apply($cfg, gettext('Threat Shield: turned on map locations'), gettext('Location data is downloading; the map fills in within a minute.'))) {
			mwexec_bg(THREATSHIELD_UPDATER . ' geodb force');
		}
		threatshield_redirect((string)($_POST['back'] ?? $self));
	}
	if (isset($_POST['save_map'])) {
		$old_geo = $cfg['map_geodb'];
		foreach (['map_geodb', 'map_location', 'map_style', 'map_theme', 'map_window', 'map_animations', 'map_layout'] as $k) {
			if (isset($_POST[$k])) $cfg[$k] = (string)$_POST[$k];
		}
		foreach (['map_lat', 'map_lon', 'map_retention_days', 'map_alert_factor', 'map_title'] as $k) {
			if (isset($_POST[$k])) $cfg[$k] = trim((string)$_POST[$k]);
		}
		foreach (['map_overview', 'map_background', 'map_dns', 'map_log_allowed', 'map_mask_ips', 'map_alerts', 'map_alert_sound'] as $k) {
			$cfg[$k] = isset($_POST[$k]) ? 'on' : 'off';
		}
		$cfg['map_panels'] = array_values(array_intersect(array_keys($panel_names), (array)($_POST['map_panels'] ?? [])));
		if (threatshield_apply($cfg, gettext('Threat Shield: saved the threat map settings'), gettext('Threat map settings saved.'))
		    && $cfg['map_geodb'] !== 'off' && $cfg['map_geodb'] !== $old_geo) {
			mwexec_bg(THREATSHIELD_UPDATER . ' geodb force');
		}
		threatshield_redirect($self);
	}
}

$pick = fn(string $key, array $allowed, string $default) => array_key_exists((string)($_GET[$key] ?? ''), $allowed) ? (string)$_GET[$key] : $default;
$style = $pick('style', $styles, (string)$cfg['map_style']);
$window = $pick('window', $windows, (string)$cfg['map_window']);
$layout = $pick('layout', $layouts, (string)$cfg['map_layout']);
$theme = in_array($_GET['theme'] ?? '', ['auto', 'light', 'dark'], true) ? (string)$_GET['theme'] : (string)$cfg['map_theme'];
$mask = (($_GET['mask'] ?? '') === '1') || ($cfg['map_mask_ips'] === 'on');
$panels = array_map('strval', threatshield_normalize_list($cfg['map_panels'] ?? []));
$geo_state = (ThreatShieldGeo::open() !== null) ? 'ok' : (($cfg['map_geodb'] === 'off') ? 'off' : 'missing');

$asset = function (string $file): string {
	return '/threatshield/assets/' . $file . '?v=' . (int)@filemtime('/usr/local/www/threatshield/assets/' . $file);
};

/* texts for the scripts */
$geo_button = $can_configure ? '<form method="post" action="' . $self . '"><input type="hidden" name="back" value="' . htmlspecialchars($_SERVER['REQUEST_URI'] ?? $self) . '">'
    . '<button type="submit" name="enable_geodb" value="1" class="btn btn-sm btn-primary">' . htmlspecialchars(gettext('Turn on map locations')) . '</button></form>' : '';
$js_text = [
	'details' => gettext('Address details'), 'close' => gettext('Close'), 'loading' => gettext('Loading…'), 'noPtr' => gettext('No host name'),
	'hits' => gettext('%d connections'), 'nothing' => gettext('Nothing yet'), 'blocked' => gettext('Blocked'), 'allowed' => gettext('Allowed'),
	'blockedConn' => gettext('blocked connections'), 'paused' => gettext('Blocking paused'), 'protecting' => gettext('Protecting'), 'stopped' => gettext('Stopped'),
	'health' => gettext('Health'), 'h_ok' => gettext('all checks passed'), 'h_warn' => gettext('needs attention'), 'h_fail' => gettext('problem'), 'h_unknown' => gettext('not checked yet'),
	'reputation' => gettext('Reputation checks'), 'failing' => gettext('failing'), 'working' => gettext('working'), 'flood' => gettext('Flood offenders'),
	'spike' => gettext('Spike: %1 blocked in one interval, %2× the usual level'), 'breakerOpen' => gettext('Reputation lookups are failing; the failure action applies.'),
	'geoOff' => '<p>' . htmlspecialchars(gettext('The map needs a location database to place addresses. It is downloaded once a month from DB-IP (free, CC BY 4.0); nothing else leaves the firewall.')) . '</p>' . $geo_button,
	'geoMissing' => htmlspecialchars(gettext('The location database is downloading. The map fills in when it is ready.')),
	'noHome' => htmlspecialchars(gettext('Set the firewall location under map settings to draw the connections.')),
	'kinds' => ['geoip' => gettext('GeoIP'), 'iplist' => gettext('IP list'), 'dnsbl' => gettext('Reputation'), 'reputation' => gettext('Reputation check'),
	    'bypass' => gettext('Anti-bypass'), 'flood' => gettext('Flood limit'), 'fw_block' => gettext('Firewall rule'), 'fw_pass' => gettext('Firewall rule'),
	    'ts_pass' => gettext('Protected service'), 'dns' => gettext('DNS'), 'service' => gettext('Blocked service'), 'safebrowsing' => gettext('Safe browsing')],
];
$map_opts = [
	'data' => '/threatshield/threatshield_map_data.php', 'style' => $style, 'window' => $window, 'animations' => (string)$cfg['map_animations'],
	'mask' => $mask, 't' => $js_text,
];
$alerts = ['on' => $cfg['map_alerts'] === 'on', 'factor' => (int)$cfg['map_alert_factor'], 'sound' => $cfg['map_alert_sound'] === 'on'];

/* one panel's markup; the scripts fill it */
$panel = function (string $name, string $extra = '') use ($panel_names): string {
	$title = htmlspecialchars($panel_names[$name] ?? $name);
	switch ($name) {
		case 'kpis':
			$k = fn($key, $cls, $label) => '<div class="tsm-kpi tsm-kpi--' . $cls . '"><div class="tsm-kpi-label">' . htmlspecialchars($label) . '</div><div class="tsm-kpi-value" data-k="' . $key . '">0</div></div>';
			return '<div class="tsm-panel tsm-kpis" data-tsm-panel="kpis"' . $extra . '>' . $k('block', 'block', gettext('Blocked')) . $k('pass', 'pass', gettext('Allowed'))
			    . $k('dns', 'dns', gettext('DNS blocked')) . $k('sources', 'src', gettext('Sources')) . $k('rate', 'rate', gettext('Events / s')) . '</div>';
		case 'mix':
			return '<div class="tsm-panel tsm-mix" data-tsm-panel="mix"' . $extra . '><h3>' . $title . '</h3><div class="tsm-mix-body"><div class="tsm-donut"><span>0</span></div><ul class="tsm-legend-list"></ul></div></div>';
		case 'timeline':
			return '<div class="tsm-panel tsm-timeline" data-tsm-panel="timeline"' . $extra . '><h3>' . $title . ' <span class="fs-mono" data-k="peak"></span></h3><canvas aria-hidden="true"></canvas></div>';
		case 'feed':
			return '<div class="tsm-panel tsm-feed" data-tsm-panel="feed"' . $extra . '><h3>' . $title . '</h3><ul class="tsm-feed-list" aria-live="off"></ul></div>';
		case 'spotlight':
			return '<div class="tsm-panel tsm-spot" data-tsm-panel="spotlight"' . $extra . ' role="button" tabindex="0"><h3>' . $title . '</h3><div class="tsm-spot-body"></div></div>';
		case 'status':
			return '<div class="tsm-panel tsm-status" data-tsm-panel="status"' . $extra . '><h3>' . $title . '</h3><ul></ul></div>';
	}
	return '<div class="tsm-panel tsm-rank" data-tsm-panel="' . $name . '"' . $extra . '><h3>' . $title . '</h3><ul></ul></div>';
};

/* ================================================================== kiosk */
if (($_GET['view'] ?? '') === 'kiosk'):
	$title = (string)$cfg['map_title'] ?: (string)config_get_path('system/hostname', 'FreeSense');
	$has = fn($p) => in_array($p, $panels, true);
	$css = ['/vendor/bootstrap/css/bootstrap.min.css', '/vendor/font-awesome/css/all.min.css', '/css/fonts/roboto.css',
	    '/css/_freesense-tokens.css', '/css/_freesense-core.css', '/css/_freesense-components.css'];
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="<?=($theme === 'light') ? 'light' : 'dark'?>">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title><?=htmlspecialchars($title . ' - ' . gettext('Threat map'))?></title>
<?php foreach ($css as $file): ?>
	<link rel="stylesheet" href="<?=$file?>?v=<?=(int)@filemtime('/usr/local/www' . $file)?>">
<?php endforeach; ?>
	<link rel="stylesheet" href="<?=$asset('threatshield_map.css')?>">
	<script>
	/* theme before first paint: auto follows the screen */
	(function () {
		var t = <?=json_encode($theme)?>;
		if (t === 'auto') {
			t = (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
		}
		document.documentElement.setAttribute('data-bs-theme', t);
	})();
	</script>
</head>
<body class="tsk tsk--<?=$style?> tsk--layout-<?=$layout?>" data-signed-out="<?=htmlspecialchars(gettext('Signed out — sign in again to continue the threat map.'))?>">
<div class="tsk-shell">
	<header class="tsk-head">
		<div class="tsk-brand"><i class="fa-solid fa-shield-halved" aria-hidden="true"></i><span><?=htmlspecialchars($title)?></span></div>
		<span class="tsk-live"><i aria-hidden="true"></i>LIVE</span>
		<div class="tsk-alert-slot"><div class="tsm-alert" data-tsm-panel="alert" hidden><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i><span></span></div></div>
		<span class="tsk-clock" data-tsk-clock></span>
		<div class="tsk-tools">
			<select data-tsk="window" aria-label="<?=gettext('Time window')?>">
<?php foreach ($windows as $k => $l): ?>
				<option value="<?=$k?>"<?=($k === $window) ? ' selected' : ''?>><?=htmlspecialchars($l)?></option>
<?php endforeach; ?>
			</select>
			<select data-tsk="style" aria-label="<?=gettext('Style')?>">
<?php foreach ($styles as $k => $l): ?>
				<option value="<?=$k?>"<?=($k === $style) ? ' selected' : ''?>><?=htmlspecialchars($l)?></option>
<?php endforeach; ?>
			</select>
			<select data-tsk="layout" aria-label="<?=gettext('Layout')?>">
<?php foreach ($layouts as $k => $l): ?>
				<option value="<?=$k?>"<?=($k === $layout) ? ' selected' : ''?>><?=htmlspecialchars($l)?></option>
<?php endforeach; ?>
			</select>
			<button type="button" data-tsk="theme" title="<?=gettext('Light or dark')?>" aria-label="<?=gettext('Light or dark')?>"><i class="fa-solid fa-circle-half-stroke" aria-hidden="true"></i></button>
			<button type="button" data-tsk="replay" title="<?=gettext('Replay the last hour at 60× speed')?>"><i class="fa-solid fa-clock-rotate-left" aria-hidden="true"></i></button>
			<button type="button" data-tsk="pause" aria-pressed="false" title="<?=gettext('Pause the animation')?>"><i class="fa-solid fa-pause" aria-hidden="true"></i></button>
			<button type="button" data-tsk="fullscreen" title="<?=gettext('Full screen')?>"><i class="fa-solid fa-expand" aria-hidden="true"></i></button>
			<a href="<?=$self?>" title="<?=gettext('Back to the WebUI')?>"><i class="fa-solid fa-xmark" aria-hidden="true"></i></a>
		</div>
	</header>
	<main class="tsk-body">
<?php if ($has('kpis')): ?>
		<div class="tsk-box tsk-kpibar"><?=$panel('kpis')?></div>
<?php endif; ?>
		<div class="tsk-col tsk-left">
<?php foreach (['mix', 'timeline', 'spotlight', 'status'] as $p) if ($has($p)) echo '<div class="tsk-box">' . $panel($p) . '</div>'; ?>
		</div>
		<div class="tsk-box tsk-mapbox">
			<div id="tsk-map"></div>
			<div class="tsk-attrib"><a href="<?=THREATSHIELD_GEO_ATTRIBUTION_URL?>" target="_blank" rel="noopener"><?=THREATSHIELD_GEO_ATTRIBUTION?></a> · Natural Earth</div>
		</div>
		<div class="tsk-col tsk-right">
<?php foreach (['countries', 'sources', 'asns', 'ports'] as $p) if ($has($p)) echo '<div class="tsk-box' . (($p === 'sources') ? ' tsk-grow' : '') . '">' . $panel($p, ' data-rows="' . (($p === 'sources') ? 10 : 6) . '"') . '</div>'; ?>
		</div>
		<div class="tsk-bottom">
<?php if ($has('feed')): ?>
			<div class="tsk-box tsk-feed tsk-ticker"><?=$panel('feed')?></div>
<?php endif; ?>
<?php foreach (['rules', 'domains'] as $p) if ($has($p)) echo '<div class="tsk-box">' . $panel($p, ' data-rows="5"') . '</div>'; ?>
		</div>
	</main>
</div>
<script src="<?=$asset('ts-world.js')?>"></script>
<script src="<?=$asset('threatshield_map.js')?>"></script>
<script>
(function () {
	var opts = <?=json_encode($map_opts + ['mode' => 'kiosk', 'poll' => 2000], JSON_UNESCAPED_SLASHES)?>;
	var map = new TSMap(document.getElementById('tsk-map'), opts);
	new TSPanels(document.body, map, {alerts: <?=json_encode($alerts)?>, t: opts.t});
	map.on(function (d) {
		document.body.classList.toggle('is-signed-out', d.error === 'signed-out');
	});
	var url = new URL(location.href);
	function keep(k, v) {
		url.searchParams.set(k, v);
		history.replaceState(null, '', url);
	}
	document.querySelectorAll('[data-tsk]').forEach(function (el) {
		var what = el.getAttribute('data-tsk');
		el.addEventListener(el.tagName === 'SELECT' ? 'change' : 'click', function () {
			if (what === 'window') {
				map.setOptions({window: el.value});
				keep('window', el.value);
			} else if (what === 'style') {
				document.body.className = document.body.className.replace(/tsk--(freesense|pro|hacker)/, 'tsk--' + el.value);
				map.setOptions({style: el.value});
				keep('style', el.value);
			} else if (what === 'layout') {
				document.body.className = document.body.className.replace(/tsk--layout-\w+/, 'tsk--layout-' + el.value);
				keep('layout', el.value);
				setTimeout(function () { map.resize(); }, 50);
			} else if (what === 'theme') {
				var next = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
				document.documentElement.setAttribute('data-bs-theme', next);
				keep('theme', next);
			} else if (what === 'pause') {
				map.paused = !map.paused;
				el.setAttribute('aria-pressed', map.paused ? 'true' : 'false');
			} else if (what === 'replay') {
				el.disabled = true;
				map.replay(3600, 60, function () { el.disabled = false; });
			} else if (what === 'fullscreen') {
				if (document.fullscreenElement) {
					document.exitFullscreen();
				} else if (document.documentElement.requestFullscreen) {
					document.documentElement.requestFullscreen();
				}
			}
		});
	});
	/* wall screen helpers: clock, hide the cursor and tools, stay awake, refresh twice a day */
	var clockEl = document.querySelector('[data-tsk-clock]');
	setInterval(function () {
		clockEl.textContent = new Date().toLocaleTimeString();
	}, 1000);
	var idle;
	function wake() {
		document.body.classList.remove('is-idle');
		clearTimeout(idle);
		idle = setTimeout(function () { document.body.classList.add('is-idle'); }, 4000);
	}
	['mousemove', 'keydown', 'touchstart'].forEach(function (ev) { document.addEventListener(ev, wake); });
	wake();
	if (navigator.wakeLock) {
		var lock = function () { navigator.wakeLock.request('screen').catch(function () {}); };
		lock();
		document.addEventListener('visibilitychange', function () { if (!document.hidden) { lock(); } });
	}
	setTimeout(function () { location.reload(); }, 12 * 3600 * 1000);
})();
</script>
</body>
</html>
<?php
	exit;
endif;

/* ============================================================ Status page */
$pgtitle = [gettext('Status'), gettext('Threat Shield'), gettext('Threat map')];
$pglinks = ['', '/threatshield/threatshield_status.php', '@self'];
fs_page_action(gettext('Full screen'), $self . '?view=kiosk', 'fa-expand', 'secondary', ['data-tsp-kiosk' => '1', 'target' => '_blank']);
if ($can_configure) fs_page_action(gettext('Map settings'), '#', 'fa-sliders', 'secondary', ['data-fs-modal' => '#tsp-settings']);

include('head.inc');
?>
<link rel="stylesheet" href="<?=$asset('threatshield_map.css')?>">
<?php
threatshield_print_messages();
threatshield_display_tabs('map');
$top_views = ['countries', 'sources', 'asns', 'ports', 'rules', 'domains'];    // one picker card on this page
?>
<div class="tsp" id="tsp">
	<div class="tsm-alert" data-tsm-panel="alert" hidden><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i><span></span></div>
	<div class="tsp-controls">
		<nav class="fs-viewswitch" aria-label="<?=gettext('Time window')?>" data-tsp-window>
<?php foreach ($windows as $k => $l): ?>
			<a href="#" data-v="<?=$k?>"<?=($k === $window) ? ' aria-current="page"' : ''?>><?=htmlspecialchars($l)?></a>
<?php endforeach; ?>
		</nav>
		<label class="form-check"><input class="form-check-input" type="checkbox" data-tsp-f="block" checked> <?=gettext('Blocked')?></label>
		<label class="form-check"><input class="form-check-input" type="checkbox" data-tsp-f="pass" checked> <?=gettext('Allowed')?></label>
		<label class="form-check"><input class="form-check-input" type="checkbox" data-tsp-f="dns" checked> <?=gettext('DNS')?></label>
		<label class="form-check"><input class="form-check-input" type="checkbox" data-tsp-f="ts"> <?=gettext('Threat Shield only')?></label>
		<select class="form-select form-select-sm w-auto" data-tsp-style aria-label="<?=gettext('Style')?>">
<?php foreach ($styles as $k => $l): ?>
			<option value="<?=$k?>"<?=($k === $style) ? ' selected' : ''?>><?=htmlspecialchars($l)?></option>
<?php endforeach; ?>
		</select>
		<button type="button" class="btn btn-sm btn-outline-secondary" data-tsp-replay><i class="fa-solid fa-clock-rotate-left icon-embed-btn" aria-hidden="true"></i><?=gettext('Replay 1 h')?></button>
		<button type="button" class="btn btn-sm btn-outline-secondary" data-tsp-pause aria-pressed="false"><i class="fa-solid fa-pause icon-embed-btn" aria-hidden="true"></i><?=gettext('Pause')?></button>
		<span class="tsp-live"><i aria-hidden="true"></i><span data-tsp-live><?=gettext('Live')?></span></span>
	</div>
<?php if (in_array('kpis', $panels, true)): ?>
	<div class="tsp-card tsp-kpis"><?=$panel('kpis')?></div>
<?php endif; ?>
	<div id="tsp-map"></div>
	<div class="tsp-grid">
<?php foreach (['mix', 'timeline', 'spotlight'] as $p) if (in_array($p, $panels, true)) echo '<div class="tsp-card">' . $panel($p) . '</div>'; ?>
		<div class="tsp-card">
			<nav class="fs-viewswitch tsp-topswitch" aria-label="<?=gettext('Top list')?>" data-tsp-top>
<?php foreach ($top_views as $i => $p): ?>
				<a href="#" data-v="<?=$p?>"<?=($i === 0) ? ' aria-current="page"' : ''?>><?=htmlspecialchars(['countries' => gettext('Countries'), 'sources' => gettext('Sources'), 'asns' => gettext('Networks'),
				    'ports' => gettext('Ports'), 'rules' => gettext('Rules'), 'domains' => gettext('Domains')][$p])?></a>
<?php endforeach; ?>
			</nav>
<?php foreach ($top_views as $i => $p) echo str_replace('<div class="tsm-panel', '<div' . (($i === 0) ? '' : ' hidden') . ' class="tsm-panel', $panel($p, ' data-rows="10"')); ?>
		</div>
<?php if (in_array('feed', $panels, true)): ?>
		<div class="tsp-card tsp-card--feed"><?=$panel('feed')?></div>
<?php endif; ?>
<?php if (in_array('status', $panels, true)): ?>
		<div class="tsp-card tsp-card--wide"><?=$panel('status')?></div>
<?php endif; ?>
	</div>
	<p class="small fs-muted mt-3"><i class="fa-solid fa-circle-info" aria-hidden="true"></i>
		<?=gettext('Positions are approximate (country level). Blocked connections come from the firewall log, so only rules that log appear; allowed connections need logging rules or "Log allowed connections" in the map settings.')?>
		<a href="<?=THREATSHIELD_GEO_ATTRIBUTION_URL?>" target="_blank" rel="noopener"><?=THREATSHIELD_GEO_ATTRIBUTION?></a>.
	</p>
</div>

<?php if ($can_configure):
	fs_modal_form_begin('tsp-settings', gettext('Threat map settings'), $self);
	$chk = fn($name, $label, $help = '') => '<label class="form-check"><input class="form-check-input" type="checkbox" name="' . $name . '"' . (($cfg[$name] ?? 'off') === 'on' ? ' checked' : '') . '> '
	    . htmlspecialchars($label) . '</label>' . ($help !== '' ? '<div class="form-text mb-2">' . htmlspecialchars($help) . '</div>' : '');
	$sel = function ($name, $label, array $options) use ($cfg) {
		$h = '<div class="mb-3"><label class="form-label" for="' . $name . '">' . htmlspecialchars($label) . '</label><select class="form-select" id="' . $name . '" name="' . $name . '">';
		foreach ($options as $k => $l) $h .= '<option value="' . $k . '"' . (((string)$cfg[$name]) === (string)$k ? ' selected' : '') . '>' . htmlspecialchars($l) . '</option>';
		return $h . '</select></div>';
	};
?>
	<h3 class="h6"><?=gettext('Look')?></h3>
	<?=$sel('map_style', gettext('Style'), $styles)?>
	<?=$sel('map_theme', gettext('Full screen: light or dark'), ['auto' => gettext('Follow the screen'), 'light' => gettext('Light'), 'dark' => gettext('Dark')])?>
	<?=$sel('map_layout', gettext('Full screen layout'), $layouts)?>
	<?=$sel('map_window', gettext('Time window'), $windows)?>
	<?=$sel('map_animations', gettext('Animations'), ['full' => gettext('Full'), 'reduced' => gettext('Reduced (no moving arcs)'), 'off' => gettext('Off')])?>
	<div class="mb-3"><label class="form-label" for="map_title"><?=gettext('Full screen title')?></label>
		<input class="form-control" id="map_title" name="map_title" maxlength="60" value="<?=htmlspecialchars((string)$cfg['map_title'])?>" placeholder="<?=htmlspecialchars((string)config_get_path('system/hostname', ''))?>"></div>
	<fieldset class="mb-3"><legend class="form-label"><?=gettext('Panels')?></legend>
		<div class="ts-ifaces">
<?php	foreach ($panel_names as $k => $l): ?>
			<label class="form-check"><input class="form-check-input" type="checkbox" name="map_panels[]" value="<?=$k?>"<?=in_array($k, $panels, true) ? ' checked' : ''?>> <?=htmlspecialchars($l)?></label>
<?php	endforeach; ?>
		</div></fieldset>
	<?=$chk('map_overview', gettext('Show a small map on the Threat Shield overview'))?>
	<?=$chk('map_mask_ips', gettext('Mask addresses (198.51.100.x) and hide client names'), gettext('For screens other people can see.'))?>
	<h3 class="h6 mt-3"><?=gettext('Data')?></h3>
	<?=$sel('map_geodb', gettext('Location data'), ['off' => gettext('Off'), 'country' => gettext('Countries (DB-IP Lite, about 5 MB a month)'), 'country_asn' => gettext('Countries and networks (DB-IP Lite, about 12 MB a month)')])?>
	<?=$sel('map_location', gettext('Firewall location'), ['auto' => gettext('From the time zone'), 'manual' => gettext('Enter coordinates')])?>
	<div class="row g-2 mb-3">
		<div class="col"><input class="form-control" name="map_lat" value="<?=htmlspecialchars((string)$cfg['map_lat'])?>" placeholder="<?=gettext('Latitude')?>" aria-label="<?=gettext('Latitude')?>"></div>
		<div class="col"><input class="form-control" name="map_lon" value="<?=htmlspecialchars((string)$cfg['map_lon'])?>" placeholder="<?=gettext('Longitude')?>" aria-label="<?=gettext('Longitude')?>"></div>
	</div>
	<?=$chk('map_dns', gettext('Show DNS: blocked queries and where allowed answers point'))?>
	<?=$chk('map_log_allowed', gettext('Log allowed connections of protected services (Inbound protection)'), gettext('Adds log to the pass rules Threat Shield owns; reloads the firewall.'))?>
	<?=$chk('map_background', gettext('Collect in the background (every minute), not only while a map is open'))?>
	<div class="mb-3"><label class="form-label" for="map_retention_days"><?=gettext('Keep history (days)')?></label>
		<input class="form-control" type="number" min="1" max="30" id="map_retention_days" name="map_retention_days" value="<?=htmlspecialchars((string)$cfg['map_retention_days'])?>"></div>
	<h3 class="h6 mt-3"><?=gettext('Alerts')?></h3>
	<?=$chk('map_alerts', gettext('Show a banner on sudden spikes and when reputation lookups fail'))?>
	<div class="mb-3"><label class="form-label" for="map_alert_factor"><?=gettext('Spike: times the usual level')?></label>
		<input class="form-control" type="number" min="2" max="50" id="map_alert_factor" name="map_alert_factor" value="<?=htmlspecialchars((string)$cfg['map_alert_factor'])?>"></div>
	<?=$chk('map_alert_sound', gettext('Play a short sound with an alert (full screen)'))?>
<?php
	fs_modal_form_end(gettext('Save'), 'save_map', '1', 'fa-floppy-disk');
endif;
threatshield_ui_styles();
?>
<style>
#tsp-map { border: 1px solid var(--fs-border); }
.tsp-topswitch { margin-bottom: .6rem; }
</style>
<script src="<?=$asset('ts-world.js')?>"></script>
<script src="<?=$asset('threatshield_map.js')?>"></script>
<script>
//<![CDATA[
events.push(function () {
	var opts = <?=json_encode($map_opts + ['mode' => 'page', 'poll' => 3000, 'canAct' => isAllowedPage('threatshield/threatshield_allowlist.php')], JSON_UNESCAPED_SLASHES)?>;
	var root = document.getElementById('tsp');
	var map = new TSMap(document.getElementById('tsp-map'), opts);
	new TSPanels(root, map, {alerts: <?=json_encode($alerts)?>, t: opts.t});
	/* threatshield_map.php?ip=… opens that address (links from the Overview) */
	var openIp = new URL(location.href).searchParams.get('ip');
	if (openIp) {
		map.openIp(openIp);
	}
	function pick(nav, cb) {
		nav.querySelectorAll('a').forEach(function (a) {
			a.addEventListener('click', function (e) {
				e.preventDefault();
				nav.querySelectorAll('a').forEach(function (x) { x.removeAttribute('aria-current'); });
				a.setAttribute('aria-current', 'page');
				cb(a.getAttribute('data-v'));
			});
		});
	}
	pick(root.querySelector('[data-tsp-window]'), function (v) { map.setOptions({window: v}); });
	var top = root.querySelector('[data-tsp-top]');
	if (top) {
		pick(top, function (v) {
			top.parentNode.querySelectorAll('[data-tsm-panel]').forEach(function (p) {
				p.hidden = (p.getAttribute('data-tsm-panel') !== v);
			});
		});
	}
	root.querySelectorAll('[data-tsp-f]').forEach(function (box) {
		box.addEventListener('change', function () {
			var f = {};
			root.querySelectorAll('[data-tsp-f]').forEach(function (b) { f[b.getAttribute('data-tsp-f')] = b.checked; });
			map.setOptions({filters: f});
		});
	});
	var styleSel = root.querySelector('[data-tsp-style]');
	styleSel.addEventListener('change', function () {
		map.setOptions({style: styleSel.value});
		var k = document.querySelector('[data-tsp-kiosk]');
		if (k) {
			k.href = 'threatshield_map.php?view=kiosk&style=' + styleSel.value;
		}
	});
	var pause = root.querySelector('[data-tsp-pause]');
	pause.addEventListener('click', function () {
		map.paused = !map.paused;
		pause.setAttribute('aria-pressed', map.paused ? 'true' : 'false');
		root.classList.toggle('is-paused', map.paused);
	});
	var replay = root.querySelector('[data-tsp-replay]');
	replay.addEventListener('click', function () {
		replay.disabled = true;
		map.replay(3600, 60, function () { replay.disabled = false; });
	});
});
//]]>
</script>
<?php include('foot.inc'); ?>
