<?php
/*
 * threatshield_map_data.php
 * FreeSense Threat Shield - data for the threat map, the Overview explorer
 * and the dashboard widget
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 *
 * GET  what=events   live events after a cursor, map dots, counters, top lists
 *      what=explore  one ranked list for the Overview explorer
 *      what=ip       the IP card (HTML)
 *      what=ptr      reverse DNS of one address (on request only)
 *      what=replay   stored events of a time range, oldest first
 * POST act=allow_ip|recheck_ip|release_ip (needs the full Threat Shield privilege)
 */

##|+PRIV
##|*IDENT=page-status-threatshield-map
##|*NAME=Status: Threat Shield threat map
##|*DESCR=View the Threat Shield threat map (read only)
##|*MATCH=threatshield/threatshield_map_data.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');

/* concurrent map screens must not wait for each other on the session lock */
if ($_SERVER['REQUEST_METHOD'] !== 'POST') phpsession_end();
header('Cache-Control: no-store');

$cfg = threatshield_config();
$mask = (($cfg['map_mask_ips'] ?? 'off') === 'on') || (($_GET['mask'] ?? '') === '1');
$can_act = isAllowedPage('threatshield/threatshield_allowlist.php');

function ts_map_json(array $data, int $code = 200): void {
	http_response_code($code);
	header('Content-Type: application/json');
	echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
	exit;
}

function ts_map_filters(): array {
	return [
		'actions' => array_filter(explode(',', (string)($_GET['f'] ?? ''))),
		'ts' => ($_GET['ts'] ?? '') === '1',
		'cc' => strtoupper((string)($_GET['cc'] ?? '')),
		'q' => substr(trim((string)($_GET['q'] ?? '')), 0, 80),
	];
}

/* ------------------------------------------------------------------ actions */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	if (!$can_act) ts_map_json(['ok' => false, 'message' => gettext('You may only view the threat map.')], 403);
	$ip = (string)($_POST['ip'] ?? '');
	if (!filter_var($ip, FILTER_VALIDATE_IP)) ts_map_json(['ok' => false, 'message' => gettext('Not an IP address.')], 400);
	switch ((string)($_POST['act'] ?? '')) {
		case 'allow_ip':
			$m = null;
			if (!threatshield_ip_allowlist_add($cfg, $ip, 'threat map', gettext('Allowed from the threat map'), $m)) ts_map_json(['ok' => false, 'message' => (string)$m]);
			$errors = [];
			$ok = threatshield_save_and_apply($cfg, gettext('Threat Shield: allowed an address from the threat map'), $errors);
			if ($ok) threatshield_dnsbl_forget([$ip]);
			ts_map_json(['ok' => $ok, 'message' => $ok ? (string)$m : implode(' ', $errors)]);
		case 'recheck_ip':
			threatshield_dnsbl_forget([$ip]);
			ts_map_json(['ok' => true, 'message' => sprintf(gettext('%s will be checked again on its next connection.'), $ip)]);
		case 'release_ip':
			$ok = threatshield_flood_release($ip, THREATSHIELD_T_FLOOD) | threatshield_flood_release($ip, 'virusprot');
			ts_map_json(['ok' => (bool)$ok, 'message' => $ok ? sprintf(gettext('%s released.'), $ip) : gettext('The address was not blocked for flooding.')]);
	}
	ts_map_json(['ok' => false, 'message' => gettext('Unknown action.')], 400);
}

$what = (string)($_GET['what'] ?? 'events');
$window = (string)($_GET['window'] ?? ($cfg['map_window'] ?? '1h'));
$since = time() - threatshield_map_window($window);

/* ------------------------------------------------------------------- events */
if ($what === 'events' || $what === 'replay') {
	if (($cfg['enable'] ?? 'off') === 'on' && $what === 'events') threatshield_map_collect($cfg);
	$db = threatshield_map_db();
	if ($db === null) ts_map_json(['v' => 1, 'error' => 'store'], 503);
	$f = ts_map_filters();
	if ($what === 'replay') {
		$from = max(0, (int)($_GET['from'] ?? $since));
		$to = (int)($_GET['to'] ?? time());
		$where = threatshield_map_where($db, $f);
		$res = $db->query("SELECT * FROM events WHERE t >= {$from} AND t <= {$to}{$where} ORDER BY seq ASC LIMIT 3000");
		$rows = [];
		while ($res && ($r = $res->fetchArray(SQLITE3_ASSOC))) $rows[] = threatshield_map_event_json($r, $mask);
		$db->close();
		ts_map_json(['v' => 1, 'events' => $rows]);
	}
	$after = max(0, (int)($_GET['after'] ?? 0));
	$lite = ($_GET['lite'] ?? '') === '1';
	$state = threatshield_map_state();
	$geo = ThreatShieldGeo::open();
	$out = [
		'v' => 1,
		'now' => time(),
		'cursor' => (int)($db->querySingle('SELECT MAX(seq) FROM events') ?? 0),
		'home' => threatshield_map_home($cfg),
		'geodb' => ['state' => ($geo !== null) ? 'ok' : ((($cfg['map_geodb'] ?? 'off') === 'off') ? 'off' : 'missing'),
		    'month' => $geo ? (string)($geo->meta()['month'] ?? '') : '', 'asn' => $geo ? (bool)($geo->meta()['asn'] ?? false) : false,
		    'attribution' => THREATSHIELD_GEO_ATTRIBUTION, 'url' => THREATSHIELD_GEO_ATTRIBUTION_URL],
		'sources' => [
			'filterlog' => is_file(THREATSHIELD_FILTER_LOG) ? 'ok' : 'off',
			'dns' => (($cfg['map_dns'] ?? 'on') === 'on' && ($cfg['enable'] ?? 'off') === 'on') ? 'ok' : 'off',
			'dnsbl' => (($cfg['dnsbl_enable'] ?? 'off') === 'on') ? 'ok' : 'off',
		],
		'dropped' => (int)($state['dropped'] ?? 0) + (int)($state['skipped'] ?? 0),
		'events' => threatshield_map_events($db, $after, $since, $f, ($after === 0) ? 60 : ($lite ? 40 : 150), $mask),
	];
	if ($after === 0 || ($_GET['dots'] ?? '') === '1') $out['dots'] = threatshield_map_dots($db, $since, $f, $mask, $lite ? 400 : 1500);
	$out += threatshield_map_summary($db, $since, $f, $mask);
	if (!$lite) {
		$pause = threatshield_pause_state();
		$dnsbl = threatshield_dnsbl_status();
		/* the cached result only: a map screen must not run the checks */
		$health = json_decode((string)@file_get_contents(THREATSHIELD_CACHE_DIR . '/health.json'), true);
		$out['status'] = [
			'running' => threatshield_is_running(), 'paused' => (bool)$pause['active'], 'paused_until' => (int)$pause['until'],
			'health' => is_array($health) ? threatshield_health_worst($health) : 'unknown', 'breaker' => (string)($dnsbl['breaker'] ?? 'closed'),
			'flood' => count(threatshield_flood_entries()), 'lists' => threatshield_last_update('feeds'),
			'title' => (string)($cfg['map_title'] ?? '') ?: (string)config_get_path('system/hostname', 'FreeSense'),
		];
	}
	$db->close();
	ts_map_json($out);
}

/* ------------------------------------------------------- Overview explorer */
if ($what === 'explore') {
	$view = (string)($_GET['view'] ?? 'blocked_domains');
	$q = strtolower(substr(trim((string)($_GET['q'] ?? '')), 0, 80));
	$rows = [];
	$note = '';
	if (in_array($view, ['blocked_domains', 'queried_domains', 'clients'], true)) {
		$stats = threatshield_get_stats();
		$key = ['blocked_domains' => 'top_blocked_domains', 'queried_domains' => 'top_queried_domains', 'clients' => 'top_clients'][$view];
		$hosts = ($view === 'clients') ? threatshield_get_dhcp_hostnames() : [];
		foreach ((array)($stats[$key] ?? []) as $item) {
			$name = is_array($item) ? (string)($item['name'] ?? key($item)) : (string)$item;
			$n = is_array($item) ? (int)($item['count'] ?? current($item)) : 1;
			$rows[] = ['label' => $name, 'sub' => (string)($hosts[$name] ?? ''), 'n' => $n];
		}
		$note = gettext('From the DNS statistics (Settings > statistics period).');
	} else {
		$db = threatshield_map_db();
		if ($db !== null) {
			$sum = threatshield_map_summary($db, $since, ['ts' => ($_GET['ts'] ?? '') === '1'], $mask);
			$db->close();
			switch ($view) {
				case 'sources':
					foreach ($sum['top']['ips'] as $r) $rows[] = ['label' => $r['ip'], 'sub' => trim($r['cc'] . ' ' . $r['org']), 'n' => $r['n'], 'ip' => $r['ip'], 'cc' => $r['cc']];
					break;
				case 'countries':
					foreach ($sum['top']['countries'] as $r) $rows[] = ['label' => $r['name'], 'sub' => $r['cc'], 'n' => $r['n'], 'cc' => $r['cc']];
					break;
				case 'ports':
					foreach ($sum['top']['ports'] as $r) $rows[] = ['label' => strtoupper($r['proto']) . ' ' . $r['port'], 'sub' => $r['service'], 'n' => $r['n']];
					break;
				case 'rules':
					foreach ($sum['top']['rules'] as $r) $rows[] = ['label' => $r['rule'], 'sub' => '', 'n' => $r['n']];
					break;
				case 'networks':
					foreach ($sum['top']['asns'] as $r) $rows[] = ['label' => $r['org'] ?: ('AS' . $r['asn']), 'sub' => 'AS' . $r['asn'], 'n' => $r['n']];
					break;
			}
			$note = gettext('Blocked connections seen in the firewall log.');
		}
	}
	if ($q !== '') $rows = array_values(array_filter($rows, fn($r) => str_contains(strtolower($r['label'] . ' ' . $r['sub']), $q)));
	ts_map_json(['v' => 1, 'view' => $view, 'rows' => array_slice($rows, 0, 25), 'total' => count($rows), 'note' => $note, 'can_act' => $can_act]);
}

/* ------------------------------------------------------------------- IP card */
if ($what === 'ptr') {
	$ip = (string)($_GET['ip'] ?? '');
	ts_map_json(['ptr' => filter_var($ip, FILTER_VALIDATE_IP) ? threatshield_map_ptr($ip) : null]);
}

if ($what === 'ip') {
	$ip = (string)($_GET['ip'] ?? '');
	/* masked screens identify a source by id only */
	if (!filter_var($ip, FILTER_VALIDATE_IP) && preg_match('/^[0-9a-f]{16}$/', (string)($_GET['id'] ?? ''))) {
		$db = threatshield_map_db();
		$st = $db ? $db->prepare('SELECT DISTINCT ip FROM events WHERE ip != \'\' ORDER BY seq DESC LIMIT 5000') : null;
		$res = $st ? $st->execute() : null;
		while ($res && ($r = $res->fetchArray(SQLITE3_NUM))) {
			if (hash_equals(threatshield_map_ip_id((string)$r[0]), (string)$_GET['id'])) { $ip = (string)$r[0]; break; }
		}
		if ($db) $db->close();
	}
	header('Content-Type: text/html; charset=utf-8');
	if (!filter_var($ip, FILTER_VALIDATE_IP)) {
		echo '<p class="fs-muted">' . htmlspecialchars(gettext('Unknown address.')) . '</p>';
		exit;
	}
	$info = threatshield_map_ip_info($ip, $cfg);
	$shown = $mask ? threatshield_map_mask($ip) : $ip;
	$rec = $info['record'];
	$kinds = ['geoip' => gettext('GeoIP'), 'iplist' => gettext('IP list'), 'dnsbl' => gettext('Reputation'), 'bypass' => gettext('Anti-bypass'),
	    'flood' => gettext('Flood limit'), 'ts_pass' => gettext('Allowed (Threat Shield)'), 'fw_block' => gettext('Firewall rule'), 'fw_pass' => gettext('Allowed (firewall rule)'),
	    'reputation' => gettext('Reputation check'), 'dns' => gettext('DNS')];
	$badges = [];
	if ($info['allowlisted']) $badges[] = fs_badge('pass', gettext('Allowlisted'), (string)$info['allowlisted']);
	if (($info['verdict']['verdict'] ?? '') === 'listed') $badges[] = fs_badge('block', gettext('Listed by DNSBL'));
	elseif (($info['verdict']['verdict'] ?? '') === 'clean') $badges[] = fs_badge('pass', gettext('Clean reputation'));
	foreach ($info['tables'] as $t) {
		$label = str_starts_with($t, 'ts_ipf_') ? sprintf(gettext('On IP list %s'), substr($t, 7))
		    : (str_starts_with($t, 'freesense_geoip_') ? gettext('Blocked country') : (($t === 'threatshield_dnsbl_bad') ? '' : gettext('Flood offender')));
		if ($label !== '') $badges[] = fs_badge('block', $label);
	}
	$flag = ($info['geo']['cc'] !== '') ? '<span class="fs-chip fs-chip--mono fs-chip--strong">' . htmlspecialchars($info['geo']['cc']) . '</span> ' : '';
?>
<div class="tsm-card" data-ip="<?=htmlspecialchars($mask ? '' : $ip)?>">
	<div class="tsm-card-head">
		<div class="tsm-card-ip fs-mono"><?=htmlspecialchars($shown)?></div>
		<div class="tsm-card-badges"><?=implode(' ', $badges)?></div>
	</div>
	<dl class="tsm-facts">
		<dt><?=gettext('Location')?></dt><dd><?=$flag . htmlspecialchars($info['country'] ?: gettext('Unknown'))?> <span class="fs-muted small">(<?=gettext('country level')?>)</span></dd>
		<dt><?=gettext('Network')?></dt><dd><?=($info['geo']['asn'] > 0) ? htmlspecialchars('AS' . $info['geo']['asn'] . ' ' . $info['geo']['org']) : '<span class="fs-muted">' . gettext('Unknown') . '</span>'?></dd>
<?php if (!$mask): ?>
		<dt><?=gettext('Host name')?></dt><dd data-tsm-ptr="<?=htmlspecialchars($ip)?>"><button type="button" class="btn btn-sm btn-link p-0" data-tsm-lookup><?=gettext('Look up')?></button></dd>
<?php endif; ?>
		<dt><?=gettext('Seen')?></dt><dd><?=$rec ? htmlspecialchars(sprintf(gettext('%1$s – %2$s'), date('Y-m-d H:i', (int)$rec['first']), date('Y-m-d H:i', (int)$rec['last']))) : '–'?></dd>
		<dt><?=gettext('Connections')?></dt><dd><?=$rec ? htmlspecialchars(sprintf(gettext('%1$s blocked, %2$s allowed'), number_format((int)$rec['nb']), number_format((int)$rec['np']))) : '–'?></dd>
		<dt><?=gettext('Last rule')?></dt><dd><?=htmlspecialchars((string)($rec['rule'] ?? '')) ?: '–'?></dd>
<?php if (!empty($info['ports'])): ?>
		<dt><?=gettext('Ports')?></dt><dd class="fs-chips"><?php foreach ($info['ports'] as $p): ?><span class="fs-chip fs-chip--mono"><?=htmlspecialchars(strtoupper((string)$p['proto']) . ' ' . $p['port'] . (threatshield_map_service((int)$p['port']) ? ' ' . threatshield_map_service((int)$p['port']) : ''))?> ×<?=(int)$p['n']?></span><?php endforeach; ?></dd>
<?php endif; ?>
<?php if ($info['verdict']): ?>
		<dt><?=gettext('Reputation')?></dt><dd><?=htmlspecialchars(sprintf(gettext('%1$s (%2$s), checked %3$s'), $info['verdict']['verdict'], str_replace(';', ', ', (string)$info['verdict']['zones']) ?: '–', threatshield_age((int)$info['verdict']['checked'])))?></dd>
<?php endif; ?>
		<dt><?=gettext('Open states')?></dt><dd><?=(int)$info['states']?></dd>
	</dl>
<?php if (!empty($info['events'])): ?>
	<ul class="tsm-card-events">
<?php	foreach (array_slice($info['events'], 0, 6) as $e): ?>
		<li><span class="fs-mono"><?=date('H:i:s', (int)$e['t'])?></span>
			<?=in_array($e['a'], ['pass', 'clean', 'dns_allow'], true) ? fs_badge('pass', gettext('Allowed')) : fs_badge('block', gettext('Blocked'))?>
			<span><?=htmlspecialchars($kinds[$e['k']] ?? $e['k'])?><?=((int)$e['port'] > 0) ? htmlspecialchars(' · ' . strtoupper((string)$e['proto']) . ' ' . $e['port']) : ''?></span></li>
<?php	endforeach; ?>
	</ul>
<?php endif; ?>
<?php if ($can_act && !$mask): ?>
	<div class="tsm-card-actions">
<?php	if (!$info['allowlisted']): ?>
		<button type="button" class="btn btn-sm btn-outline-secondary" data-tsm-act="allow_ip"><i class="fa-solid fa-circle-check icon-embed-btn" aria-hidden="true"></i><?=gettext('Always allow')?></button>
<?php	endif; ?>
<?php	if ($info['verdict']): ?>
		<button type="button" class="btn btn-sm btn-outline-secondary" data-tsm-act="recheck_ip"><i class="fa-solid fa-rotate icon-embed-btn" aria-hidden="true"></i><?=gettext('Check again')?></button>
<?php	endif; ?>
<?php	if (array_intersect($info['tables'], ['threatshield_flood', 'virusprot'])): ?>
		<button type="button" class="btn btn-sm btn-outline-secondary" data-tsm-act="release_ip"><i class="fa-solid fa-unlock icon-embed-btn" aria-hidden="true"></i><?=gettext('Release')?></button>
<?php	endif; ?>
		<a class="btn btn-sm btn-link" href="/threatshield/threatshield_inbound.php?view=activity&amp;check=<?=rawurlencode($ip)?>"><?=gettext('Reputation lookup')?></a>
	</div>
<?php endif; ?>
	<p class="tsm-attrib fs-muted small"><a href="<?=THREATSHIELD_GEO_ATTRIBUTION_URL?>" target="_blank" rel="noopener"><?=THREATSHIELD_GEO_ATTRIBUTION?></a></p>
</div>
<?php
	exit;
}

ts_map_json(['error' => 'unknown request'], 400);
