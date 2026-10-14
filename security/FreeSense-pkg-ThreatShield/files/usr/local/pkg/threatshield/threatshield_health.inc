<?php
/*
 * threatshield_health.inc
 * FreeSense Threat Shield - health checks, pre-flight checks, self-repair and
 * the one-switch quick setup
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

function threatshield_health_check(string $id, string $label, string $state, string $detail = '', string $fix = ''): array {
	return ['id' => $id, 'label' => $label, 'state' => $state, 'detail' => $detail, 'fix' => $fix];
}

/* 'fail' beats 'warn' beats 'ok'; 'skip' never counts. */
function threatshield_health_worst(array $checks): string {
	$rank = ['ok' => 0, 'skip' => 0, 'warn' => 1, 'fail' => 2];
	$worst = 'ok';
	foreach ($checks as $c) {
		if (($rank[$c['state']] ?? 0) > $rank[$worst]) $worst = $c['state'];
	}
	return $worst;
}

/* Listening sockets on a port: [['command' => ..., 'proto' => ..., 'local' => ...]] */
function threatshield_sockets(int $port): array {
	if (!is_executable('/usr/bin/sockstat')) return [];
	exec('/usr/bin/sockstat -l -46 -P tcp,udp -p ' . (int)$port . ' 2>/dev/null', $out);
	$rows = [];
	foreach (array_slice($out, 1) as $line) {
		$f = preg_split('/\s+/', trim($line));
		if (count($f) >= 6) $rows[] = ['command' => $f[1], 'proto' => $f[4], 'local' => $f[5]];
	}
	return $rows;
}

function threatshield_pf_output(string $args): string {
	static $cache = [];
	if (!isset($cache[$args])) {
		$out = [];
		if (file_exists('/sbin/pfctl')) exec('/sbin/pfctl ' . $args . ' 2>/dev/null', $out);
		$cache[$args] = implode("\n", $out);
	}
	return $cache[$args];
}

function threatshield_pf_table_count(string $table): ?int {
	if (!file_exists('/sbin/pfctl')) return null;
	exec('/sbin/pfctl -t ' . escapeshellarg($table) . ' -T show 2>/dev/null', $out, $rc);
	return ($rc === 0) ? count($out) : null;
}

/* The DNS redirect currently loaded in pf, by redirect target port. */
function threatshield_pf_rdr_present(int $target): bool {
	return (bool)preg_match('/^rdr pass on \S+ inet proto (tcp|udp) .*port = (53|domain) -> 127\.0\.0\.1 port ' . $target . '\b/m',
	    threatshield_pf_output('-sn'));
}

/* Inbound policies whose DNSBL gate depends on the daemon running. */
function threatshield_dnsbl_soft_gates(array $cfg): array {
	$ids = [];
	if (($cfg['dnsbl_enable'] ?? 'off') !== 'on') return $ids;
	foreach (threatshield_normalize_list($cfg['inbound_policies'] ?? []) as $p) {
		if (is_array($p) && ($p['enable'] ?? 'on') === 'on' && ($p['dnsbl_mode'] ?? 'off') !== 'off' && ($p['on_failure'] ?? 'allow') === 'allow') {
			$ids[] = threatshield_pf_ident((string)($p['id'] ?? ''));
		}
	}
	return $ids;
}

/* Every check of the health panel.  Cached for 30 s; $deep adds the slow
 * upstream test. */
function threatshield_health(bool $deep = false, bool $use_cache = true): array {
	$cache = THREATSHIELD_CACHE_DIR . '/health.json';
	if ($use_cache && !$deep && is_file($cache) && (time() - (int)filemtime($cache)) < 30) {
		$data = json_decode((string)@file_get_contents($cache), true);
		if (is_array($data)) return $data;
	}
	$cfg = threatshield_config();
	$checks = [];
	if (($cfg['enable'] ?? 'off') !== 'on') {
		return [threatshield_health_check('engine', gettext('DNS filter'), 'skip', gettext('Threat Shield is turned off.'))];
	}
	$mode = (string)($cfg['dns_coordination_mode'] ?? 'primary');
	$target = threatshield_pf_redirect_target($cfg);
	$running = threatshield_is_running();
	$api = $running ? threatshield_api_request('status', 'GET', null, 1.0) : null;
	if (!$running) {
		$checks[] = threatshield_health_check('engine', gettext('DNS filter'), 'fail', gettext('AdGuard Home is not running.'), 'restart');
	} elseif ($api === null) {
		$checks[] = threatshield_health_check('engine', gettext('DNS filter'), 'warn', gettext('Running, but its management API does not answer.'), 'restart');
	} else {
		$checks[] = threatshield_health_check('engine', gettext('DNS filter'), 'ok', sprintf(gettext('AdGuard Home %s is running.'), (string)($api['version'] ?? '')));
	}

	$sockets = array_filter(threatshield_sockets($target), fn($s) => stripos($s['command'], 'AdGuard') === 0);
	if (!empty($sockets)) {
		$checks[] = threatshield_health_check('listener', gettext('DNS listener'), 'ok',
		    sprintf(gettext('Listening on %s.'), implode(', ', array_unique(array_column($sockets, 'local')))));
	} elseif (is_executable('/usr/bin/sockstat')) {
		$checks[] = threatshield_health_check('listener', gettext('DNS listener'), 'fail', sprintf(gettext('Nothing of Threat Shield listens on port %d.'), $target), 'restart');
	}

	$domain = (string)($cfg['health_test_domain'] ?? 'freesense.org');
	$probe = threatshield_dns_query_many('127.0.0.1', $target, [$domain, THREATSHIELD_PROBE_BLOCKED], 1500);
	$r = $probe[$domain];
	if ($r['rcode'] === 0 && !empty($r['answers'])) {
		$checks[] = threatshield_health_check('resolve', gettext('Name resolution'), 'ok', sprintf(gettext('%1$s resolves to %2$s.'), $domain, $r['answers'][0]));
	} elseif ($r['rcode'] !== null) {
		$checks[] = threatshield_health_check('resolve', gettext('Name resolution'), 'fail',
		    sprintf(gettext('%1$s did not resolve (DNS code %2$d): the upstream servers may be unreachable.'), $domain, $r['rcode']), 'settings');
	} else {
		$checks[] = threatshield_health_check('resolve', gettext('Name resolution'), 'fail', gettext('The DNS filter does not answer queries.'), 'restart');
	}

	$pause = threatshield_pause_state();
	$b = $probe[THREATSHIELD_PROBE_BLOCKED];
	$blocked = ($b['rcode'] === 3 || $b['rcode'] === 5 || in_array('0.0.0.0', $b['answers'], true) ||
	    (($cfg['blocking_mode'] ?? '') === 'custom_ip' && in_array((string)($cfg['blocking_ipv4'] ?? ''), $b['answers'], true)));
	if ($pause['active']) {
		$checks[] = threatshield_health_check('blocking', gettext('Blocking'), 'warn', ($pause['until'] > 0)
		    ? sprintf(gettext('Paused until %s.'), date('H:i', $pause['until'])) : gettext('Paused until resumed.'), 'resume');
	} elseif ($b['rcode'] !== null) {
		$checks[] = threatshield_health_check('blocking', gettext('Blocking'), $blocked ? 'ok' : 'fail',
		    $blocked ? gettext('A test domain is blocked as expected.') : gettext('A test domain was not blocked.'), $blocked ? '' : 'restart');
	}

	if ($mode === 'primary') {
		$u = threatshield_dns_query_many('127.0.0.1', 5335, [$domain], 1500)[$domain];
		$checks[] = threatshield_health_check('unbound', gettext('DNS Resolver (local names)'), ($u['rcode'] !== null) ? 'ok' : 'warn',
		    ($u['rcode'] !== null) ? gettext('Answers on 127.0.0.1:5335 for local host names and reverse lookups.')
		    : gettext('The DNS Resolver does not answer on 127.0.0.1:5335; local host names will not resolve.'), 'reload_unbound');
	} elseif ($mode === 'proxy') {
		$opts = base64_decode((string)config_get_path('unbound/custom_options', ''));
		$ok = config_path_enabled('unbound') && strpos((string)$opts, 'forward-addr: 127.0.0.1@5354') !== false;
		$checks[] = threatshield_health_check('unbound', gettext('DNS Resolver (proxy)'), $ok ? 'ok' : 'fail',
		    $ok ? gettext('The DNS Resolver forwards to Threat Shield.') : gettext('The DNS Resolver does not forward to Threat Shield.'), $ok ? '' : 'resync');
	}

	if ($deep && $api !== null) {
		$upstreams = array_values(array_filter(array_map('trim', threatshield_lines((string)($cfg['upstreams'] ?? '')))));
		$test = threatshield_api_request('test_upstream_dns', 'POST', ['upstream_dns' => $upstreams,
		    'bootstrap_dns' => array_values(array_filter(array_map('trim', threatshield_lines((string)($cfg['bootstrap_dns'] ?? '')))))], 15);
		$bad = [];
		foreach ((array)$test as $server => $result) {
			if ($result !== 'OK') $bad[] = $server;
		}
		$checks[] = threatshield_health_check('upstreams', gettext('Upstream servers'), empty($bad) ? 'ok' : 'warn',
		    empty($bad) ? gettext('Every upstream server answers.') : sprintf(gettext('Not answering: %s'), implode(', ', $bad)), 'settings');
	}

	$health = threatshield_feed_health($cfg);
	$counts = ['ok' => 0, 'failing' => 0, 'stale' => 0, 'empty' => 0, 'pending' => 0];
	$rules = 0;
	foreach (threatshield_normalize_list($cfg['feeds'] ?? []) as $feed) {
		if (!is_array($feed) || ($feed['enabled'] ?? 'off') !== 'on') continue;
		$h = $health[(string)($feed['url'] ?? '')] ?? ['state' => 'pending'];
		$counts[$h['state']] = ($counts[$h['state']] ?? 0) + 1;
		$rules += (int)($h['rules'] ?? 0);
	}
	$state = ($counts['failing'] > 0) ? 'fail' : (($counts['stale'] + $counts['empty'] + $counts['pending'] > 0) ? 'warn' : 'ok');
	$checks[] = threatshield_health_check('lists', gettext('Blocklists'), $state, ($state === 'ok')
	    ? sprintf(gettext('%1$s rules loaded from %2$d lists.'), number_format($rules), $counts['ok'])
	    : sprintf(gettext('%1$d failing, %2$d outdated or empty, %3$d not downloaded yet.'), $counts['failing'], $counts['stale'] + $counts['empty'], $counts['pending']),
	    ($state === 'ok') ? '' : 'update_feeds');

	if (file_exists('/sbin/pfctl')) {
		$checks = array_merge($checks, threatshield_health_pf($cfg));
	}

	$crontab = (string)@file_get_contents('/etc/crontab');
	$checks[] = threatshield_health_check('cron', gettext('Scheduled updates'), (strpos($crontab, THREATSHIELD_UPDATER) !== false) ? 'ok' : 'warn',
	    (strpos($crontab, THREATSHIELD_UPDATER) !== false) ? gettext('List and health updates are scheduled.') : gettext('The update jobs are missing from cron.'), 'resync');

	$free = @disk_free_space(THREATSHIELD_DB_DIR);
	if ($free !== false) {
		$mb = (int)($free / 1048576);
		$checks[] = threatshield_health_check('disk', gettext('Disk space'), ($mb < 50) ? 'fail' : (($mb < 200) ? 'warn' : 'ok'),
		    sprintf(gettext('%d MB free for lists and logs.'), $mb));
	}

	if (threatshield_dnsbl_wanted($cfg)) {
		$status = json_decode((string)@file_get_contents(THREATSHIELD_DNSBL_STATUS), true);
		if (!threatshield_dnsbl_running()) {
			$checks[] = threatshield_health_check('dnsbl', gettext('Reputation checks'), 'fail', gettext('The DNSBL service is not running; new sources are handled by each policy\'s failure action.'), 'start_dnsbl');
		} elseif (is_array($status) && ($status['breaker'] ?? 'closed') === 'open') {
			$checks[] = threatshield_health_check('dnsbl', gettext('Reputation checks'), 'warn',
			    sprintf(gettext('Lookups fail (%s); new sources are handled by each policy\'s failure action.'), (string)($status['last_error'] ?? '')));
		} else {
			$checks[] = threatshield_health_check('dnsbl', gettext('Reputation checks'), 'ok', is_array($status)
			    ? sprintf(gettext('%1$s lookups, %2$s listed sources blocked.'), number_format((int)($status['lookups'] ?? 0)), number_format((int)($status['listed'] ?? 0)))
			    : gettext('Running.'));
		}
	}

	if (is_dir(THREATSHIELD_CACHE_DIR)) @file_put_contents($cache, json_encode($checks), LOCK_EX);
	return $checks;
}

/* pf part of the health panel: the rules and tables the settings ask for are
 * really loaded. */
function threatshield_health_pf(array $cfg): array {
	$checks = [];
	if (is_file('/tmp/rules.packages.threatshield')) {
		$checks[] = threatshield_health_check('pf', gettext('Firewall rules'), 'fail',
		    gettext('The firewall rejected Threat Shield\'s rules. See /tmp/rules.packages.threatshield.'), 'reload_filter');
		return $checks;
	}
	$rules = threatshield_pf_output('-sr');
	$expect = [];
	if (($cfg['geoip_enable'] ?? 'off') === 'on') {
		foreach (threatshield_normalize_list($cfg['geoip_policies'] ?? []) as $p) {
			if (is_array($p) && ($p['enable'] ?? 'on') === 'on' && !empty($p['countries'])) $expect['ThreatShield GeoIP'] = gettext('GeoIP');
		}
	}
	if (($cfg['block_dot'] ?? 'off') === 'on' && !empty($cfg['dns_intercept_interfaces'])) $expect['ThreatShield anti-bypass DoT'] = gettext('DoT blocking');
	if (($cfg['block_doh_ips'] ?? 'off') === 'on' && !empty($cfg['dns_intercept_interfaces'])) $expect['ThreatShield anti-bypass DoH'] = gettext('DoH blocking');
	if (($cfg['ipbl_enable'] ?? 'off') === 'on') $expect['ThreatShield IP list'] = gettext('IP lists');
	foreach (threatshield_normalize_list($cfg['inbound_policies'] ?? []) as $p) {
		if (is_array($p) && ($p['enable'] ?? 'on') === 'on') $expect['ThreatShield ' . threatshield_pf_ident((string)($p['id'] ?? ''))] = (string)($p['name'] ?? '');
	}
	$missing = [];
	foreach ($expect as $label => $name) {
		if (strpos($rules, $label) === false) $missing[] = $name;
	}
	$checks[] = threatshield_health_check('pf', gettext('Firewall rules'), empty($missing) ? 'ok' : 'fail', empty($missing)
	    ? (empty($expect) ? gettext('No firewall rules needed.') : sprintf(gettext('Loaded: %s.'), implode(', ', array_values($expect))))
	    : sprintf(gettext('Not loaded: %s.'), implode(', ', $missing)), empty($missing) ? '' : 'reload_filter');

	if (($cfg['catch_rogue_dns'] ?? 'off') === 'on' && !empty($cfg['dns_intercept_interfaces'])) {
		$present = threatshield_pf_rdr_present(threatshield_pf_redirect_target($cfg));
		$checks[] = threatshield_health_check('redirect', gettext('DNS redirection'), $present ? 'ok' : 'fail', $present
		    ? gettext('Queries to other DNS servers are redirected to Threat Shield.')
		    : gettext('The redirect is not loaded (it is held back while the DNS filter does not answer).'), $present ? '' : 'reload_filter');
	}

	$empty = [];
	foreach (threatshield_normalize_list($cfg['geoip_policies'] ?? []) as $p) {
		if (($cfg['geoip_enable'] ?? 'off') !== 'on' || !is_array($p) || ($p['enable'] ?? 'on') !== 'on' || empty($p['countries'])) continue;
		$id = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($p['id'] ?? 'default'))) ?: 'default';
		if ((int)threatshield_pf_table_count(threatshield_geoip_table($id)) === 0) $empty[] = 'GeoIP ' . $id;
	}
	foreach (threatshield_active_ipfeeds($cfg) as $feed) {
		if (($feed['kind'] ?? 'threat') !== 'threat') continue;
		$table = 'ts_ipf_' . threatshield_pf_ident((string)$feed['id']);
		if ((int)threatshield_pf_table_count($table) === 0) $empty[] = (string)($feed['name'] ?? $table);
	}
	if (($cfg['block_doh_ips'] ?? 'off') === 'on' && (int)threatshield_pf_table_count(THREATSHIELD_T_DOH) === 0) $empty[] = gettext('DoH resolvers');
	if (!empty($empty)) {
		$checks[] = threatshield_health_check('tables', gettext('Address tables'), 'warn', sprintf(gettext('Empty: %s.'), implode(', ', $empty)), 'update_feeds');
	}
	return $checks;
}

/* Problems with a configuration before it is applied: 'block' entries stop
 * the save, 'warn' entries are shown with the result. */
function threatshield_preflight(array $candidate, array $current): array {
	$block = [];
	$warn = [];
	$on = ($candidate['enable'] ?? 'off') === 'on';
	if (!$on) return ['block' => [], 'warn' => []];
	$mode = (string)($candidate['dns_coordination_mode'] ?? 'primary');
	$port = ($mode === 'proxy') ? 5354 : (int)($candidate['listen_port'] ?? 53);
	$running = threatshield_is_running();

	if ($mode !== 'proxy' && config_path_enabled('dnsmasq')) {
		$block[] = gettext('The DNS Forwarder (dnsmasq) is enabled and holds port 53. Turn it off under Services > DNS Forwarder, or use proxy mode with the DNS Resolver.');
	}
	foreach (threatshield_sockets($port) as $s) {
		$cmd = strtolower($s['command']);
		if (strpos($cmd, 'adguard') === 0 || strpos($cmd, 'unbound') === 0 || strpos($cmd, 'dnsmasq') === 0) continue;
		$block[] = sprintf(gettext('Port %1$d is already used by %2$s (%3$s).'), $port, $s['command'], $s['local']);
		break;
	}

	$redirect_on = ($candidate['catch_rogue_dns'] ?? 'off') === 'on';
	$redirect_was_on = ($current['catch_rogue_dns'] ?? 'off') === 'on' && ($current['enable'] ?? 'off') === 'on';
	if ($redirect_on && empty(threatshield_normalize_list($candidate['dns_intercept_interfaces'] ?? []))) {
		$warn[] = gettext('DNS redirection is on, but no interface is selected, so nothing is redirected.');
	}
	if ($redirect_on && !$redirect_was_on && $running && ($current['enable'] ?? 'off') === 'on' && !threatshield_listener_healthy($current, 1500)) {
		$block[] = gettext('DNS redirection was not turned on: Threat Shield does not answer DNS queries right now, so redirecting would break DNS for the LAN. Check the health panel on the Overview.');
	}

	$wans = threatshield_wan_interfaces();
	$listen = threatshield_normalize_list($candidate['interfaces'] ?? ['all']);
	if (!empty(array_intersect($listen, array_keys($wans)))) {
		$warn[] = gettext('Threat Shield listens on a WAN interface. Keep DNS closed to the internet with firewall rules, or it can be abused for amplification attacks.');
	}
	if (!$redirect_on) {
		$fw_ips = [];
		foreach (array_keys(threatshield_assigned_interfaces()) as $if) {
			$ip = function_exists('get_interface_ip') ? get_interface_ip($if) : null;
			if (is_string($ip)) $fw_ips[] = $ip;
		}
		foreach (config_get_path('dhcpd', []) as $if => $scope) {
			if (!is_array($scope) || !isset($scope['enable'])) continue;
			$servers = array_filter((array)($scope['dnsserver'] ?? []));
			if (!empty($servers) && empty(array_intersect($servers, $fw_ips))) {
				$warn[] = sprintf(gettext('DHCP on %1$s hands out other DNS servers (%2$s). Those clients bypass Threat Shield unless DNS redirection is on.'),
				    strtoupper((string)$if), implode(', ', $servers));
			}
		}
	}
	if (($candidate['dnsbl_enable'] ?? 'off') === 'on' && $mode === 'primary' && trim((string)($candidate['dnsbl_resolver'] ?? 'auto')) === 'auto' &&
	    config_path_enabled('unbound', 'forwarding')) {
		$warn[] = gettext('The DNS Resolver forwards to other servers, so DNSBL lookups reach Spamhaus through a public resolver and are refused. Turn forwarding off, set a DNSBL resolver, or use a DQS key.');
	}
	foreach (threatshield_normalize_list($candidate['inbound_policies'] ?? []) as $p) {
		if (is_array($p) && ($p['enable'] ?? 'on') === 'on' && ($p['owned'] ?? 'off') === 'on') {
			$warn[] = sprintf(gettext('Inbound policy "%1$s" passes port %2$s itself: firewall rules for that traffic no longer apply.'),
			    (string)($p['name'] ?? $p['id'] ?? ''), (string)($p['ports'] ?? ''));
		}
	}

	$limit = 0;
	if (preg_match('/table-entries\s+hard limit\s+(\d+)/', threatshield_pf_output('-sm'), $m)) $limit = (int)$m[1];
	if ($limit > 0) {
		$entries = 0;
		foreach (threatshield_active_ipfeeds($candidate) as $feed) {
			$raw = threatshield_ipfeed_raw_path($feed);
			if (is_file($raw)) $entries += count(file($raw, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
		}
		foreach (threatshield_normalize_list($candidate['geoip_policies'] ?? []) as $p) {
			foreach (threatshield_normalize_list(is_array($p) ? ($p['countries'] ?? []) : []) as $cc) {
				$zone = THREATSHIELD_GEOIP_DIR . '/' . strtoupper((string)$cc) . '.zone';
				if (is_file($zone)) $entries += count(file($zone, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
			}
		}
		if ($entries > $limit * 0.9) {
			$block[] = sprintf(gettext('The selected IP lists and countries need about %1$s table entries, more than the firewall allows (%2$s). Raise "Firewall Maximum Table Entries" under System > Advanced > Firewall & NAT, or select fewer lists.'),
			    number_format($entries), number_format($limit));
		}
	}
	return ['block' => $block, 'warn' => $warn];
}

/* Self-repair, run by cron every 5 minutes and after the service starts:
 * restarts what should run and reloads the filter when the loaded rules no
 * longer match the health of the services they depend on. */
function threatshield_reconcile(bool $after_start = false): void {
	$cfg = threatshield_config();
	if (($cfg['enable'] ?? 'off') !== 'on') return;
	if (!$after_start) {
		/* A Save & Apply stops and starts the services itself: never race it. */
		$lock = threatshield_apply_lock(false);
		if ($lock === false) return;
		threatshield_apply_unlock($lock);
	}
	if ($after_start) {
		for ($i = 0; $i < 40 && !threatshield_listener_healthy($cfg, 500); $i++) usleep(500000);
	} elseif (!threatshield_is_running()) {
		logger(LOG_WARNING, 'Threat Shield: AdGuard Home was not running; starting it.');
		threatshield_service_control('start');
	}
	if (threatshield_dnsbl_wanted($cfg) && !threatshield_dnsbl_running()) {
		logger(LOG_WARNING, 'Threat Shield: the DNSBL service was not running; starting it.');
		threatshield_service_control('start', 'threatshield_dnsbl');
	}
	$reload = false;
	if (($cfg['catch_rogue_dns'] ?? 'off') === 'on' && !empty(threatshield_normalize_list($cfg['dns_intercept_interfaces'] ?? []))) {
		$healthy = threatshield_listener_healthy($cfg);
		$present = threatshield_pf_rdr_present(threatshield_pf_redirect_target($cfg));
		if ($healthy !== $present) {
			$reload = true;
			if (!$healthy) {
				file_notice('threatshield', gettext('Threat Shield stopped answering DNS queries, so its DNS redirection was removed to keep DNS working. It returns once the service answers again.'),
				    gettext('Threat Shield'), '/threatshield/threatshield_status.php');
			}
		}
	}
	$soft = threatshield_dnsbl_soft_gates($cfg);
	if (!empty($soft)) {
		$rules = threatshield_pf_output('-sr');
		$up = threatshield_dnsbl_running();
		foreach ($soft as $id) {
			/* an allow-on-failure gate is only loaded while the daemon runs */
			$gate = strpos($rules, "ThreatShield {$id} DNSBL pending") !== false || strpos($rules, "ThreatShield {$id} DNSBL check") !== false;
			if ($gate !== $up) $reload = true;
		}
	}
	@unlink(THREATSHIELD_CACHE_DIR . '/health.json');
	if ($reload) filter_configure();
}

/* One switch: sane defaults for DNS blocking on the LAN side. */
function threatshield_quick_setup(bool $block_dot, bool $block_doh, array &$errors, array &$messages): bool {
	$cfg = threatshield_config();
	$wans = array_keys(threatshield_wan_interfaces());
	$lans = array_values(array_diff(array_keys(threatshield_assigned_interfaces()), $wans));
	$cfg['enable'] = 'on';
	$cfg['dns_coordination_mode'] = 'primary';
	$cfg['listen_port'] = '53';
	$cfg['interfaces'] = empty($lans) ? ['all'] : $lans;
	if (($cfg['feed_level'] ?? 'custom') !== 'custom' || empty(threatshield_normalize_list($cfg['feeds'] ?? []))) {
		$cfg['feeds'] = threatshield_apply_feed_level(threatshield_normalize_list($cfg['feeds'] ?? []), 'normal');
		$cfg['feed_level'] = 'normal';
	}
	$cfg['block_doh_canary'] = 'on';
	$cfg['catch_rogue_dns'] = empty($lans) ? 'off' : 'on';
	$cfg['dns_intercept_interfaces'] = $lans;
	$cfg['block_dns6_bypass'] = 'on';
	$cfg['block_dot'] = $block_dot ? 'on' : 'off';
	$cfg['block_doh_ips'] = $block_doh ? 'on' : 'off';
	$warnings = [];
	if (!threatshield_save_and_apply($cfg, gettext('Threat Shield: quick setup turned on DNS blocking'), $errors, $warnings)) {
		return false;
	}
	$messages = $warnings;
	$check = threatshield_dns_query_many('127.0.0.1', 53, [(string)($cfg['health_test_domain'] ?? 'freesense.org')], 3000);
	$first = reset($check);
	if ($first['rcode'] !== 0 && $cfg['catch_rogue_dns'] === 'on') {
		$cfg['catch_rogue_dns'] = 'off';
		threatshield_save_and_apply($cfg, gettext('Threat Shield: quick setup held back DNS redirection'), $errors, $warnings);
		$messages[] = gettext('DNS blocking is on, but test queries did not resolve yet, so DNS redirection was left off. Check the upstream servers, then turn redirection on under Settings.');
	}
	return true;
}
