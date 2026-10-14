<?php
/*
 * threatshield_update.php
 * FreeSense Threat Shield - list downloads and scheduled maintenance
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 *
 * freesense-threatshield-update <mode> [force]
 *   feeds         DNS block and allow lists
 *   geoip         country address lists
 *   ipfeeds       IP threat lists and DoH resolver lists
 *   all           all three
 *   health        self-repair (cron, every 5 minutes)
 *   reconcile     after the service started: reload the filter once DNS answers
 *   flood-expire  release flood offenders after the configured time (cron)
 *   geodb         IP location database for the threat map (monthly, DB-IP Lite)
 *   map-collect   threat map: read new log lines (cron, every minute)
 *   map-prune     threat map: drop data older than the retention
 *   dnsbl-check <ip>  look an address up in the DNSBL zones now
 */

require_once('threatshield.inc');

$mode = $argv[1] ?? 'all';
$force = ($argv[2] ?? '') === 'force';
$cfg = threatshield_config();

foreach ([THREATSHIELD_DB_DIR, THREATSHIELD_FILTER_DIR, THREATSHIELD_GEOIP_DIR, THREATSHIELD_IP_DIR, THREATSHIELD_IP_DIR . '/raw', THREATSHIELD_CACHE_DIR] as $dir) {
	safe_mkdir($dir, 0750);
}

/* Downloads $url to $dest atomically.  Returns null on success or an error
 * text; the previous copy is kept on any failure. */
function threatshield_download_file(string $url, string $dest): ?string {
	$parts = parse_url($url);
	if (!is_array($parts) || strtolower($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])) {
		return 'not an HTTPS URL';
	}
	$tmp = $dest . '.tmp.' . getmypid();
	$fp = @fopen($tmp, 'x');
	if (!$fp) return 'cannot write ' . dirname($dest);
	$ch = curl_init($url);
	curl_setopt($ch, CURLOPT_FILE, $fp);
	curl_setopt($ch, CURLOPT_TIMEOUT, 60);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
	curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
	curl_setopt($ch, CURLOPT_USERAGENT, 'FreeSense-ThreatShield/1.1');
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
	curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
	curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
	curl_setopt($ch, CURLOPT_NOPROGRESS, false);
	curl_setopt($ch, CURLOPT_PROGRESSFUNCTION, static function ($resource, $downloadSize, $downloaded) {
		return $downloaded > THREATSHIELD_MAX_FEED_BYTES ? 1 : 0;
	});

	$success = curl_exec($ch);
	$code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
	$curl_error = curl_error($ch);
	$aborted = curl_errno($ch) === CURLE_ABORTED_BY_CALLBACK;
	curl_close($ch);
	fclose($fp);

	$error = null;
	if ($aborted) {
		$error = sprintf('larger than %d MB', THREATSHIELD_MAX_FEED_BYTES / 1048576);
	} elseif (!$success) {
		$error = ($curl_error !== '') ? $curl_error : 'download failed';
	} elseif ($code < 200 || $code >= 300) {
		$error = "HTTP {$code}";
	} else {
		/* A captive portal or error page answered with HTTP 200; loading it
		 * would silently replace a working list with nothing. */
		$head = (string)@file_get_contents($tmp, false, null, 0, 2048);
		if (filesize($tmp) === 0) $error = 'empty file';
		elseif (preg_match('/<\s*(!doctype|html|head|body)\b/i', $head)) $error = 'received a web page instead of a list';
	}
	if ($error !== null || !@rename($tmp, $dest)) {
		@unlink($tmp);
		return $error ?? 'cannot replace the cached copy';
	}
	return null;
}

function threatshield_interval_due(string $kind, string $interval): bool {
	$hours = ['6hours' => 6, '12hours' => 12, 'daily' => 24, 'weekly' => 168][$interval] ?? 24;
	$last = threatshield_last_update($kind);
	return $last <= 0 || (time() - $last) >= ($hours * 3600);
}

function threatshield_mark_updated(string $kind): void {
	file_put_contents(THREATSHIELD_DB_DIR . '/last_' . $kind . '_update', (string)time() . "\n", LOCK_EX);
}

/* Per-URL download results for the Blocklists page and the health panel. */
function threatshield_record_status(string $url, ?string $error, string $file, int $entries = -1): void {
	$status = is_file(THREATSHIELD_FEED_STATUS) ? json_decode((string)file_get_contents(THREATSHIELD_FEED_STATUS), true) : [];
	$status = is_array($status) ? $status : [];
	$s = is_array($status[$url] ?? null) ? $status[$url] : [];
	$s['last_attempt'] = time();
	$s['error'] = $error;
	if ($error === null) {
		$s['last_success'] = time();
		$s['bytes'] = is_file($file) ? filesize($file) : 0;
		if ($entries >= 0) $s['entries'] = $entries;
	}
	$status[$url] = $s;
	$tmp = THREATSHIELD_FEED_STATUS . '.tmp.' . getmypid();
	file_put_contents($tmp, json_encode($status), LOCK_EX);
	@rename($tmp, THREATSHIELD_FEED_STATUS);
}

/* Downloads one list and reports it; returns null or the error text. */
function threatshield_fetch(string $label, string $url, string $dest): ?string {
	echo "  - {$label} ({$url})... ";
	$error = threatshield_download_file($url, $dest);
	echo ($error === null) ? "OK, " . filesize($dest) . " bytes\n" : "FAILED: {$error}\n";
	if ($error !== null) logger(LOG_WARNING, "Threat Shield: download of {$label} failed: {$error}");
	return $error;
}

switch ($mode) {
	case 'health':
		threatshield_reconcile(false);
		exit(0);
	case 'reconcile':
		threatshield_reconcile(true);
		exit(0);
	case 'flood-expire':
		threatshield_flood_expire($cfg);
		exit(0);
	case 'map-collect':
		if (($cfg['enable'] ?? 'off') === 'on') {
			threatshield_map_collect($cfg, true);
			}
		exit(0);
	case 'map-prune':
		threatshield_map_prune($cfg);
		exit(0);
	case 'geodb':
		$kind = (string)($cfg['map_geodb'] ?? 'off');
		if ($kind === 'off' && !$force) exit(0);
		$meta = json_decode((string)@file_get_contents(THREATSHIELD_GEO_DIR . '/meta.json'), true);
		$have = is_array($meta) ? (string)($meta['month'] ?? '') : '';
		$complete = $have !== '' && (($meta['asn'] ?? false) || $kind !== 'country_asn');
		if ($complete && $have === gmdate('Y-m') && !$force) exit(0);
		/* DB-IP publishes early in the month; until then only look for a
		 * newer file instead of fetching last month's copy again every night */
		$newer = array_values(array_filter(threatshield_geo_dbip_urls('country', time()),
		    fn($u) => !preg_match('/(\d{4}-\d{2})\.csv\.gz$/', $u, $m) || $m[1] > $have));
		if ($complete && !$force && empty($newer)) exit(0);
		echo "[ThreatShield] Updating the IP location database (DB-IP Lite)...\n";
		$tmpdir = THREATSHIELD_DB_DIR . '/geodb.download';
		safe_mkdir($tmpdir, 0750);
		$files = [];
		foreach (($kind === 'country_asn') ? ['country', 'asn'] : ['country'] as $part) {
			$error = 'no download';
			$urls = ($part === 'country' && $complete && !$force) ? $newer : threatshield_geo_dbip_urls($part, time());
			foreach ($urls as $url) {
				$dest = $tmpdir . '/' . basename($url);
				$error = threatshield_fetch("DB-IP {$part}", $url, $dest);
				if ($error === null && (string)@file_get_contents($dest, false, null, 0, 2) !== "\x1f\x8b") $error = 'not a gzip file';
				if ($error === null) { $files[$part] = $dest; break; }
				@unlink($dest);
			}
			if (!isset($files[$part])) {
				logger(LOG_WARNING, "Threat Shield: the IP location database could not be downloaded ({$error}); the previous copy stays in use.");
				exit(1);
			}
		}
		$stats = null;
		$ok = threatshield_geo_build($files['country'], $files['asn'] ?? null, THREATSHIELD_GEO_DIR, $stats);
		foreach ($files as $f) @unlink($f);
		echo $ok ? '[ThreatShield] Location database built: ' . json_encode($stats) . "\n" : "[ThreatShield] Building the location database failed.\n";
		if ($ok) threatshield_mark_updated('geodb');
		exit($ok ? 0 : 1);
	case 'dnsbl-check':
		$r = threatshield_dnsbl_lookup((string)($argv[2] ?? ''), $cfg);
		foreach ($r['zones'] as $id => $z) {
			printf("%-12s %-50s %s\n", $id, $z['qname'], ($z['error'] ?? null) !== null ? 'error: ' . $z['error']
			    : (($z['rcode'] === 3) ? 'not listed' : 'rcode ' . $z['rcode'] . ' ' . implode(',', (array)$z['answers']) . ($z['listed'] ? ' (listed)' : '')));
		}
		echo 'verdict: ', $r['verdict'], ($r['reason'] !== '') ? ' (' . $r['reason'] . ')' : '', "\n";
		exit(($r['verdict'] === 'fail') ? 1 : 0);
}

if (($mode === 'all' || $mode === 'feeds') && ($force || threatshield_interval_due('feeds', (string)($cfg['feed_update_interval'] ?? 'daily')))) {
	echo "[ThreatShield] Updating DNS lists...\n";
	$changed = ['block' => false, 'allow' => false];
	$failures = 0;
	foreach (threatshield_normalize_list($cfg['feeds'] ?? []) as $feed) {
		if (!is_array($feed) || ($feed['enabled'] ?? '') !== 'on' || empty($feed['url'])) continue;
		$url = (string)$feed['url'];
		$dest = threatshield_feed_path($url);
		$error = threatshield_fetch((string)($feed['name'] ?? $url), $url, $dest);
		threatshield_record_status($url, $error, $dest);
		if ($error === null) $changed[(($feed['kind'] ?? 'block') === 'allow') ? 'allow' : 'block'] = true;
		else $failures++;
	}
	$applied = true;
	if (threatshield_is_running()) {
		foreach ($changed as $kind => $did) {
			if (!$did) continue;
			echo "[ThreatShield] Loading the {$kind} lists into AdGuard Home...\n";
			$refresh = threatshield_api_request('filtering/refresh', 'POST', ['whitelist' => ($kind === 'allow')]);
			if (!is_array($refresh) || !isset($refresh['updated'])) {
				$applied = false;
				echo "    [FAIL] AdGuard Home rejected the reload; the updater will retry.\n";
			}
		}
	}
	if ($applied && ($changed['block'] || $changed['allow'] || $failures === 0)) threatshield_mark_updated('feeds');
	@unlink(THREATSHIELD_CACHE_DIR . '/api_' . md5('filtering/status') . '.json');
}

if (($mode === 'all' || $mode === 'ipfeeds') && ($force || threatshield_interval_due('ipfeeds', (string)($cfg['ipbl_update_interval'] ?? 'daily')))) {
	echo "[ThreatShield] Updating IP lists...\n";
	$any = false;
	foreach (threatshield_active_ipfeeds($cfg) as $feed) {
		$url = (string)$feed['url'];
		$dest = threatshield_ipfeed_raw_path($feed);
		/* keep the last good copy until the new one proves to hold addresses */
		$error = threatshield_fetch((string)($feed['name'] ?? $url), $url, $dest . '.new');
		$entries = ($error === null) ? count(threatshield_parse_ip_list((string)file_get_contents($dest . '.new'))) : -1;
		if ($entries === 0) $error = 'no IP addresses in the list';
		if ($error === null && !@rename($dest . '.new', $dest)) $error = 'cannot replace the cached copy';
		@unlink($dest . '.new');
		threatshield_record_status($url, $error, $dest, $entries);
		$any = $any || $error === null;
	}
	echo "[ThreatShield] Rebuilding pf IP tables...\n";
	threatshield_update_ip_tables($cfg);
	if ($any || empty(threatshield_active_ipfeeds($cfg))) threatshield_mark_updated('ipfeeds');
}

if (($mode === 'all' || $mode === 'geoip') && ($force || threatshield_interval_due('geoip', (string)($cfg['geoip_update_interval'] ?? 'weekly')))) {
	echo "[ThreatShield] Updating GeoIP country lists...\n";
	if (($cfg['geoip_enable'] ?? 'off') === 'on' && !empty($cfg['geoip_policies'])) {
		$countries = [];
		foreach (threatshield_normalize_list($cfg['geoip_policies']) as $policy) {
			$countries = array_merge($countries, threatshield_normalize_list(is_array($policy) ? ($policy['countries'] ?? []) : []));
		}
		$v6 = ($cfg['geoip_ipv6'] ?? 'off') === 'on';
		$ok = true;
		foreach (array_unique($countries) as $cc) {
			$cc = strtolower(preg_replace('/[^a-zA-Z]/', '', (string)$cc));
			if ($cc === '') continue;
			$CC = strtoupper($cc);
			$ok = (threatshield_fetch("{$CC} IPv4", "https://www.ipdeny.com/ipblocks/data/countries/{$cc}.zone", THREATSHIELD_GEOIP_DIR . "/{$CC}.zone") === null) && $ok;
			if ($v6) {
				$ok = (threatshield_fetch("{$CC} IPv6", "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{$cc}-aggregated.zone", THREATSHIELD_GEOIP_DIR . "/{$CC}.zone6") === null) && $ok;
			}
		}
		echo "[ThreatShield] Rebuilding pf GeoIP tables...\n";
		threatshield_update_geoip($cfg);
		if ($ok) threatshield_mark_updated('geoip');
	}
}

echo "[ThreatShield] Update complete.\n";
