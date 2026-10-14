<?php
/*
 * threatshield_dnsbl.inc
 * FreeSense Threat Shield - DNSBL reputation cache shared by the daemon and
 * the WebUI
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 *
 * Verdicts: 'listed' and 'clean' are cached in SQLite for their TTL;
 * lookup failures are kept in the daemon's memory only, so a resolver outage
 * never turns into a long-lived block.
 *
 * pf tables (see threatshield_pf.inc):
 *   threatshield_dnsbl_bad      listed sources
 *   threatshield_dnsbl_known    clean sources + IP allowlist + local ranges
 *   threatshield_dnsbl_known_f  known + sources whose lookup failed (allow-on-failure policies)
 *   threatshield_dnsbl_fail     sources whose lookup failed (fail-open + deny policies)
 */

function threatshield_dnsbl_db(): ?SQLite3 {
	if (!class_exists('SQLite3')) return null;
	if (!is_dir(THREATSHIELD_DNSBL_DIR)) @mkdir(THREATSHIELD_DNSBL_DIR, 0750, true);
	try {
		$db = new SQLite3(THREATSHIELD_DNSBL_DIR . '/cache.sqlite');
		$db->busyTimeout(3000);
		$db->exec('PRAGMA journal_mode=WAL');
		$db->exec('CREATE TABLE IF NOT EXISTS verdicts (ip TEXT PRIMARY KEY, verdict TEXT NOT NULL, zones TEXT NOT NULL DEFAULT \'\',
		    checked INTEGER NOT NULL, expires INTEGER NOT NULL, hits INTEGER NOT NULL DEFAULT 1)');
		$db->exec('CREATE INDEX IF NOT EXISTS verdicts_expires ON verdicts (expires)');
		return $db;
	} catch (Exception $e) {
		return null;
	}
}

/* Addresses that never need a lookup: the IP allowlist and local ranges. */
function threatshield_dnsbl_static_known(array $cfg): array {
	return array_values(array_unique(array_merge(threatshield_protected_ranges(), threatshield_local_networks(), threatshield_ip_allow_entries($cfg))));
}

/* The daemon writes known*.txt; until it runs (or while it is down) the
 * allowlist and local ranges must still pass a "deny on failure" policy. */
function threatshield_dnsbl_seed_known(array $cfg): void {
	$static = threatshield_dnsbl_static_known($cfg);
	foreach (['known.txt' => THREATSHIELD_T_KNOWN, 'known_f.txt' => THREATSHIELD_T_KNOWNF] as $name => $table) {
		$file = THREATSHIELD_DNSBL_DIR . '/' . $name;
		$have = is_file($file) ? array_values(array_filter(array_map('trim', (array)@file($file)))) : [];
		$all = array_values(array_unique(array_merge($static, $have)));
		if (is_file($file) && count($all) === count(array_unique($have))) continue;
		threatshield_write_table_file($file, $all);
		threatshield_pfctl_replace($table, $file);
	}
}

function threatshield_dnsbl_status(): array {
	$s = is_file(THREATSHIELD_DNSBL_STATUS) ? json_decode((string)@file_get_contents(THREATSHIELD_DNSBL_STATUS), true) : null;
	return is_array($s) ? $s : [];
}

/* Paged cache rows for the WebUI. */
function threatshield_dnsbl_rows(string $verdict, string $search, int $limit, int $offset, ?int &$total = null): array {
	$total = 0;
	$db = threatshield_dnsbl_db();
	if ($db === null) return [];
	$where = 'expires > :now';
	if (in_array($verdict, ['listed', 'clean'], true)) $where .= ' AND verdict = :verdict';
	if ($search !== '') $where .= ' AND (ip LIKE :search OR zones LIKE :search)';
	$bind = function (SQLite3Stmt $st) use ($verdict, $search) {
		$st->bindValue(':now', time(), SQLITE3_INTEGER);
		if (in_array($verdict, ['listed', 'clean'], true)) $st->bindValue(':verdict', $verdict, SQLITE3_TEXT);
		if ($search !== '') $st->bindValue(':search', '%' . $search . '%', SQLITE3_TEXT);
	};
	$st = $db->prepare("SELECT COUNT(*) FROM verdicts WHERE {$where}");
	$bind($st);
	$res = $st->execute();
	$total = (int)($res ? $res->fetchArray(SQLITE3_NUM)[0] : 0);
	$st = $db->prepare("SELECT ip, verdict, zones, checked, expires, hits FROM verdicts WHERE {$where} ORDER BY checked DESC LIMIT :limit OFFSET :offset");
	$bind($st);
	$st->bindValue(':limit', max(1, $limit), SQLITE3_INTEGER);
	$st->bindValue(':offset', max(0, $offset), SQLITE3_INTEGER);
	$rows = [];
	$res = $st->execute();
	while ($res && ($row = $res->fetchArray(SQLITE3_ASSOC))) $rows[] = $row;
	$db->close();
	return $rows;
}

function threatshield_dnsbl_tables(): array {
	return [THREATSHIELD_T_BAD, THREATSHIELD_T_KNOWN, THREATSHIELD_T_KNOWNF, THREATSHIELD_T_FAIL];
}

/* Forget cached verdicts so the next connection is checked again. */
function threatshield_dnsbl_forget(array $ips): int {
	$ips = array_values(array_filter($ips, fn($ip) => filter_var($ip, FILTER_VALIDATE_IP)));
	if (empty($ips)) return 0;
	$db = threatshield_dnsbl_db();
	if ($db !== null) {
		$st = $db->prepare('DELETE FROM verdicts WHERE ip = :ip');
		foreach ($ips as $ip) {
			$st->bindValue(':ip', $ip, SQLITE3_TEXT);
			$st->execute();
			$st->reset();
		}
		$db->close();
	}
	foreach (threatshield_dnsbl_tables() as $table) {
		mwexec('/sbin/pfctl -t ' . $table . ' -T delete ' . implode(' ', array_map('escapeshellarg', $ips)), true);
	}
	threatshield_dnsbl_signal();
	return count($ips);
}

function threatshield_dnsbl_flush(): void {
	$db = threatshield_dnsbl_db();
	if ($db !== null) {
		$db->exec('DELETE FROM verdicts');
		$db->close();
	}
	foreach (threatshield_dnsbl_tables() as $table) {
		@file_put_contents(THREATSHIELD_DNSBL_DIR . '/' . str_replace('threatshield_dnsbl_', '', $table) . '.txt', '');
		mwexec('/sbin/pfctl -t ' . $table . ' -T flush', true);
	}
	threatshield_dnsbl_signal();
}

/* Looks one address up in every enabled zone now, without the cache; for
 * "Check an address" and the updater's dnsbl-check mode.
 * Returns ['verdict' => listed|clean|fail|skip, 'zones' => [id => [qname,
 * rcode, answers, error, listed]], 'reason' => text]. */
function threatshield_dnsbl_lookup(string $ip, ?array $cfg = null): array {
	$cfg = $cfg ?? threatshield_config();
	$out = ['verdict' => 'skip', 'zones' => [], 'reason' => ''];
	if (!filter_var($ip, FILTER_VALIDATE_IP)) {
		$out['reason'] = gettext('Not an IP address.');
		return $out;
	}
	foreach (threatshield_dnsbl_static_known($cfg) as $cidr) {
		if (threatshield_cidr_contains($cidr, $ip)) {
			$out['reason'] = gettext('Local, private and allowlisted addresses are never checked.');
			return $out;
		}
	}
	$v6 = (strpos($ip, ':') !== false);
	$qnames = [];
	$zones = [];
	foreach (threatshield_normalize_list($cfg['dnsbl_zones'] ?? []) as $z) {
		if (!is_array($z) || ($z['enabled'] ?? 'off') !== 'on' || ($v6 && ($z['ipv6'] ?? 'off') !== 'on')) continue;
		$q = threatshield_dnsbl_qname($ip, (string)$z['zone'], (string)($z['access_key'] ?? ''));
		if ($q === null) continue;
		$zones[(string)$z['id']] = ['qname' => $q, 'match' => (string)($z['match'] ?? 'any')];
		$qnames[] = $q;
	}
	if (empty($zones)) {
		$out['reason'] = gettext('No enabled zone covers this address.');
		return $out;
	}
	[$server, $port] = threatshield_dnsbl_resolver($cfg);
	$answers = threatshield_dns_query_many($server, $port, $qnames, max(200, (int)($cfg['dnsbl_timeout_ms'] ?? 1500)));
	$results = [];
	foreach ($zones as $id => $z) {
		$r = $answers[$z['qname']] ?? ['rcode' => null, 'answers' => [], 'error' => 'timeout'];
		$results[$id] = $r + ['match' => $z['match']];
		$out['zones'][$id] = $r + ['qname' => $z['qname'],
		    'listed' => ($r['error'] ?? null) === null && ($r['rcode'] ?? null) === 0 && threatshield_dnsbl_match((array)$r['answers'], $z['match'])];
	}
	$quorum = max(1, min(count($zones), (int)($cfg['dnsbl_quorum'] ?? 1)));
	$out['verdict'] = threatshield_dnsbl_verdict($results, $quorum)['verdict'];
	return $out;
}

/* SIGHUP: the daemon reloads its settings and the cache. */
function threatshield_dnsbl_signal(): void {
	$pid = (int)trim((string)@file_get_contents(THREATSHIELD_DNSBL_PID_FILE));
	if ($pid > 0 && function_exists('posix_kill')) posix_kill($pid, 1);
}

/* Offenders caught by the flood limits: [['ip' => ..., 'since' => unix]] */
function threatshield_flood_entries(): array {
	if (!file_exists('/sbin/pfctl')) return [];
	exec('/sbin/pfctl -t ' . THREATSHIELD_T_FLOOD . ' -T show -v 2>/dev/null', $out);
	$rows = [];
	$current = null;
	foreach ($out as $line) {
		if (preg_match('/^\s+([0-9a-f:.\/]+)\s*$/i', $line, $m)) {
			if ($current !== null) $rows[] = $current;
			$current = ['ip' => $m[1], 'since' => 0, 'table' => THREATSHIELD_T_FLOOD];
		} elseif ($current !== null && preg_match('/Cleared:\s+(.+)$/', $line, $m)) {
			$t = strtotime(trim($m[1]));
			$current['since'] = ($t !== false) ? $t : 0;
		}
	}
	if ($current !== null) $rows[] = $current;
	exec('/sbin/pfctl -t virusprot -T show 2>/dev/null', $vp);
	foreach ($vp as $line) {
		$line = trim($line);
		if ($line !== '') $rows[] = ['ip' => $line, 'since' => 0, 'table' => 'virusprot'];
	}
	return $rows;
}

function threatshield_flood_release(string $ip, string $table): bool {
	if (!filter_var(explode('/', $ip)[0], FILTER_VALIDATE_IP) || !in_array($table, [THREATSHIELD_T_FLOOD, 'virusprot'], true)) return false;
	mwexec('/sbin/pfctl -t ' . $table . ' -T delete ' . escapeshellarg($ip), true);
	threatshield_dump_flood_table();
	return true;
}

/* Cron: releases flood offenders after the configured time. */
function threatshield_flood_expire(array $cfg): void {
	if (!file_exists('/sbin/pfctl')) return;
	$secs = max(60, (int)($cfg['flood_release_secs'] ?? 3600));
	mwexec('/sbin/pfctl -t ' . THREATSHIELD_T_FLOOD . ' -T expire ' . $secs, true);
	threatshield_dump_flood_table();
}
