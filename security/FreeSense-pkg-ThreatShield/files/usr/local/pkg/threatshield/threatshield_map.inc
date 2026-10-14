<?php
/*
 * threatshield_map.inc
 * FreeSense Threat Shield - threat map: collects firewall log lines, DNS
 * answers and reputation verdicts into a small event store and serves the
 * summaries, live events and IP details the map pages show
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 *
 * Nothing runs in the background except an optional per-minute cron job:
 * the map pages call threatshield_map_collect(), which reads what was added
 * to /var/log/filter.log since the last run (at most one run per 1.5 s, no
 * matter how many screens show the map).
 */

require_once(__DIR__ . '/threatshield_geo.inc');

if (!defined('THREATSHIELD_MAP_DB')) define('THREATSHIELD_MAP_DB', '/var/db/threatshield/map.sqlite');
if (!defined('THREATSHIELD_MAP_STATE')) define('THREATSHIELD_MAP_STATE', '/var/db/threatshield/map_state.json');
if (!defined('THREATSHIELD_MAP_LOCK')) define('THREATSHIELD_MAP_LOCK', '/var/run/threatshield_map.lock');
if (!defined('THREATSHIELD_MAP_RULES')) define('THREATSHIELD_MAP_RULES', '/var/db/threatshield/cache/map_rules.json');
if (!defined('THREATSHIELD_FILTER_LOG')) define('THREATSHIELD_FILTER_LOG', '/var/log/filter.log');
if (!defined('THREATSHIELD_DNSBL_RECENT')) define('THREATSHIELD_DNSBL_RECENT', '/var/run/threatshield_dnsbl.recent.json');

const THREATSHIELD_MAP_RING = 20000;          // detailed events kept
const THREATSHIELD_MAP_STORE_PER_RUN = 300;   // detailed events stored per collect (all are counted)
const THREATSHIELD_MAP_WINDOWS = ['15m' => 900, '1h' => 3600, '6h' => 21600, '24h' => 86400, '7d' => 604800];

/* ---------------------------------------------------------------- parsing */

/* One filterlog line (RFC 3164 or RFC 5424 syslog) or null.
 * Layout: rulenum,subrule,anchor,tracker,if,reason,action,dir,ipver,... */
function threatshield_map_parse_filterlog(string $line, int $now = 0): ?array {
	$now = $now ?: time();
	if ($line === '') return null;
	if ($line[0] === '<') {
		if (!preg_match('/^<\d{1,3}>\d*\s(\S+)\s\S+\sfilterlog\s\S+\s\S+\s\S+\s(.*)$/', $line, $m)) return null;
		$t = strtotime($m[1]);
	} else {
		if (!preg_match('/^(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s\S+\sfilterlog\[\d+\]:\s(.*)$/', $line, $m)) return null;
		$t = strtotime($m[1], $now);
		if ($t !== false && $t > $now + 86400) $t = strtotime('-1 year', $t);    // no year in RFC 3164
	}
	$f = explode(',', $m[2]);
	if (count($f) < 12) return null;
	$ev = ['t' => ($t === false) ? $now : (int)$t, 'rulenum' => (int)$f[0], 'tracker' => (string)$f[3], 'if' => (string)$f[4],
	    'action' => (string)$f[6], 'dir' => (string)$f[7], 'ipver' => (int)$f[8]];
	if (!in_array($ev['action'], ['pass', 'block', 'reject'], true) || !in_array($ev['ipver'], [4, 6], true)) return null;
	if ($ev['action'] === 'reject') $ev['action'] = 'block';
	$i = 9;
	if (str_starts_with((string)($f[$i] ?? ''), 'error=')) $i++;
	if ($ev['ipver'] === 4) {
		$protoid = (int)($f[$i + 6] ?? 0);
		$proto = strtolower((string)($f[$i + 7] ?? ''));
		$i += 8;
	} else {
		$proto = strtolower((string)($f[$i + 3] ?? ''));
		$protoid = (int)($f[$i + 4] ?? 0);
		$i += 5;
	}
	$i++;    // length
	$ev['src'] = (string)($f[$i++] ?? '');
	$ev['dst'] = (string)($f[$i++] ?? '');
	if (!filter_var($ev['src'], FILTER_VALIDATE_IP) || !filter_var($ev['dst'], FILTER_VALIDATE_IP)) return null;
	$ev['proto'] = ($proto !== '') ? $proto : (string)$protoid;
	$ev['sport'] = $ev['dport'] = 0;
	if (in_array($protoid, [6, 17, 132], true)) {
		$ev['sport'] = (int)($f[$i] ?? 0);
		$ev['dport'] = (int)($f[$i + 1] ?? 0);
	}
	return $ev;
}

/* Rule names from `pfctl -vvsr`: ['t' => [tracker => label], 'n' => [rule number => label]] */
function threatshield_map_parse_pf_rules(string $out): array {
	$idx = ['t' => [], 'n' => []];
	foreach (explode("\n", $out) as $line) {
		if (!preg_match('/^@(\d+)\s/', $line, $m)) continue;
		$label = preg_match('/\slabel "([^"]*)"/', $line, $l) ? $l[1] : '';
		if (str_starts_with($label, 'descr=')) $label = substr($label, 6);
		if ($label === '' || str_starts_with($label, 'id:')) {
			$label = preg_match('/^@\d+\s+(pass|block)/', $line, $a) ? (($a[1] === 'pass') ? 'Pass rule' : 'Block rule') : '';
		}
		$idx['n'][(int)$m[1]] = $label;
		if (preg_match('/\sridentifier (\d+)/', $line, $r)) $idx['t'][$r[1]] = $label;
	}
	return $idx;
}

/* What blocked or passed the packet: ['kind', 'policy', 'ts' => Threat Shield rule] */
function threatshield_map_classify(string $label, string $action): array {
	if (preg_match('/^ThreatShield GeoIP (\S+) (?:inbound|outbound)$/', $label, $m)) return ['kind' => 'geoip', 'policy' => $m[1], 'ts' => true];
	if (preg_match('/^ThreatShield IP list (\S+) (?:inbound|outbound)$/', $label, $m)) return ['kind' => 'iplist', 'policy' => $m[1], 'ts' => true];
	if (preg_match('/^ThreatShield (\S+) DNSBL (?:listed|unverified)$/', $label, $m)) return ['kind' => 'dnsbl', 'policy' => $m[1], 'ts' => true];
	if (str_starts_with($label, 'ThreatShield anti-bypass ')) return ['kind' => 'bypass', 'policy' => substr($label, 25), 'ts' => true];
	if ($label === 'ThreatShield flood offender') return ['kind' => 'flood', 'policy' => '', 'ts' => true];
	if (preg_match('/^ThreatShield (\S+) (?:pass|allowlisted)$/', $label, $m)) return ['kind' => 'ts_pass', 'policy' => $m[1], 'ts' => true];
	return ['kind' => ($action === 'pass') ? 'fw_pass' : 'fw_block', 'policy' => '', 'ts' => false];
}

/* Which side is outside: ['remote' => ip or null, 'local' => ip, 'flow' => in|out|internal] */
function threatshield_map_orient(string $src, string $dst, string $dir, array $local): array {
	$is_local = function (string $ip) use ($local): bool {
		foreach ($local as $cidr) {
			if (threatshield_cidr_contains($cidr, $ip)) return true;
		}
		return false;
	};
	$src_local = $is_local($src);
	$dst_local = $is_local($dst);
	if ($src_local && $dst_local) return ['remote' => null, 'local' => $src, 'flow' => 'internal'];
	if (!$src_local && $dst_local) return ['remote' => $src, 'local' => $dst, 'flow' => 'in'];
	if ($src_local && !$dst_local) return ['remote' => $dst, 'local' => $src, 'flow' => 'out'];
	return ($dir === 'out') ? ['remote' => $dst, 'local' => $src, 'flow' => 'out'] : ['remote' => $src, 'local' => $dst, 'flow' => 'in'];
}

/* Reads what was appended since $state ['ino', 'off'].
 * Returns [lines, new state, bytes skipped]. The first run starts near the
 * end; a backlog larger than $backlog is skipped (a log flood) and counted;
 * a rotated file (new inode or shorter) is read from the start. */
function threatshield_map_read_new(string $file, array $state, int $max_bytes = 4194304, int $tail = 1048576, int $backlog = 8388608): array {
	clearstatcache(true, $file);
	$st = @stat($file);
	if ($st === false) return [[], $state, 0];
	$ino = (int)$st['ino'];
	$size = (int)$st['size'];
	$skipped = 0;
	$partial = false;
	if (!isset($state['ino'], $state['off'])) {
		$off = max(0, $size - $tail);
		$partial = ($off > 0);
	} elseif ((int)$state['ino'] !== $ino || $size < (int)$state['off']) {
		$off = 0;
	} else {
		$off = (int)$state['off'];
	}
	if ($size - $off > $backlog) {
		$skipped = $size - $tail - $off;
		$off = $size - $tail;
		$partial = true;
	}
	$lines = [];
	if ($size > $off) {
		$fh = @fopen($file, 'rb');
		if ($fh) {
			fseek($fh, $off);
			$chunk = (string)fread($fh, min($max_bytes, $size - $off));
			fclose($fh);
			$last = strrpos($chunk, "\n");
			$chunk = ($last === false) ? '' : substr($chunk, 0, $last + 1);
			$off += strlen($chunk);
			$lines = ($chunk === '') ? [] : explode("\n", rtrim($chunk, "\n"));
			if ($partial && !empty($lines)) array_shift($lines);    // may start mid-line
		}
	}
	return [$lines, ['ino' => $ino, 'off' => $off], $skipped];
}

/* AdGuard Home time stamps carry nanoseconds, which strtotime() rejects. */
function threatshield_map_parse_time(string $s): int {
	$t = strtotime((string)preg_replace('/(\.\d+)(?=Z|[+-]\d{2}:?\d{2}$)/', '', $s));
	return ($t === false) ? 0 : $t;
}

/* DNS events from a query log page (newest first), newer than $after (unix
 * time, exclusive with $after_names deduplicating the same second).
 * Returns [events, newest time, names seen at that second]. */
function threatshield_map_querylog_events(array $entries, int $after, array $after_names, int $allow_sample = 30): array {
	$blocked = ['FilteredBlackList', 'FilteredSafeBrowsing', 'FilteredParental', 'FilteredInvalid', 'FilteredBlockedService'];
	$events = [];
	$newest = $after;
	$names_at_newest = $after_names;
	$allowed = 0;
	$seen = [];
	foreach (array_reverse($entries) as $e) {
		if (!is_array($e)) continue;
		$t = threatshield_map_parse_time((string)($e['time'] ?? ''));
		$name = rtrim((string)($e['question']['name'] ?? ''), '.');
		$client = (string)($e['client'] ?? '');
		$key = $name . '|' . $client;
		if ($t < $after || ($t === $after && in_array($key, $after_names, true)) || $name === '') continue;
		if ($t > $newest) { $newest = $t; $names_at_newest = []; }
		if ($t === $newest) $names_at_newest[] = $key;
		$reason = (string)($e['reason'] ?? '');
		if (in_array($reason, $blocked, true)) {
			$events[] = ['t' => $t, 'a' => 'dns_block', 'k' => ($reason === 'FilteredBlockedService') ? 'service' : (($reason === 'FilteredSafeBrowsing') ? 'safebrowsing' : 'dns'),
			    'dom' => $name, 'client' => $client, 'rule' => (string)($e['rules'][0]['text'] ?? ''), 'list' => (int)($e['rules'][0]['filter_list_id'] ?? -1)];
			continue;
		}
		if ($allowed >= $allow_sample || isset($seen[$name])) continue;
		foreach ((array)($e['answer'] ?? []) as $ans) {
			$ip = (string)($ans['value'] ?? '');
			if (in_array($ans['type'] ?? '', ['A', 'AAAA'], true) && filter_var($ip, FILTER_VALIDATE_IP)) {
				$events[] = ['t' => $t, 'a' => 'dns_allow', 'k' => 'dns', 'dom' => $name, 'client' => $client, 'ip' => $ip];
				$seen[$name] = true;
				$allowed++;
				break;
			}
		}
	}
	return [$events, $newest, array_values(array_unique($names_at_newest))];
}

/* ------------------------------------------------------------------ store */

function threatshield_map_db(): ?SQLite3 {
	if (!class_exists('SQLite3')) return null;
	@mkdir(dirname(THREATSHIELD_MAP_DB), 0750, true);
	try {
		$db = new SQLite3(THREATSHIELD_MAP_DB);
		$db->busyTimeout(3000);
		$db->exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;');
		$db->exec('CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, t INTEGER, a TEXT, k TEXT, flow TEXT,
			ip TEXT, cc TEXT, asn INTEGER, proto TEXT, port INTEGER, iface TEXT, rule TEXT, pol TEXT, local TEXT, dom TEXT, client TEXT)');
		$db->exec('CREATE INDEX IF NOT EXISTS events_t ON events(t)');
		$db->exec('CREATE INDEX IF NOT EXISTS events_ip ON events(ip)');
		$db->exec('CREATE TABLE IF NOT EXISTS ips (ip TEXT PRIMARY KEY, first INTEGER, last INTEGER, nb INTEGER DEFAULT 0, np INTEGER DEFAULT 0,
			cc TEXT, asn INTEGER, rule TEXT, port INTEGER, ptr TEXT, ptr_t INTEGER DEFAULT 0)');
		$db->exec('CREATE TABLE IF NOT EXISTS agg (m INTEGER, a TEXT, k TEXT, cc TEXT, n INTEGER, PRIMARY KEY (m, a, k, cc)) WITHOUT ROWID');
		$db->exec('CREATE TABLE IF NOT EXISTS aggp (h INTEGER, a TEXT, proto TEXT, port INTEGER, n INTEGER, PRIMARY KEY (h, a, proto, port)) WITHOUT ROWID');
		return $db;
	} catch (Throwable $e) {
		return null;
	}
}

function threatshield_map_state(): array {
	$s = json_decode((string)@file_get_contents(THREATSHIELD_MAP_STATE), true);
	return is_array($s) ? $s : [];
}

/* Rule names and the firewall's own networks, refreshed after a filter
 * reload (rules.debug changes). */
function threatshield_map_context(): array {
	$mtime = (int)@filemtime('/tmp/rules.debug');
	$cached = json_decode((string)@file_get_contents(THREATSHIELD_MAP_RULES), true);
	if (is_array($cached) && ($cached['mtime'] ?? -1) === $mtime && time() - (int)($cached['built'] ?? 0) < 3600) return $cached;
	$out = (string)@shell_exec('/sbin/pfctl -vvsr 2>/dev/null');
	$idx = threatshield_map_parse_pf_rules($out);
	$local = threatshield_protected_ranges();
	if (function_exists('threatshield_local_networks')) $local = array_merge($local, threatshield_local_networks());
	foreach (array_keys(threatshield_assigned_interfaces()) as $friendly) {
		$ip4 = function_exists('get_interface_ip') ? (string)get_interface_ip($friendly) : '';
		$ip6 = function_exists('get_interface_ipv6') ? (string)get_interface_ipv6($friendly) : '';
		if (filter_var($ip4, FILTER_VALIDATE_IP)) $local[] = $ip4 . '/32';
		if (filter_var($ip6, FILTER_VALIDATE_IP)) $local[] = $ip6 . '/128';
	}
	$ifnames = [];
	foreach (threatshield_assigned_interfaces() as $friendly => $descr) {
		$real = function_exists('get_real_interface') ? (string)get_real_interface($friendly) : '';
		if ($real !== '') $ifnames[$real] = $descr;
	}
	$ctx = ['mtime' => $mtime, 'built' => time(), 't' => $idx['t'], 'n' => $idx['n'], 'local' => array_values(array_unique($local)), 'ifnames' => $ifnames];
	@file_put_contents(THREATSHIELD_MAP_RULES, json_encode($ctx), LOCK_EX);
	return $ctx;
}

/* Collects new events; returns ['ran' => bool, 'added' => n, 'skipped' => bytes]. */
function threatshield_map_collect(array $cfg, bool $force = false): array {
	$lock = @fopen(THREATSHIELD_MAP_LOCK, 'c');
	if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) return ['ran' => false];
	$state = threatshield_map_state();
	if (!$force && microtime(true) - (float)($state['last'] ?? 0) < 1.5) {
		flock($lock, LOCK_UN);
		fclose($lock);
		return ['ran' => false];
	}
	$db = threatshield_map_db();
	if ($db === null) {
		flock($lock, LOCK_UN);
		fclose($lock);
		return ['ran' => false, 'error' => 'no database'];
	}
	$now = time();
	$ctx = threatshield_map_context();
	$geo = ThreatShieldGeo::open();
	$events = [];
	$counts = [];     // agg rows
	$ports = [];      // aggp rows
	$ipstat = [];

	/* firewall log */
	[$lines, $fstate, $skipped] = threatshield_map_read_new(THREATSHIELD_FILTER_LOG, (array)($state['filterlog'] ?? []));
	$state['filterlog'] = $fstate;
	$state['skipped'] = (int)($state['skipped'] ?? 0) + $skipped;
	$log_pass = (($cfg['map_log_allowed'] ?? 'off') === 'on');
	foreach ($lines as $line) {
		$ev = threatshield_map_parse_filterlog($line, $now);
		if ($ev === null) continue;
		$label = $ctx['t'][$ev['tracker']] ?? ($ctx['n'][$ev['rulenum']] ?? '');
		$c = threatshield_map_classify($label, $ev['action']);
		$o = threatshield_map_orient($ev['src'], $ev['dst'], $ev['dir'], (array)$ctx['local']);
		$m = intdiv($ev['t'], 60) * 60;
		if ($o['flow'] === 'internal') {
			$key = "{$m}|{$ev['action']}|{$c['kind']}|";
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			continue;
		}
		$g = ($geo !== null) ? $geo->lookup((string)$o['remote']) : ['cc' => '', 'asn' => 0, 'org' => ''];
		$key = "{$m}|{$ev['action']}|{$c['kind']}|{$g['cc']}";
		$counts[$key] = ($counts[$key] ?? 0) + 1;
		$port = $ev['dport'];    // inbound: the targeted service; outbound: the remote service
		$pk = intdiv($ev['t'], 3600) * 3600 . "|{$ev['action']}|{$ev['proto']}|{$port}";
		$ports[$pk] = ($ports[$pk] ?? 0) + 1;
		$ip = (string)$o['remote'];
		$ipstat[$ip] = ($ipstat[$ip] ?? ['first' => $ev['t'], 'last' => 0, 'nb' => 0, 'np' => 0, 'cc' => $g['cc'], 'asn' => $g['asn'], 'rule' => '', 'port' => 0]);
		$ipstat[$ip]['last'] = max($ipstat[$ip]['last'], $ev['t']);
		$ipstat[$ip][($ev['action'] === 'pass') ? 'np' : 'nb']++;
		$ipstat[$ip]['rule'] = $label;
		$ipstat[$ip]['port'] = $port;
		$events[] = ['t' => $ev['t'], 'a' => $ev['action'], 'k' => $c['kind'], 'flow' => $o['flow'], 'ip' => $ip, 'cc' => $g['cc'], 'asn' => $g['asn'],
		    'proto' => $ev['proto'], 'port' => $port, 'iface' => (string)($ctx['ifnames'][$ev['if']] ?? $ev['if']), 'rule' => $label,
		    'pol' => $c['policy'], 'local' => (string)$o['local'], 'dom' => '', 'client' => ''];
	}

	/* reputation verdicts (DNSBL daemon ring) */
	$ring = json_decode((string)@file_get_contents(THREATSHIELD_DNSBL_RECENT), true);
	if (is_array($ring)) {
		$last_n = (int)($state['dnsbl_n'] ?? 0);
		if ((int)($ring['boot'] ?? 0) !== (int)($state['dnsbl_boot'] ?? -1)) $last_n = 0;    // daemon restarted
		foreach ((array)($ring['v'] ?? []) as $v) {
			if (!is_array($v) || (int)($v['n'] ?? 0) <= $last_n) continue;
			$ip = (string)($v['ip'] ?? '');
			if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
			$g = ($geo !== null) ? $geo->lookup($ip) : ['cc' => '', 'asn' => 0, 'org' => ''];
			$a = (($v['v'] ?? '') === 'listed') ? 'listed' : 'clean';
			$m = intdiv((int)$v['t'], 60) * 60;
			$key = "{$m}|{$a}|reputation|{$g['cc']}";
			$counts[$key] = ($counts[$key] ?? 0) + 1;
			$events[] = ['t' => (int)$v['t'], 'a' => $a, 'k' => 'reputation', 'flow' => 'in', 'ip' => $ip, 'cc' => $g['cc'], 'asn' => $g['asn'],
			    'proto' => '', 'port' => 0, 'iface' => '', 'rule' => implode(', ', (array)($v['z'] ?? [])), 'pol' => '', 'local' => '', 'dom' => '', 'client' => ''];
		}
		$state['dnsbl_n'] = (int)($ring['n'] ?? $last_n);
		$state['dnsbl_boot'] = (int)($ring['boot'] ?? 0);
	}

	/* DNS: blocked queries and where allowed answers point (every 3 s at most) */
	if (($cfg['map_dns'] ?? 'on') === 'on' && ($cfg['enable'] ?? 'off') === 'on' && $now - (int)($state['dns_polled'] ?? 0) >= 3
	    && function_exists('threatshield_api_request')) {
		$state['dns_polled'] = $now;
		$log = threatshield_api_request('querylog?limit=300', 'GET', null, 2);
		if (is_array($log) && isset($log['data'])) {
			$after = (int)($state['dns_t'] ?? ($now - 60));
			[$dns, $newest, $names] = threatshield_map_querylog_events((array)$log['data'], $after, (array)($state['dns_names'] ?? []));
			$state['dns_t'] = $newest;
			$state['dns_names'] = array_slice($names, -200);
			foreach ($dns as $d) {
				$m = intdiv($d['t'], 60) * 60;
				$cc = '';
				$asn = 0;
				if ($d['a'] === 'dns_allow') {
					if ($geo !== null) {
						$g = $geo->lookup($d['ip']);
						$cc = $g['cc'];
						$asn = $g['asn'];
					}
				}
				$key = "{$m}|{$d['a']}|{$d['k']}|{$cc}";
				$counts[$key] = ($counts[$key] ?? 0) + 1;
				$events[] = ['t' => $d['t'], 'a' => $d['a'], 'k' => $d['k'], 'flow' => 'out', 'ip' => (string)($d['ip'] ?? ''), 'cc' => $cc, 'asn' => $asn,
				    'proto' => '', 'port' => 0, 'iface' => '', 'rule' => (string)($d['rule'] ?? ''), 'pol' => '', 'local' => $d['client'],
				    'dom' => $d['dom'], 'client' => $d['client']];
			}
		}
	}

	/* write */
	$db->exec('BEGIN');
	$st = $db->prepare('INSERT INTO agg (m, a, k, cc, n) VALUES (:m, :a, :k, :cc, :n) ON CONFLICT(m, a, k, cc) DO UPDATE SET n = n + excluded.n');
	foreach ($counts as $key => $n) {
		[$m, $a, $k, $cc] = explode('|', $key, 4);
		$st->bindValue(':m', (int)$m, SQLITE3_INTEGER);
		$st->bindValue(':a', $a);
		$st->bindValue(':k', $k);
		$st->bindValue(':cc', $cc);
		$st->bindValue(':n', $n, SQLITE3_INTEGER);
		$st->execute();
		$st->reset();
	}
	$st = $db->prepare('INSERT INTO aggp (h, a, proto, port, n) VALUES (:h, :a, :p, :port, :n) ON CONFLICT(h, a, proto, port) DO UPDATE SET n = n + excluded.n');
	foreach ($ports as $key => $n) {
		[$h, $a, $p, $port] = explode('|', $key, 4);
		$st->bindValue(':h', (int)$h, SQLITE3_INTEGER);
		$st->bindValue(':a', $a);
		$st->bindValue(':p', $p);
		$st->bindValue(':port', (int)$port, SQLITE3_INTEGER);
		$st->bindValue(':n', $n, SQLITE3_INTEGER);
		$st->execute();
		$st->reset();
	}
	$st = $db->prepare('INSERT INTO ips (ip, first, last, nb, np, cc, asn, rule, port) VALUES (:ip, :first, :last, :nb, :np, :cc, :asn, :rule, :port)
		ON CONFLICT(ip) DO UPDATE SET last = MAX(last, excluded.last), nb = nb + excluded.nb, np = np + excluded.np, cc = excluded.cc,
		asn = excluded.asn, rule = excluded.rule, port = excluded.port');
	foreach ($ipstat as $ip => $s) {
		$st->bindValue(':ip', $ip);
		foreach (['first', 'last', 'nb', 'np', 'asn', 'port'] as $k) $st->bindValue(':' . $k, (int)$s[$k], SQLITE3_INTEGER);
		$st->bindValue(':cc', $s['cc']);
		$st->bindValue(':rule', $s['rule']);
		$st->execute();
		$st->reset();
	}
	$stored = array_slice($events, -THREATSHIELD_MAP_STORE_PER_RUN);
	usort($stored, fn($x, $y) => $x['t'] <=> $y['t']);
	$st = $db->prepare('INSERT INTO events (t, a, k, flow, ip, cc, asn, proto, port, iface, rule, pol, local, dom, client)
		VALUES (:t, :a, :k, :flow, :ip, :cc, :asn, :proto, :port, :iface, :rule, :pol, :local, :dom, :client)');
	foreach ($stored as $e) {
		foreach ($e as $k => $v) $st->bindValue(':' . $k, $v, is_int($v) ? SQLITE3_INTEGER : SQLITE3_TEXT);
		$st->execute();
		$st->reset();
	}
	$db->exec('DELETE FROM events WHERE seq <= (SELECT MAX(seq) FROM events) - ' . THREATSHIELD_MAP_RING);
	$db->exec('COMMIT');
	$db->close();

	$state['last'] = microtime(true);
	$state['dropped'] = (int)($state['dropped'] ?? 0) + max(0, count($events) - count($stored));
	@file_put_contents(THREATSHIELD_MAP_STATE, json_encode($state), LOCK_EX);
	flock($lock, LOCK_UN);
	fclose($lock);
	return ['ran' => true, 'added' => count($events), 'skipped' => $skipped];
}

/* Drops aggregates and IP records older than the retention (cron). */
function threatshield_map_prune(array $cfg): void {
	$db = threatshield_map_db();
	if ($db === null) return;
	$keep = time() - max(1, min(30, (int)($cfg['map_retention_days'] ?? 7))) * 86400;
	$db->exec("DELETE FROM agg WHERE m < {$keep}");
	$db->exec("DELETE FROM aggp WHERE h < {$keep}");
	$db->exec("DELETE FROM ips WHERE last < {$keep}");
	$db->exec("DELETE FROM events WHERE t < {$keep}");
	$db->close();
}

/* ------------------------------------------------------------------ reads */

function threatshield_map_window(string $w): int {
	return THREATSHIELD_MAP_WINDOWS[$w] ?? 3600;
}

/* SQL condition for the filters: ['actions' => [...], 'ts' => bool, 'cc' => 'DK', 'q' => text] */
function threatshield_map_where(SQLite3 $db, array $f, string $table = 'events'): string {
	$w = [];
	$acts = array_values(array_intersect((array)($f['actions'] ?? []), ['block', 'pass', 'dns_block', 'dns_allow', 'listed', 'clean']));
	if (!empty($acts)) $w[] = 'a IN (' . implode(',', array_map(fn($a) => "'" . $a . "'", $acts)) . ')';
	if (!empty($f['ts']) && $table !== 'aggp') $w[] = "k NOT IN ('fw_block', 'fw_pass')";
	if (!empty($f['cc']) && preg_match('/^[A-Z]{2}$/', (string)$f['cc']) && $table !== 'aggp') $w[] = "cc = '" . $f['cc'] . "'";
	if (!empty($f['q']) && $table === 'events') {
		$q = "'%" . $db->escapeString(str_replace(['%', '_'], ['\\%', '\\_'], (string)$f['q'])) . "%'";
		$w[] = "(ip LIKE {$q} ESCAPE '\\' OR dom LIKE {$q} ESCAPE '\\' OR rule LIKE {$q} ESCAPE '\\' OR client LIKE {$q} ESCAPE '\\')";
	}
	return empty($w) ? '' : ' AND ' . implode(' AND ', $w);
}

/* Events after a cursor, newest last, with positions. */
function threatshield_map_events(SQLite3 $db, int $after, int $since, array $f, int $limit, bool $mask): array {
	$where = threatshield_map_where($db, $f);
	$sql = "SELECT * FROM events WHERE seq > {$after} AND t >= {$since}{$where} ORDER BY seq DESC LIMIT " . max(1, min(500, $limit));
	$rows = [];
	$res = $db->query($sql);
	while ($res && ($r = $res->fetchArray(SQLITE3_ASSOC))) $rows[] = threatshield_map_event_json($r, $mask);
	return array_reverse($rows);
}

function threatshield_map_mask(string $ip): string {
	if (strpos($ip, ':') !== false) {
		$parts = explode(':', $ip);
		return implode(':', array_slice($parts, 0, 3)) . '::x';
	}
	$p = explode('.', $ip);
	return (count($p) === 4) ? "{$p[0]}.{$p[1]}.{$p[2]}.x" : $ip;
}

function threatshield_map_event_json(array $r, bool $mask): array {
	static $geo = false;
	if ($geo === false) $geo = ThreatShieldGeo::open();
	$ip = (string)$r['ip'];
	$pos = ($ip !== '' && $r['cc'] !== '') ? threatshield_geo_position($ip, (string)$r['cc']) : null;
	return [
		'seq' => (int)$r['seq'], 't' => (int)$r['t'], 'a' => (string)$r['a'], 'k' => (string)$r['k'], 'flow' => (string)$r['flow'],
		'ip' => ($mask && $ip !== '') ? threatshield_map_mask($ip) : $ip, 'id' => ($ip !== '') ? substr(md5($ip), 0, 10) : '',
		'cc' => (string)$r['cc'], 'asn' => (int)$r['asn'], 'org' => ($geo && (int)$r['asn'] > 0) ? $geo->asn_name((int)$r['asn']) : '',
		'p' => $pos, 'proto' => (string)$r['proto'], 'port' => (int)$r['port'], 'if' => (string)$r['iface'],
		'rule' => (string)$r['rule'], 'pol' => (string)$r['pol'],
		'dom' => (string)$r['dom'], 'client' => $mask ? '' : (string)$r['client'],
	];
}

/* Map dots: one per source network in the window. */
function threatshield_map_dots(SQLite3 $db, int $since, array $f, bool $mask, int $limit = 1500): array {
	$where = threatshield_map_where($db, $f);
	$res = $db->query("SELECT ip, cc, a, COUNT(*) AS n, MAX(t) AS last FROM events WHERE t >= {$since} AND ip != '' AND cc != ''{$where}
		GROUP BY ip ORDER BY last DESC LIMIT {$limit}");
	$out = [];
	while ($res && ($r = $res->fetchArray(SQLITE3_ASSOC))) {
		$pos = threatshield_geo_position((string)$r['ip'], (string)$r['cc']);
		if ($pos === null) continue;
		$out[] = ['ip' => $mask ? threatshield_map_mask((string)$r['ip']) : (string)$r['ip'], 'id' => substr(md5((string)$r['ip']), 0, 10),
		    'cc' => (string)$r['cc'], 'a' => (string)$r['a'], 'n' => (int)$r['n'], 'last' => (int)$r['last'], 'p' => $pos];
	}
	return $out;
}

/* Counters, timeline, mix and top lists for a window. */
function threatshield_map_summary(SQLite3 $db, int $since, array $f, bool $mask, int $now = 0): array {
	$now = $now ?: time();
	$where_agg = threatshield_map_where($db, ['ts' => $f['ts'] ?? false, 'cc' => $f['cc'] ?? '']);
	$counters = ['block' => 0, 'pass' => 0, 'dns_block' => 0, 'dns_allow' => 0, 'listed' => 0, 'clean' => 0];
	$mix = [];
	$res = $db->query("SELECT a, k, SUM(n) AS n FROM agg WHERE m >= {$since}{$where_agg} GROUP BY a, k");
	while ($res && ($r = $res->fetchArray(SQLITE3_ASSOC))) {
		$counters[$r['a']] = ($counters[$r['a']] ?? 0) + (int)$r['n'];
		if (in_array($r['a'], ['block', 'listed', 'dns_block'], true)) $mix[$r['k']] = ($mix[$r['k']] ?? 0) + (int)$r['n'];
	}
	arsort($mix);

	/* timeline: up to 60 buckets of at least one minute */
	$span = max(60, $now - $since);
	$bucket = max(60, (int)(ceil($span / 60 / 60) * 60));
	$start = intdiv($since, $bucket) * $bucket;
	$series = [];
	for ($b = $start; $b <= $now; $b += $bucket) $series[$b] = ['t' => $b, 'block' => 0, 'pass' => 0, 'dns' => 0];
	$res = $db->query("SELECT ((m - {$start}) / {$bucket}) * {$bucket} + {$start} AS b, a, SUM(n) AS n FROM agg WHERE m >= {$since}{$where_agg} GROUP BY b, a");
	while ($res && ($r = $res->fetchArray(SQLITE3_ASSOC))) {
		$b = (int)$r['b'];
		if (!isset($series[$b])) continue;
		$col = in_array($r['a'], ['block', 'listed'], true) ? 'block' : (($r['a'] === 'dns_block') ? 'dns' : (($r['a'] === 'pass') ? 'pass' : null));
		if ($col !== null) $series[$b][$col] += (int)$r['n'];
	}

	$top = function (string $sql) use ($db): array {
		$rows = [];
		$res = $db->query($sql);
		while ($res && ($r = $res->fetchArray(SQLITE3_NUM))) $rows[] = $r;
		return $rows;
	};
	$blocks = threatshield_map_where($db, ['actions' => ['block', 'listed'], 'ts' => $f['ts'] ?? false, 'cc' => $f['cc'] ?? '']);
	$countries = $top("SELECT cc, SUM(n) FROM agg WHERE m >= {$since} AND cc != ''{$blocks} GROUP BY cc ORDER BY 2 DESC LIMIT 10");
	$ips = $top("SELECT ip, COUNT(*), MAX(cc), MAX(asn) FROM events WHERE t >= {$since} AND ip != ''{$blocks} GROUP BY ip ORDER BY 2 DESC LIMIT 10");
	$asns = $top("SELECT asn, COUNT(*) FROM events WHERE t >= {$since} AND asn > 0{$blocks} GROUP BY asn ORDER BY 2 DESC LIMIT 10");
	$rules = $top("SELECT rule, COUNT(*) FROM events WHERE t >= {$since} AND rule != ''{$blocks} GROUP BY rule ORDER BY 2 DESC LIMIT 10");
	$hour = intdiv($since, 3600) * 3600;
	$ports = $top("SELECT proto, port, SUM(n) FROM aggp WHERE h >= {$hour} AND a = 'block' AND port > 0 GROUP BY proto, port ORDER BY 3 DESC LIMIT 12");
	$domains = $top("SELECT dom, COUNT(*) FROM events WHERE t >= {$since} AND a = 'dns_block' GROUP BY dom ORDER BY 2 DESC LIMIT 10");
	$sources = (int)($db->querySingle("SELECT COUNT(DISTINCT ip) FROM events WHERE t >= {$since} AND ip != ''") ?? 0);

	$geo = ThreatShieldGeo::open();
	$name = fn($cc) => (string)(threatshield_geo_country((string)$cc)[0] ?? $cc);
	return [
		'counters' => $counters + ['sources' => $sources],
		'mix' => $mix,
		'rate' => array_values($series),
		'bucket' => $bucket,
		'top' => [
			'countries' => array_map(fn($r) => ['cc' => (string)$r[0], 'name' => $name($r[0]), 'n' => (int)$r[1]], $countries),
			'ips' => array_map(fn($r) => ['ip' => $mask ? threatshield_map_mask((string)$r[0]) : (string)$r[0], 'id' => substr(md5((string)$r[0]), 0, 10),
			    'n' => (int)$r[1], 'cc' => (string)$r[2], 'asn' => (int)$r[3], 'org' => $geo ? $geo->asn_name((int)$r[3]) : ''], $ips),
			'asns' => array_map(fn($r) => ['asn' => (int)$r[0], 'org' => $geo ? $geo->asn_name((int)$r[0]) : '', 'n' => (int)$r[1]], $asns),
			'rules' => array_map(fn($r) => ['rule' => (string)$r[0], 'n' => (int)$r[1]], $rules),
			'ports' => array_map(fn($r) => ['proto' => (string)$r[0], 'port' => (int)$r[1], 'service' => threatshield_map_service((int)$r[1]), 'n' => (int)$r[2]], $ports),
			'domains' => array_map(fn($r) => ['dom' => (string)$r[0], 'n' => (int)$r[1]], $domains),
		],
	];
}

/* A familiar name for well-known ports. */
function threatshield_map_service(int $port): string {
	static $names = [21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP', 53 => 'DNS', 80 => 'HTTP', 110 => 'POP3', 123 => 'NTP', 135 => 'RPC',
	    137 => 'NetBIOS', 139 => 'NetBIOS', 143 => 'IMAP', 161 => 'SNMP', 389 => 'LDAP', 443 => 'HTTPS', 445 => 'SMB', 465 => 'SMTPS', 500 => 'IKE',
	    587 => 'Submission', 853 => 'DoT', 993 => 'IMAPS', 995 => 'POP3S', 1194 => 'OpenVPN', 1433 => 'MSSQL', 1723 => 'PPTP', 1883 => 'MQTT',
	    2222 => 'SSH alt', 3306 => 'MySQL', 3389 => 'RDP', 4500 => 'IPsec NAT-T', 5060 => 'SIP', 5432 => 'PostgreSQL', 5900 => 'VNC',
	    6379 => 'Redis', 8080 => 'HTTP alt', 8443 => 'HTTPS alt', 9200 => 'Elasticsearch', 11211 => 'Memcached', 27017 => 'MongoDB', 51820 => 'WireGuard'];
	return $names[$port] ?? '';
}

/* Where the firewall is on the map: ['lat', 'lon', 'cc', 'source'] or null. */
function threatshield_map_home(array $cfg): ?array {
	if (($cfg['map_location'] ?? 'auto') === 'manual' && is_numeric($cfg['map_lat'] ?? null) && is_numeric($cfg['map_lon'] ?? null)) {
		return ['lat' => (float)$cfg['map_lat'], 'lon' => (float)$cfg['map_lon'], 'cc' => '', 'source' => 'manual'];
	}
	$tz = function_exists('config_get_path') ? (string)config_get_path('system/timezone', '') : '';
	if ($tz !== '' && !str_starts_with($tz, 'Etc/') && $tz !== 'UTC') {
		/* zone.tab still lists zones that zone1970.tab folds into a neighbour */
		foreach (['/usr/share/zoneinfo/zone.tab', '/usr/share/zoneinfo/zone1970.tab'] as $file) {
			$tab = (string)@file_get_contents($file);
			$z = ($tab !== '') ? threatshield_geo_zone_location($tab, $tz) : null;
			if ($z !== null) return ['lat' => $z[0], 'lon' => $z[1], 'cc' => $z[2], 'source' => 'timezone'];
		}
	}
	/* the country of a public WAN address */
	$geo = ThreatShieldGeo::open();
	if ($geo !== null && function_exists('threatshield_wan_interfaces')) {
		foreach (array_keys(threatshield_wan_interfaces()) as $wan) {
			$ip = function_exists('get_interface_ip') ? (string)get_interface_ip($wan) : '';
			if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) continue;
			$cc = $geo->lookup($ip)['cc'];
			$c = ($cc !== '') ? threatshield_geo_country($cc) : null;
			if ($c !== null) return ['lat' => $c[1], 'lon' => $c[2], 'cc' => $cc, 'source' => 'wan'];
		}
	}
	return null;
}

/* Everything known about one address (the IP card). */
function threatshield_map_ip_info(string $ip, array $cfg): array {
	$info = ['ip' => $ip, 'geo' => ['cc' => '', 'asn' => 0, 'org' => ''], 'record' => null, 'events' => [], 'ports' => [], 'verdict' => null,
	    'tables' => [], 'allowlisted' => false, 'states' => 0, 'country' => ''];
	$geo = ThreatShieldGeo::open();
	if ($geo !== null) $info['geo'] = $geo->lookup($ip);
	$info['country'] = (string)(threatshield_geo_country($info['geo']['cc'])[0] ?? '');
	$db = threatshield_map_db();
	if ($db !== null) {
		$st = $db->prepare('SELECT * FROM ips WHERE ip = :ip');
		$st->bindValue(':ip', $ip);
		$r = $st->execute()->fetchArray(SQLITE3_ASSOC);
		$info['record'] = $r ?: null;
		$st = $db->prepare('SELECT * FROM events WHERE ip = :ip ORDER BY seq DESC LIMIT 12');
		$st->bindValue(':ip', $ip);
		$res = $st->execute();
		while ($res && ($e = $res->fetchArray(SQLITE3_ASSOC))) $info['events'][] = $e;
		$st = $db->prepare("SELECT proto, port, COUNT(*) AS n FROM events WHERE ip = :ip AND port > 0 GROUP BY proto, port ORDER BY n DESC LIMIT 6");
		$st->bindValue(':ip', $ip);
		$res = $st->execute();
		while ($res && ($p = $res->fetchArray(SQLITE3_ASSOC))) $info['ports'][] = $p;
		$db->close();
	}
	if (function_exists('threatshield_dnsbl_db') && ($d = threatshield_dnsbl_db()) !== null) {
		$st = @$d->prepare('SELECT verdict, zones, checked, expires FROM verdicts WHERE ip = :ip');
		if ($st) {
			$st->bindValue(':ip', $ip);
			$r = $st->execute()->fetchArray(SQLITE3_ASSOC);
			$info['verdict'] = $r ?: null;
		}
		$d->close();
	}
	if (file_exists('/sbin/pfctl')) {
		exec('/sbin/pfctl -sT 2>/dev/null', $tables);
		foreach ($tables as $t) {
			$t = trim($t);
			if (!preg_match('/^(ts_ipf_\w+|freesense_geoip_\w+|threatshield_(?:dnsbl_bad|flood|doh)|virusprot)$/', $t)) continue;
			exec('/sbin/pfctl -t ' . escapeshellarg($t) . ' -T test ' . escapeshellarg($ip) . ' 2>&1', $o, $rc);
			if ($rc === 0) $info['tables'][] = $t;
			$o = [];
		}
		$states = (string)@shell_exec('/sbin/pfctl -ss 2>/dev/null | grep -cF ' . escapeshellarg(' ' . $ip . ':'));
		$info['states'] = (int)trim($states);
	}
	if (function_exists('threatshield_ip_allow_entries')) {
		foreach (threatshield_ip_allow_entries($cfg) as $cidr) {
			if (threatshield_cidr_contains($cidr, $ip)) { $info['allowlisted'] = $cidr; break; }
		}
	}
	return $info;
}

/* Reverse DNS on request only (it tells the address owner's DNS server that
 * someone looked), cached for a day in the ips table. */
function threatshield_map_ptr(string $ip): ?string {
	$db = threatshield_map_db();
	if ($db !== null) {
		$st = $db->prepare('SELECT ptr, ptr_t FROM ips WHERE ip = :ip');
		$st->bindValue(':ip', $ip);
		$r = $st->execute()->fetchArray(SQLITE3_ASSOC);
		if ($r && time() - (int)$r['ptr_t'] < 86400) {
			$db->close();
			return ($r['ptr'] === '') ? null : (string)$r['ptr'];
		}
	}
	$name = @gethostbyaddr($ip);
	$ptr = ($name !== false && $name !== $ip) ? substr($name, 0, 253) : '';
	if ($db !== null) {
		$st = $db->prepare('UPDATE ips SET ptr = :ptr, ptr_t = :t WHERE ip = :ip');
		$st->bindValue(':ptr', $ptr);
		$st->bindValue(':t', time(), SQLITE3_INTEGER);
		$st->bindValue(':ip', $ip);
		$st->execute();
		$db->close();
	}
	return ($ptr === '') ? null : $ptr;
}
