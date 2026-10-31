<?php
/*
 * threatshield_lib.inc
 * FreeSense Threat Shield - pure helpers (no system includes, unit tested)
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

/* ------------------------------------------------------------------ text */

function threatshield_lines(string $text): array {
	return preg_split('/\r\n|\r|\n/', $text);
}

function threatshield_text_list(string $text): array {
	$out = [];
	foreach (preg_split('/[\s,]+/', $text) as $item) {
		$item = trim($item);
		if ($item !== '') $out[] = $item;
	}
	return array_values(array_unique($out));
}

/* ------------------------------------------------------------- addresses */

/* Parse "ip" or "ip/len" into [family, binary network, prefix length], with
 * host bits cleared.  Returns null for anything else. */
function threatshield_cidr_parse(string $value): ?array {
	$value = trim($value);
	if ($value === '') return null;
	$len = null;
	if (strpos($value, '/') !== false) {
		[$value, $len] = explode('/', $value, 2);
		if (!preg_match('/^\d{1,3}$/', $len)) return null;
		$len = (int)$len;
	}
	$bin = @inet_pton($value);
	if ($bin === false) return null;
	$family = (strlen($bin) === 4) ? 4 : 6;
	$max = ($family === 4) ? 32 : 128;
	if ($len === null) $len = $max;
	if ($len > $max) return null;
	return [$family, threatshield_mask_bin($bin, $len), $len];
}

function threatshield_mask_bin(string $bin, int $len): string {
	$out = '';
	$bytes = strlen($bin);
	for ($i = 0; $i < $bytes; $i++) {
		$bits = max(0, min(8, $len - $i * 8));
		$mask = ($bits === 0) ? 0 : ((0xFF << (8 - $bits)) & 0xFF);
		$out .= chr(ord($bin[$i]) & $mask);
	}
	return $out;
}

/* Canonical "network/len" text, or null. */
function threatshield_cidr_normalize(string $value): ?string {
	$p = threatshield_cidr_parse($value);
	if ($p === null) return null;
	return inet_ntop($p[1]) . '/' . $p[2];
}

/* True when $inner lies completely inside $outer. */
function threatshield_cidr_contains(string $outer, string $inner): bool {
	$o = threatshield_cidr_parse($outer);
	$i = threatshield_cidr_parse($inner);
	if ($o === null || $i === null || $o[0] !== $i[0] || $o[2] > $i[2]) return false;
	return threatshield_mask_bin($i[1], $o[2]) === $o[1];
}

function threatshield_cidr_overlaps(string $a, string $b): bool {
	return threatshield_cidr_contains($a, $b) || threatshield_cidr_contains($b, $a);
}

/* Address space a block table must never contain: it would cut off the LAN,
 * loopback, link-local neighbour discovery or multicast. */
function threatshield_protected_ranges(): array {
	return [
		'0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
		'172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
		'::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8',
	];
}

/* First token of each line of an IP list (Spamhaus DROP, FireHOL netset,
 * plain lists, ipdeny zones); comments after # or ; are ignored. */
function threatshield_parse_ip_list(string $text, int $family = 0): array {
	$out = [];
	foreach (threatshield_lines($text) as $line) {
		$line = trim(preg_replace('/[#;].*$/', '', $line));
		if ($line === '') continue;
		$token = preg_split('/\s+/', $line)[0];
		$p = threatshield_cidr_parse($token);
		if ($p === null || ($family !== 0 && $p[0] !== $family)) continue;
		$out[inet_ntop($p[1]) . '/' . $p[2]] = true;
	}
	return array_keys($out);
}

/* Lines for a pf table file.
 *  - entries overlapping a protected range are dropped
 *  - entries wholly inside an exclusion are dropped
 *  - exclusions inside a remaining entry are added as "!cidr" (pf matches the
 *    longest prefix, so the negated entry wins)
 *  - $always entries (allow-only tables) are added unconditionally */
function threatshield_build_table_lines(array $entries, array $exclusions = [], array $protected = [], array $always = []): array {
	$excl = [];
	foreach ($exclusions as $e) {
		$n = threatshield_cidr_normalize((string)$e);
		if ($n !== null) $excl[$n] = true;
	}
	$excl = array_keys($excl);
	$prot = array_values(array_filter(array_map('threatshield_cidr_normalize', array_map('strval', $protected))));
	$keep = [];
	foreach ($entries as $entry) {
		$n = threatshield_cidr_normalize((string)$entry);
		if ($n === null || isset($keep[$n])) continue;
		foreach ($prot as $p) {
			if (threatshield_cidr_overlaps($p, $n)) continue 2;
		}
		foreach ($excl as $x) {
			if (threatshield_cidr_contains($x, $n)) continue 2;
		}
		$keep[$n] = true;
	}
	foreach ($always as $entry) {
		$n = threatshield_cidr_normalize((string)$entry);
		if ($n !== null) $keep[$n] = true;
	}
	$lines = array_keys($keep);
	foreach ($excl as $x) {
		foreach ($lines as $n) {
			if ($n !== $x && threatshield_cidr_contains($n, $x)) {
				$lines[] = '!' . $x;
				break;
			}
		}
	}
	return $lines;
}

/* ---------------------------------------------------------------- domains */

/* Accepts "example.com", "*.example.com", "||example.com^", URLs and IDNs;
 * returns the lower-case ASCII host name or null. */
function threatshield_normalize_domain(string $value): ?string {
	$value = strtolower(trim($value));
	if ($value === '') return null;
	if (preg_match('#^[a-z][a-z0-9+.-]*://#', $value)) {
		$host = parse_url($value, PHP_URL_HOST);
		if (!is_string($host)) return null;
		$value = $host;
	}
	$value = preg_replace('/^@@/', '', $value);
	$value = preg_replace('/^\|\|?/', '', $value);
	$value = preg_replace('/\^.*$/', '', $value);
	$value = preg_replace('/^\*\./', '', $value);
	$value = rtrim($value, '.');
	if ($value === '') return null;
	if (preg_match('/[^\x20-\x7e]/', $value) && function_exists('idn_to_ascii')) {
		$ascii = idn_to_ascii($value, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
		if (!is_string($ascii)) return null;
		$value = $ascii;
	}
	if (strlen($value) > 253 || !preg_match('/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$/', $value)) {
		return null;
	}
	return $value;
}

/* Index of the allowlist entry that already allows $domain, or null. */
function threatshield_allowlist_find(array $list, string $domain): ?int {
	foreach ($list as $i => $entry) {
		if (!is_array($entry)) continue;
		$d = (string)($entry['domain'] ?? '');
		if ($d === $domain) return $i;
		if (($entry['subdomains'] ?? 'on') === 'on' && $d !== '' && str_ends_with($domain, '.' . $d)) return $i;
	}
	return null;
}

/* AdGuard rules for the enabled entries.  $important beats every block rule,
 * including $important ones in feeds. */
function threatshield_allowlist_rules(array $list): array {
	$rules = [];
	foreach ($list as $entry) {
		if (!is_array($entry) || ($entry['enabled'] ?? 'on') !== 'on') continue;
		$d = threatshield_normalize_domain((string)($entry['domain'] ?? ''));
		if ($d === null) continue;
		$rules[] = ((($entry['subdomains'] ?? 'on') === 'on') ? '@@||' : '@@|') . $d . '^$important';
	}
	return array_values(array_unique($rules));
}

/* Moves simple allow rules out of free-text custom rules.  Returns
 * [allowlist entries, remaining custom rules text]. */
function threatshield_split_custom_allow_rules(string $text, int $now): array {
	$entries = [];
	$keep = [];
	$comment = null;
	$seen = [];
	foreach (threatshield_lines($text) as $line) {
		$trim = trim($line);
		if ($trim !== '' && ($trim[0] === '!' || $trim[0] === '#')) {
			if ($comment !== null) $keep[] = $comment;
			$comment = $trim;
			continue;
		}
		if (preg_match('/^@@(\|\|?)([a-z0-9._-]+)\^(\$important)?$/i', $trim, $m)) {
			$domain = threatshield_normalize_domain($m[2]);
			if ($domain !== null) {
				$sub = ($m[1] === '||') ? 'on' : 'off';
				if (!isset($seen[$domain . '|' . $sub])) {
					$seen[$domain . '|' . $sub] = true;
					$entries[] = [
						'domain' => $domain, 'subdomains' => $sub,
						'comment' => ($comment !== null) ? trim(ltrim($comment, '!#')) : '',
						'enabled' => 'on', 'added' => (string)$now, 'source' => 'migrated',
					];
				}
				$comment = null;
				continue;
			}
		}
		if ($comment !== null) {
			$keep[] = $comment;
			$comment = null;
		}
		$keep[] = $line;
	}
	if ($comment !== null) $keep[] = $comment;
	return [$entries, trim(implode("\n", $keep))];
}

/* -------------------------------------------------------------- schedules */

function threatshield_schedule_days(): array {
	return ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
}

function threatshield_valid_hhmm(string $value, bool $allow24 = false): bool {
	if ($allow24 && $value === '24:00') return true;
	return (bool)preg_match('/^([01]\d|2[0-3]):[0-5]\d$/', $value);
}

/* "08:30" -> "8h30m" (a Go duration from midnight, as AdGuard Home stores). */
function threatshield_hhmm_duration(string $value): string {
	[$h, $m] = array_map('intval', explode(':', $value));
	$out = ($h > 0 ? $h . 'h' : '') . ($m > 0 ? $m . 'm' : '');
	return ($out === '') ? '0s' : $out;
}

/* YAML for a blocked_services.schedule mapping; $indent is the indent of the
 * "schedule:" key's children. */
function threatshield_schedule_yaml(bool $enabled, string $tz, array $days, string $indent): string {
	$tz = ($tz === '' || !preg_match('#^[A-Za-z0-9_+/-]+$#', $tz)) ? 'Local' : $tz;
	$yaml = "{$indent}time_zone: " . json_encode($tz, JSON_UNESCAPED_SLASHES);
	if (!$enabled) return $yaml;
	foreach ($days as $day) {
		if (!is_array($day)) continue;
		$d = (string)($day['day'] ?? '');
		$start = (string)($day['start'] ?? '');
		$end = (string)($day['end'] ?? '');
		if (!in_array($d, threatshield_schedule_days(), true) || !threatshield_valid_hhmm($start) ||
		    !threatshield_valid_hhmm($end, true) || strcmp($end, $start) <= 0) {
			continue;
		}
		$yaml .= "\n{$indent}{$d}:\n{$indent}  start: " . threatshield_hhmm_duration($start) .
		    "\n{$indent}  end: " . threatshield_hhmm_duration($end);
	}
	return $yaml;
}

/* ------------------------------------------------------------------ DNSBL */

/* Query name for an address in a DNSBL zone ({key} is replaced for DQS). */
function threatshield_dnsbl_qname(string $ip, string $zone, string $key = ''): ?string {
	$zone = trim(str_replace('{key}', $key, $zone), '.');
	if ($zone === '') return null;
	$bin = @inet_pton($ip);
	if ($bin === false) return null;
	if (strlen($bin) === 4) {
		return implode('.', array_reverse(explode('.', inet_ntop($bin)))) . '.' . $zone;
	}
	$nibbles = str_split(bin2hex($bin));
	return implode('.', array_reverse($nibbles)) . '.' . $zone;
}

/* Source address of an inbound line from `tcpdump -n -e -q -i pflog1`:
 * "rule 1..16/0(match): block in on em0: 198.51.100.7.51036 > 192.0.2.1.22: tcp 0" */
function threatshield_dnsbl_pflog_source(string $line): ?string {
	if (!preg_match('/\b(?:block|match)\s+in\s+on\s+\S+:\s+([0-9a-fA-F:.]+?)\.\d+\s+>/', $line, $m)) return null;
	return filter_var($m[1], FILTER_VALIDATE_IP) ? $m[1] : null;
}

/* Spamhaus and others answer 127.255.255.x for errors (public resolver,
 * over quota, bad key): that is never a listing. */
function threatshield_dnsbl_is_error_code(string $answer): bool {
	return str_starts_with($answer, '127.255.255.');
}

/* Match spec: "any", or comma separated addresses and a-b ranges. */
function threatshield_dnsbl_match(array $answers, string $spec): bool {
	$spec = trim($spec);
	foreach ($answers as $a) {
		if (threatshield_dnsbl_is_error_code($a) || !filter_var($a, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) continue;
		if ($spec === '' || strtolower($spec) === 'any') {
			if (str_starts_with($a, '127.')) return true;
			continue;
		}
		$n = ip2long($a);
		foreach (explode(',', $spec) as $part) {
			$part = trim($part);
			if (strpos($part, '-') !== false) {
				[$lo, $hi] = array_map('trim', explode('-', $part, 2));
				if (ip2long($lo) !== false && ip2long($hi) !== false && $n >= ip2long($lo) && $n <= ip2long($hi)) return true;
			} elseif ($part !== '' && $part === $a) {
				return true;
			}
		}
	}
	return false;
}

function threatshield_dnsbl_valid_match(string $spec): bool {
	$spec = trim($spec);
	if ($spec === '' || strtolower($spec) === 'any') return true;
	foreach (explode(',', $spec) as $part) {
		$part = trim($part);
		$ends = (strpos($part, '-') !== false) ? array_map('trim', explode('-', $part, 2)) : [$part];
		foreach ($ends as $ip) {
			if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
		}
	}
	return true;
}

/* Verdict for one address from per-zone results:
 * [['rcode' => 0|3|..., 'answers' => [...], 'error' => ?string, 'match' => spec], ...]
 * listed: at least $quorum zones listed it; clean: every zone answered and
 * fewer than $quorum listed it; fail: too few usable answers to decide. */
function threatshield_dnsbl_verdict(array $results, int $quorum): array {
	$quorum = max(1, $quorum);
	$listed = [];
	$usable = 0;
	foreach ($results as $zone => $r) {
		$answers = (array)($r['answers'] ?? []);
		$error = $r['error'] ?? null;
		$rcode = $r['rcode'] ?? null;
		if ($error !== null || $rcode === null) continue;
		if ($rcode === 3) { $usable++; continue; }            // NXDOMAIN: not listed
		if ($rcode !== 0) continue;                            // SERVFAIL, REFUSED: unusable
		$errors = array_filter($answers, 'threatshield_dnsbl_is_error_code');
		if (!empty($errors) && count($errors) === count($answers)) continue;
		$usable++;
		if (threatshield_dnsbl_match($answers, (string)($r['match'] ?? 'any'))) {
			$listed[$zone] = implode(',', $answers);
		}
	}
	if (count($listed) >= $quorum) return ['verdict' => 'listed', 'zones' => $listed];
	/* clean only when quorum can't be reached even if every unanswered zone
	 * would have listed the address */
	$unknown = count($results) - $usable;
	if (count($listed) + $unknown < $quorum) return ['verdict' => 'clean', 'zones' => $listed];
	return ['verdict' => 'fail', 'zones' => $listed];
}

/* ------------------------------------------------------------- DNS client */

function threatshield_dns_build_query(string $qname, int $id, int $qtype = 1): string {
	$packet = pack('nnnnnn', $id & 0xFFFF, 0x0100, 1, 0, 0, 0);
	foreach (explode('.', trim($qname, '.')) as $label) {
		if ($label === '' || strlen($label) > 63) return '';
		$packet .= chr(strlen($label)) . $label;
	}
	return $packet . "\0" . pack('nn', $qtype, 1);
}

function threatshield_dns_skip_name(string $buf, int $off): ?int {
	$len = strlen($buf);
	for ($guard = 0; $guard < 128; $guard++) {
		if ($off >= $len) return null;
		$c = ord($buf[$off]);
		if ($c === 0) return $off + 1;
		if (($c & 0xC0) === 0xC0) return $off + 2;
		$off += 1 + $c;
	}
	return null;
}

/* ['id' => int, 'rcode' => int, 'answers' => [A/AAAA texts]] or null. */
function threatshield_dns_parse_response(string $buf): ?array {
	if (strlen($buf) < 12) return null;
	$h = unpack('nid/nflags/nqd/nan/nns/nar', substr($buf, 0, 12));
	if (!($h['flags'] & 0x8000)) return null;
	$off = 12;
	for ($i = 0; $i < $h['qd']; $i++) {
		$off = threatshield_dns_skip_name($buf, $off);
		if ($off === null) return null;
		$off += 4;
	}
	$answers = [];
	for ($i = 0; $i < $h['an']; $i++) {
		$off = threatshield_dns_skip_name($buf, $off);
		if ($off === null || $off + 10 > strlen($buf)) return null;
		$rr = unpack('ntype/nclass/Nttl/nrdlen', substr($buf, $off, 10));
		$off += 10;
		if ($off + $rr['rdlen'] > strlen($buf)) return null;
		$rdata = substr($buf, $off, $rr['rdlen']);
		if (($rr['type'] === 1 && $rr['rdlen'] === 4) || ($rr['type'] === 28 && $rr['rdlen'] === 16)) {
			$answers[] = inet_ntop($rdata);
		}
		$off += $rr['rdlen'];
	}
	return ['id' => $h['id'], 'rcode' => $h['flags'] & 0x0F, 'answers' => $answers];
}

/* Resolve several names over UDP in parallel.
 * Returns [qname => ['rcode' => ?int, 'answers' => [...], 'error' => ?string]]. */
function threatshield_dns_query_many(string $server, int $port, array $qnames, int $timeout_ms = 2000, int $qtype = 1): array {
	$results = [];
	$pending = [];
	$target = (strpos($server, ':') !== false) ? "udp://[{$server}]:{$port}" : "udp://{$server}:{$port}";
	foreach (array_values(array_unique($qnames)) as $qname) {
		$results[$qname] = ['rcode' => null, 'answers' => [], 'error' => 'timeout'];
		$id = random_int(1, 0xFFFF);
		$packet = threatshield_dns_build_query($qname, $id, $qtype);
		if ($packet === '') { $results[$qname]['error'] = 'bad name'; continue; }
		$sock = @stream_socket_client($target, $errno, $errstr, 1);
		if (!$sock) { $results[$qname]['error'] = 'socket: ' . $errstr; continue; }
		stream_set_blocking($sock, false);
		if (@fwrite($sock, $packet) === false) { $results[$qname]['error'] = 'send failed'; fclose($sock); continue; }
		$pending[(int)$sock] = [$sock, $qname, $id];
	}
	$deadline = microtime(true) + $timeout_ms / 1000;
	while (!empty($pending)) {
		$left = $deadline - microtime(true);
		if ($left <= 0) break;
		$read = array_map(fn($p) => $p[0], $pending);
		$w = $e = null;
		$n = @stream_select($read, $w, $e, (int)$left, (int)(($left - (int)$left) * 1000000));
		if ($n === false) break;
		foreach ($read as $sock) {
			[, $qname, $id] = $pending[(int)$sock];
			$buf = @fread($sock, 4096);
			if ($buf === '' || $buf === false) {
				$results[$qname]['error'] = 'connection refused';
			} else {
				$parsed = threatshield_dns_parse_response($buf);
				if ($parsed === null || $parsed['id'] !== $id) continue;
				$results[$qname] = ['rcode' => $parsed['rcode'], 'answers' => $parsed['answers'], 'error' => null];
			}
			fclose($sock);
			unset($pending[(int)$sock]);
		}
	}
	foreach ($pending as $p) fclose($p[0]);
	return $results;
}

/* ------------------------------------------------------------- pf helpers */

function threatshield_pf_ident(string $value, int $max = 12): string {
	return substr(preg_replace('/[^a-z0-9]/', '', strtolower($value)), 0, $max);
}

/* GeoIP policy id as used in table names (31 characters), labels and files */
function threatshield_geoip_policy_id(array $policy): string {
	return substr(preg_replace('/[^a-z0-9_]/', '', strtolower((string)($policy['id'] ?? 'default'))), 0, 15) ?: 'default';
}

function threatshield_valid_ifname(string $value): bool {
	return (bool)preg_match('/^[A-Za-z0-9_.:-]{1,32}$/', $value);
}

/* pf ports: "22, 80-90" -> "{ 22 80:90 }" ("" for any). */
function threatshield_pf_ports(string $value): string {
	$value = trim($value);
	if ($value === '' || strtolower($value) === 'any') return '';
	$parts = [];
	foreach (explode(',', $value) as $part) {
		$part = preg_replace('/\s*-\s*/', ':', trim($part));
		if ($part !== '') $parts[] = $part;
	}
	return '{ ' . implode(' ', $parts) . ' }';
}

/* "15/5" style rate spec */
function threatshield_valid_rate(string $value): bool {
	return (bool)preg_match('/^[1-9]\d{0,5}\/[1-9]\d{0,4}$/', trim($value));
}

/* ------------------------------------------------------- update progress */

/*
 * Downloading the lists takes a while. The updater (threatshield_update.php)
 * records where it is in one small file; the WebUI reads it to show a progress
 * bar, so a save never looks like it has stalled. One updater writes it at a
 * time; the last one to start wins.
 */
if (!defined('THREATSHIELD_PROGRESS_FILE')) {
	define('THREATSHIELD_PROGRESS_FILE', '/var/db/threatshield/cache/update_progress.json');
}
/* No answer from a server for this long: the page says it is still waiting. */
const THREATSHIELD_PROGRESS_STALL_SECONDS = 45;
/* How long a finished run stays visible as a one-line result. */
const THREATSHIELD_PROGRESS_RESULT_SECONDS = 60;

function threatshield_progress_save(array $state): void {
	$state['updated'] = time();
	$GLOBALS['threatshield_progress'] = $state;
	$tmp = THREATSHIELD_PROGRESS_FILE . '.tmp.' . getmypid();
	if (@file_put_contents($tmp, json_encode($state), LOCK_EX) !== false) {
		@rename($tmp, THREATSHIELD_PROGRESS_FILE);
	}
}

/* An updater run that has $total downloads to do (0: nothing to show). */
function threatshield_progress_begin(int $total): void {
	if ($total <= 0) {
		return;
	}
	threatshield_progress_save(['running' => true, 'pid' => getmypid(), 'started' => time(), 'total' => $total,
	    'done' => 0, 'failed' => 0, 'phase' => 'starting', 'label' => '']);
}

/* The updater starts $label of $phase (feeds, ipfeeds, geoip, loading, tables). */
function threatshield_progress_step(string $phase, string $label = ''): void {
	if (empty($GLOBALS['threatshield_progress']['running'])) {
		return;
	}
	$state = $GLOBALS['threatshield_progress'];
	$state['phase'] = $phase;
	$state['label'] = $label;
	threatshield_progress_save($state);
}

/* One download finished. */
function threatshield_progress_item(bool $ok): void {
	if (empty($GLOBALS['threatshield_progress']['running'])) {
		return;
	}
	$state = $GLOBALS['threatshield_progress'];
	$state['done'] = min((int)$state['total'], (int)$state['done'] + 1);
	if (!$ok) {
		$state['failed'] = (int)$state['failed'] + 1;
	}
	threatshield_progress_save($state);
}

function threatshield_progress_finish(): void {
	if (empty($GLOBALS['threatshield_progress']['running'])) {
		return;
	}
	$state = $GLOBALS['threatshield_progress'];
	$state['running'] = false;
	$state['ended'] = time();
	$state['phase'] = 'done';
	$state['label'] = '';
	threatshield_progress_save($state);
	$GLOBALS['threatshield_progress'] = $state;
}

/*
 * What the page shows: active (a run is going), stalled (no sign of life for a
 * while), finished with its counts, or interrupted (the updater died). $alive
 * answers whether a process id still exists.
 */
function threatshield_progress_state(?int $now = null, ?callable $alive = null): array {
	$now = $now ?? time();
	$alive = $alive ?? static function (int $pid): bool {
		return ($pid > 0) && function_exists('posix_kill') && @posix_kill($pid, 0);
	};
	$raw = is_file(THREATSHIELD_PROGRESS_FILE) ? json_decode((string)@file_get_contents(THREATSHIELD_PROGRESS_FILE), true) : null;
	if (!is_array($raw) || !isset($raw['total'])) {
		return ['active' => false, 'finished' => false];
	}
	$total = max(0, (int)$raw['total']);
	$done = max(0, min($total, (int)($raw['done'] ?? 0)));
	$updated = (int)($raw['updated'] ?? $now);
	$running = !empty($raw['running']);
	$interrupted = $running && !$alive((int)($raw['pid'] ?? 0));
	$active = $running && !$interrupted;
	$ended = (int)($raw['ended'] ?? ($interrupted ? $updated : 0));
	return [
		'active' => $active,
		'finished' => !$active && (($ended > 0) && (($now - $ended) <= THREATSHIELD_PROGRESS_RESULT_SECONDS)),
		'interrupted' => $interrupted,
		'phase' => (string)($raw['phase'] ?? ''),
		'label' => (string)($raw['label'] ?? ''),
		'done' => $done,
		'total' => $total,
		'failed' => max(0, (int)($raw['failed'] ?? 0)),
		'percent' => ($total > 0) ? (int)floor($done * 100 / $total) : 0,
		'idle' => max(0, $now - $updated),
		'stalled' => $active && (($now - $updated) > THREATSHIELD_PROGRESS_STALL_SECONDS),
		'started' => (int)($raw['started'] ?? 0),
		'ended' => $ended,
	];
}

/*
 * Waits until names resolve (up to $seconds). Saving the settings restarts the
 * DNS service the firewall itself uses, so the download that follows must not
 * start before it answers. Returns whether it did; $ready and $sleep exist for
 * the unit test.
 */
function threatshield_wait_for_dns(int $seconds, ?callable $ready = null, ?callable $sleep = null, string $host = 'pkg.freesense.org'): bool {
	$ready = $ready ?? static function () use ($host): bool {
		return @gethostbyname($host) !== $host;
	};
	$sleep = $sleep ?? 'sleep';
	$deadline = time() + $seconds;
	do {
		if ($ready()) {
			return true;
		}
		$sleep(1);
	} while (time() < $deadline);
	return false;
}
