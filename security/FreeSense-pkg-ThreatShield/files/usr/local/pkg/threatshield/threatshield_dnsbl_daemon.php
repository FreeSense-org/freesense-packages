<?php
/*
 * threatshield_dnsbl_daemon.php
 * FreeSense Threat Shield - inbound DNSBL reputation daemon
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 *
 * pf logs the first packet of every unknown source on a protected port to
 * pflog1.  This daemon reads those log lines, looks the source up in the
 * configured DNSBL zones and records the verdict in pf tables:
 *
 *   listed  -> threatshield_dnsbl_bad (blocked); fail-open policies also
 *              lose the connection that already got through (pfctl -k)
 *   clean   -> threatshield_dnsbl_known(_f) (the next SYN passes)
 *   failure -> memory only, short TTL: threatshield_dnsbl_known_f for
 *              allow-on-failure policies, threatshield_dnsbl_fail for
 *              fail-open policies that deny on failure
 *
 * Load limits: a bounded ingest rate, a bounded queue, a token bucket for
 * DNS queries and bounded concurrency.  Overflow and an open circuit breaker
 * apply each policy's failure action instead of queueing more work, so a
 * spoofed-source flood can't grow memory or delay verdicts without bound.
 */

require_once('/usr/local/pkg/threatshield.inc');

const TSD_INGEST_PER_SEC = 2000;
const TSD_TICK_US = 100000;
const TSD_FLUSH_SECS = 1;
const TSD_FILES_SECS = 15;
const TSD_SWEEP_SECS = 30;
const TSD_STATUS_SECS = 5;
const TSD_PROBE_SECS = 15;
const TSD_KILLS_PER_FLUSH = 100;    // pfctl -k runs per second at most
const TSD_KILLS_PENDING = 2000;     // older states just time out
const TSD_FAIL_MAX = 20000;         // failed sources held at once

final class ThreatShieldDnsbl {
	private array $cfg = [];
	private array $zones = [];
	private int $quorum = 1;
	private array $ttl = [];
	private string $server = '127.0.0.1';
	private int $port = 53;
	private int $timeout = 2000;
	private int $retries = 1;
	private int $qps = 20;
	private int $concurrency = 8;
	private int $queue_max = 2000;
	private int $cache_max = 100000;
	private int $breaker_secs = 30;
	private bool $kill_on_listed = false;
	private bool $deny_fail_table = false;
	private array $static = [];

	private array $known = [];      // ip => expires
	private array $bad = [];        // ip => expires
	private array $fail = [];       // ip => expires (memory only)
	private array $queue = [];      // ip => enqueued
	private array $inflight = [];   // ip => ['zones' => [...], 'results' => [...]]
	private array $sockets = [];    // (int)socket => [socket, ip, zone, qname, id, sent, attempts]
	private array $pending = ['add' => [], 'delete' => [], 'kill' => []];
	private bool $files_dirty = true;
	private ?SQLite3 $db = null;
	private $tcpdump = null;
	private $pipe = null;
	private int $backoff = 1;       // seconds before tcpdump is restarted
	private int $retry_at = 0;
	private float $tokens = 0;
	private float $last_refill = 0;
	private ?int $fail_since = null;
	private bool $breaker = false;
	private int $last_probe = 0;
	private string $last_error = '';
	private bool $reload = false;
	private bool $stop = false;
	private array $stats = ['lookups' => 0, 'listed' => 0, 'clean' => 0, 'failures' => 0, 'cache_hits' => 0, 'dropped_fail' => 0,
	    'dropped_ingest' => 0, 'dropped_queue' => 0, 'per_zone' => []];
	private array $recent = [];     // lookup timestamps for the qps figure
	private array $verdicts = [];   // newest fresh verdicts for the threat map
	private int $verdict_n = 0;
	private int $boot = 0;

	public function run(): void {
		$this->load();
		$this->open_tcpdump();
		$this->sync_tables(true);
		$timers = ['flush' => 0, 'files' => 0, 'sweep' => 0, 'status' => 0];
		while (!$this->stop) {
			if (function_exists('pcntl_signal_dispatch')) pcntl_signal_dispatch();
			if ($this->reload) {
				$this->reload = false;
				$this->load();
				$this->sync_tables(true);
			}
			$this->wait_and_read();
			$this->dispatch();
			$this->check_timeouts();
			$now = time();
			if ($now - $timers['flush'] >= TSD_FLUSH_SECS) { $this->flush_pf(); $timers['flush'] = $now; }
			if ($now - $timers['files'] >= TSD_FILES_SECS) { $this->write_files(); $timers['files'] = $now; }
			if ($now - $timers['sweep'] >= TSD_SWEEP_SECS) { $this->sweep(); $timers['sweep'] = $now; }
			if ($now - $timers['status'] >= TSD_STATUS_SECS) { $this->write_status(); $timers['status'] = $now; }
			if ($this->tcpdump !== null && is_resource($this->pipe) && !proc_get_status($this->tcpdump)['running']) $this->close_input();
			/* tcpdump stopped (pflog1 missing, killed): restart it, waiting
			 * longer each time so a lasting failure doesn't spin */
			if (!is_resource($this->pipe) && $now >= $this->retry_at) {
				$this->last_error = 'tcpdump on pflog1 stopped; restarting';
				$this->open_tcpdump();
				$this->retry_at = $now + $this->backoff;
				$this->backoff = min(60, $this->backoff * 2);
			}
		}
		$this->flush_pf();
		$this->write_files();
		$this->write_status('stopped');
		if ($this->tcpdump !== null) proc_terminate($this->tcpdump);
	}

	public function request_reload(): void { $this->reload = true; }
	public function request_stop(): void { $this->stop = true; }

	private function load(): void {
		/* config_get_path() reads the copy parsed when the process started;
		 * read config.xml again so a reload sees the saved settings. */
		config_read_file(false, true);
		$this->cfg = threatshield_config();
		$c = $this->cfg;
		$this->zones = [];
		foreach (threatshield_normalize_list($c['dnsbl_zones'] ?? []) as $z) {
			if (!is_array($z) || ($z['enabled'] ?? 'off') !== 'on') continue;
			$this->zones[(string)$z['id']] = ['zone' => (string)$z['zone'], 'access_key' => (string)($z['access_key'] ?? ''),
			    'match' => (string)($z['match'] ?? 'any'), 'ipv6' => ($z['ipv6'] ?? 'off') === 'on'];
		}
		$this->quorum = max(1, min(count($this->zones) ?: 1, (int)($c['dnsbl_quorum'] ?? 1)));
		$this->ttl = ['clean' => (int)$c['dnsbl_ttl_good'], 'listed' => (int)$c['dnsbl_ttl_bad'], 'fail' => (int)$c['dnsbl_ttl_fail']];
		[$this->server, $this->port] = threatshield_dnsbl_resolver($c);
		$this->timeout = (int)$c['dnsbl_timeout_ms'];
		$this->retries = (int)$c['dnsbl_retries'];
		$this->qps = (int)$c['dnsbl_max_qps'];
		$this->concurrency = (int)$c['dnsbl_concurrency'];
		$this->queue_max = (int)$c['dnsbl_queue_max'];
		$this->cache_max = (int)$c['dnsbl_cache_max'];
		$this->breaker_secs = (int)$c['dnsbl_breaker_secs'];
		$this->kill_on_listed = false;
		$this->deny_fail_table = false;
		foreach (threatshield_normalize_list($c['inbound_policies'] ?? []) as $p) {
			if (!is_array($p) || ($p['enable'] ?? 'on') !== 'on' || ($p['dnsbl_mode'] ?? 'off') !== 'failopen') continue;
			$this->kill_on_listed = true;
			if (($p['on_failure'] ?? 'allow') === 'deny') $this->deny_fail_table = true;
		}
		$this->static = threatshield_dnsbl_static_known($c);
		if ($this->db !== null) $this->db->close();
		$this->db = threatshield_dnsbl_db();
		$this->known = $this->bad = [];
		if ($this->db !== null) {
			$st = $this->db->prepare('SELECT ip, verdict, expires FROM verdicts WHERE expires > :now ORDER BY checked DESC LIMIT :max');
			$st->bindValue(':now', time(), SQLITE3_INTEGER);
			$st->bindValue(':max', $this->cache_max, SQLITE3_INTEGER);
			$res = $st->execute();
			while ($res && ($row = $res->fetchArray(SQLITE3_ASSOC))) {
				if ($row['verdict'] === 'listed') $this->bad[$row['ip']] = (int)$row['expires'];
				else $this->known[$row['ip']] = (int)$row['expires'];
			}
		}
		/* an address put on the allowlist is never blocked by reputation */
		foreach (array_keys($this->bad) as $ip) {
			foreach ($this->static as $cidr) {
				if (!threatshield_cidr_contains($cidr, $ip)) continue;
				unset($this->bad[$ip]);
				$this->queue_pf('delete', THREATSHIELD_T_BAD, $ip);
				if ($this->db !== null) $this->db->exec("DELETE FROM verdicts WHERE ip = '" . SQLite3::escapeString($ip) . "'");
				break;
			}
		}
		$this->tokens = $this->qps;
		$this->last_refill = microtime(true);
		$this->files_dirty = true;
		logger(LOG_INFO, sprintf('Threat Shield DNSBL: %d zones via %s:%d, %d cached verdicts', count($this->zones), $this->server, $this->port, count($this->known) + count($this->bad)));
	}

	private function close_input(): void {
		if (is_resource($this->pipe)) fclose($this->pipe);
		$this->pipe = null;
	}

	private function open_tcpdump(): void {
		$this->close_input();
		if ($this->tcpdump !== null) {
			@proc_terminate($this->tcpdump);
			@proc_close($this->tcpdump);
			$this->tcpdump = null;
		}
		/* Tests feed tcpdump-formatted lines through a FIFO instead. */
		$input = (string)getenv('THREATSHIELD_DNSBL_INPUT');
		if ($input !== '' && file_exists($input)) {
			$this->pipe = fopen($input, 'r+');
			stream_set_blocking($this->pipe, false);
			return;
		}
		$this->tcpdump = proc_open(['/usr/sbin/tcpdump', '-l', '-n', '-e', '-q', '-s', '128', '-B', '4096', '-i', 'pflog1'],
		    [1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'a']], $pipes);
		if (!is_resource($this->tcpdump)) {
			$this->tcpdump = null;
			$this->last_error = 'cannot start tcpdump on pflog1';
			return;
		}
		$this->pipe = $pipes[1];
		stream_set_blocking($this->pipe, false);
	}

	/* Waits up to one tick for log lines or DNS answers. */
	private function wait_and_read(): void {
		$read = array_map(fn($s) => $s[0], $this->sockets);
		if (is_resource($this->pipe)) $read[] = $this->pipe;
		if (empty($read)) {
			usleep(TSD_TICK_US);
			return;
		}
		$w = $e = null;
		if (@stream_select($read, $w, $e, 0, TSD_TICK_US) === false) return;
		foreach ($read as $stream) {
			if ($stream === $this->pipe) $this->ingest();
			else $this->receive($stream);
		}
	}

	private function ingest(): void {
		$budget = (int)(TSD_INGEST_PER_SEC * TSD_TICK_US / 1000000) + 1;
		while (($line = fgets($this->pipe)) !== false) {
			if ($budget-- <= 0) {
				$this->stats['dropped_ingest']++;
				continue;
			}
			$this->backoff = 1;
			$ip = threatshield_dnsbl_pflog_source($line);
			if ($ip !== null) $this->observe($ip);
		}
		if (feof($this->pipe)) $this->close_input();
	}

	/* A new source showed up on a protected port. */
	private function observe(string $ip): void {
		if (!filter_var($ip, FILTER_VALIDATE_IP)) return;
		$now = time();
		/* Already decided: pf lost the entry (a filter reload between two file
		 * writes), so put it back instead of looking it up again. */
		if (($this->bad[$ip] ?? 0) > $now) { $this->queue_pf('add', THREATSHIELD_T_BAD, $ip); return; }
		if (($this->known[$ip] ?? 0) > $now) { $this->queue_pf('add', THREATSHIELD_T_KNOWN, $ip); $this->queue_pf('add', THREATSHIELD_T_KNOWNF, $ip); return; }
		if (($this->fail[$ip] ?? 0) > $now) {
			$this->queue_pf('add', THREATSHIELD_T_KNOWNF, $ip);
			if ($this->deny_fail_table) $this->queue_pf('add', THREATSHIELD_T_FAIL, $ip);
			return;
		}
		if (isset($this->queue[$ip]) || isset($this->inflight[$ip])) return;
		foreach ($this->static as $cidr) {
			if (threatshield_cidr_contains($cidr, $ip)) return;
		}
		$cached = $this->cache_get($ip);
		if ($cached !== null) {
			$this->stats['cache_hits']++;
			$this->apply($ip, $cached['verdict'], $cached['zones'], (int)$cached['expires'], false);
			return;
		}
		if ($this->breaker || count($this->queue) >= $this->queue_max || empty($this->zones)) {
			if (!$this->breaker && !empty($this->zones)) $this->stats['dropped_queue']++;
			$this->apply($ip, 'fail', [], $now + $this->ttl['fail'], false);
			return;
		}
		$this->queue[$ip] = $now;
	}

	private function cache_get(string $ip): ?array {
		if ($this->db === null) return null;
		$st = $this->db->prepare('SELECT verdict, zones, expires FROM verdicts WHERE ip = :ip AND expires > :now');
		$st->bindValue(':ip', $ip, SQLITE3_TEXT);
		$st->bindValue(':now', time(), SQLITE3_INTEGER);
		$res = $st->execute();
		$row = $res ? $res->fetchArray(SQLITE3_ASSOC) : false;
		if (!is_array($row)) return null;
		$this->db->exec('UPDATE verdicts SET hits = hits + 1 WHERE ip = ' . "'" . SQLite3::escapeString($ip) . "'");
		return ['verdict' => $row['verdict'], 'zones' => array_filter(explode(';', (string)$row['zones'])), 'expires' => $row['expires']];
	}

	/* Starts lookups while tokens and concurrency allow. */
	private function dispatch(): void {
		$now = microtime(true);
		$this->tokens = min($this->qps, $this->tokens + ($now - $this->last_refill) * $this->qps);
		$this->last_refill = $now;
		if ($this->breaker) {
			if (time() - $this->last_probe >= TSD_PROBE_SECS) $this->probe();
			return;
		}
		foreach ($this->queue as $ip => $since) {
			if (count($this->inflight) >= $this->concurrency) break;
			$v6 = strpos($ip, ':') !== false;
			$zones = array_filter($this->zones, fn($z) => !$v6 || $z['ipv6']);
			if (empty($zones)) {
				unset($this->queue[$ip]);
				$this->apply($ip, 'clean', [], time() + $this->ttl['clean'], true);
				continue;
			}
			if ($this->tokens < count($zones)) break;
			$this->tokens -= count($zones);
			unset($this->queue[$ip]);
			$this->inflight[$ip] = ['results' => [], 'zones' => array_keys($zones)];
			foreach ($zones as $id => $z) {
				$this->send($ip, $id, threatshield_dnsbl_qname($ip, $z['zone'], $z['access_key']), 1);
			}
			$this->stats['lookups']++;
			$this->recent[] = time();
		}
	}

	private function send(string $ip, string $zone, ?string $qname, int $attempt): void {
		if ($qname === null) {
			$this->result($ip, $zone, ['rcode' => null, 'answers' => [], 'error' => 'bad zone']);
			return;
		}
		$target = (strpos($this->server, ':') !== false) ? "udp://[{$this->server}]:{$this->port}" : "udp://{$this->server}:{$this->port}";
		$sock = @stream_socket_client($target, $errno, $errstr, 1);
		$id = random_int(1, 0xFFFF);
		if (!$sock || @fwrite($sock, threatshield_dns_build_query($qname, $id)) === false) {
			if ($sock) fclose($sock);
			$this->result($ip, $zone, ['rcode' => null, 'answers' => [], 'error' => 'send failed']);
			return;
		}
		stream_set_blocking($sock, false);
		$this->sockets[(int)$sock] = [$sock, $ip, $zone, $qname, $id, microtime(true), $attempt];
	}

	private function receive($sock): void {
		$entry = $this->sockets[(int)$sock] ?? null;
		if ($entry === null) return;
		[, $ip, $zone, , $id] = $entry;
		$buf = @fread($sock, 4096);
		$parsed = ($buf !== false && $buf !== '') ? threatshield_dns_parse_response($buf) : null;
		if ($buf !== false && $buf !== '' && ($parsed === null || $parsed['id'] !== $id)) return;    // stray datagram
		fclose($sock);
		unset($this->sockets[(int)$sock]);
		if ($parsed === null) {
			$this->retry_or_fail($entry, 'resolver refused the connection');
			return;
		}
		$this->result($ip, $zone, ['rcode' => $parsed['rcode'], 'answers' => $parsed['answers'], 'error' => null]);
	}

	private function check_timeouts(): void {
		$now = microtime(true);
		foreach ($this->sockets as $key => $entry) {
			if ($now - $entry[5] < $this->timeout / 1000) continue;
			fclose($entry[0]);
			unset($this->sockets[$key]);
			$this->retry_or_fail($entry, 'timeout');
		}
	}

	private function retry_or_fail(array $entry, string $error): void {
		[, $ip, $zone, $qname, , , $attempt] = $entry;
		if ($attempt <= $this->retries) {
			$this->send($ip, $zone, $qname, $attempt + 1);
			return;
		}
		$this->result($ip, $zone, ['rcode' => null, 'answers' => [], 'error' => $error]);
	}

	private function result(string $ip, string $zone, array $r): void {
		if ($ip === '__probe__') {
			$this->probe_result($r);
			return;
		}
		if (!isset($this->inflight[$ip])) return;
		$r['match'] = $this->zones[$zone]['match'] ?? 'any';
		$this->inflight[$ip]['results'][$zone] = $r;
		if ($r['error'] !== null) $this->last_error = "{$zone}: {$r['error']}";
		elseif ($r['rcode'] !== 0 && $r['rcode'] !== 3) $this->last_error = "{$zone}: DNS code {$r['rcode']}";
		elseif (!empty($r['answers']) && count(array_filter($r['answers'], 'threatshield_dnsbl_is_error_code')) === count($r['answers'])) {
			$this->last_error = "{$zone}: refused ({$r['answers'][0]}), use your own resolver or a DQS key";
		}
		if (count($this->inflight[$ip]['results']) < count($this->inflight[$ip]['zones'])) return;
		$results = $this->inflight[$ip]['results'];
		unset($this->inflight[$ip]);
		$v = threatshield_dnsbl_verdict($results, min($this->quorum, count($results)));
		$now = time();
		if ($v['verdict'] === 'fail') {
			$this->fail_since = $this->fail_since ?? $now;
			if (!$this->breaker && $now - $this->fail_since >= $this->breaker_secs) $this->open_breaker();
		} else {
			$this->fail_since = null;
		}
		foreach ($v['zones'] as $z => $codes) {
			$this->stats['per_zone'][$z] = ($this->stats['per_zone'][$z] ?? 0) + 1;
		}
		$zones = array_map(fn($z, $codes) => "{$z}={$codes}", array_keys($v['zones']), $v['zones']);
		$this->apply($ip, $v['verdict'], $zones, $now + $this->ttl[$v['verdict'] === 'listed' ? 'listed' : ($v['verdict'] === 'clean' ? 'clean' : 'fail')], true);
	}

	private function open_breaker(): void {
		$this->breaker = true;
		$this->last_probe = time();
		$msg = sprintf('Threat Shield DNSBL: lookups have failed for %d s (%s); new sources are handled by each policy\'s failure action until the resolver answers again.',
		    $this->breaker_secs, $this->last_error);
		logger(LOG_WARNING, $msg);
		file_notice('threatshield_dnsbl', $msg, gettext('Threat Shield'), '/threatshield/threatshield_inbound.php');
		foreach ($this->queue as $ip => $since) $this->apply($ip, 'fail', [], time() + $this->ttl['fail'], false);
		$this->queue = [];
	}

	/* RFC 5782 test entry: 127.0.0.2 must be listed by every zone. */
	private function probe(): void {
		$this->last_probe = time();
		$zone = reset($this->zones);
		if ($zone === false) return;
		$this->send('__probe__', (string)key($this->zones), threatshield_dnsbl_qname('127.0.0.2', $zone['zone'], $zone['access_key']), $this->retries + 1);
	}

	private function probe_result(array $r): void {
		if ($r['error'] === null && $r['rcode'] === 0 && !empty($r['answers']) && !threatshield_dnsbl_is_error_code($r['answers'][0])) {
			$this->breaker = false;
			$this->fail_since = null;
			$this->last_error = '';
			logger(LOG_NOTICE, 'Threat Shield DNSBL: lookups work again.');
		}
	}

	private function apply(string $ip, string $verdict, array $zones, int $expires, bool $fresh): void {
		if ($verdict === 'listed') {
			$this->bad[$ip] = $expires;
			unset($this->known[$ip], $this->fail[$ip]);
			$this->queue_pf('add', THREATSHIELD_T_BAD, $ip);
			foreach ([THREATSHIELD_T_KNOWN, THREATSHIELD_T_KNOWNF, THREATSHIELD_T_FAIL] as $t) $this->queue_pf('delete', $t, $ip);
			if ($this->kill_on_listed) $this->queue_kill($ip);
			if ($fresh) $this->stats['listed']++;
		} elseif ($verdict === 'clean') {
			$this->known[$ip] = $expires;
			unset($this->bad[$ip], $this->fail[$ip]);
			$this->queue_pf('add', THREATSHIELD_T_KNOWN, $ip);
			$this->queue_pf('add', THREATSHIELD_T_KNOWNF, $ip);
			$this->queue_pf('delete', THREATSHIELD_T_FAIL, $ip);
			if ($fresh) $this->stats['clean']++;
		} else {
			/* A spoofed flood while the resolver is down would otherwise grow
			 * this without limit; past the cap a source stays unverified:
			 * greylisting keeps dropping it, a background check lets it by. */
			if (!isset($this->fail[$ip]) && count($this->fail) >= $this->fail_max()) {
				$this->stats['dropped_fail']++;
				return;
			}
			$this->fail[$ip] = $expires;
			$this->queue_pf('add', THREATSHIELD_T_KNOWNF, $ip);
			if ($this->deny_fail_table) {
				$this->queue_pf('add', THREATSHIELD_T_FAIL, $ip);
				$this->queue_kill($ip);
			}
			$this->stats['failures']++;
		}
		$this->files_dirty = true;
		if ($fresh && $verdict !== 'fail') {
			$this->verdicts[] = ['n' => ++$this->verdict_n, 't' => time(), 'ip' => $ip, 'v' => $verdict, 'z' => array_values($zones)];
			if (count($this->verdicts) > 100) array_shift($this->verdicts);
		}
		if ($fresh && $verdict !== 'fail' && $this->db !== null) {
			$st = $this->db->prepare('INSERT INTO verdicts (ip, verdict, zones, checked, expires, hits) VALUES (:ip, :v, :z, :c, :e, 1)
			    ON CONFLICT(ip) DO UPDATE SET verdict = :v, zones = :z, checked = :c, expires = :e, hits = hits + 1');
			$st->bindValue(':ip', $ip, SQLITE3_TEXT);
			$st->bindValue(':v', $verdict, SQLITE3_TEXT);
			$st->bindValue(':z', implode(';', $zones), SQLITE3_TEXT);
			$st->bindValue(':c', time(), SQLITE3_INTEGER);
			$st->bindValue(':e', $expires, SQLITE3_INTEGER);
			$st->execute();
		}
	}

	private function fail_max(): int {
		return max(1000, min($this->cache_max, TSD_FAIL_MAX));
	}

	private function queue_kill(string $ip): void {
		if (count($this->pending['kill']) < TSD_KILLS_PENDING) $this->pending['kill'][$ip] = true;
	}

	private function queue_pf(string $op, string $table, string $ip): void {
		$other = ($op === 'add') ? 'delete' : 'add';
		unset($this->pending[$other][$table][$ip]);
		$this->pending[$op][$table][$ip] = true;
	}

	private function flush_pf(): void {
		foreach (['delete', 'add'] as $op) {
			foreach ($this->pending[$op] as $table => $ips) {
				foreach (array_chunk(array_keys($ips), 200) as $chunk) {
					mwexec("/sbin/pfctl -t {$table} -T {$op} " . implode(' ', array_map('escapeshellarg', $chunk)), true);
				}
			}
		}
		foreach (array_slice(array_keys($this->pending['kill']), 0, TSD_KILLS_PER_FLUSH) as $ip) {
			mwexec('/sbin/pfctl -k ' . escapeshellarg($ip), true);
			unset($this->pending['kill'][$ip]);
		}
		$this->pending['add'] = $this->pending['delete'] = [];
	}

	/* The table files survive filter reloads and reboots. */
	private function write_files(): void {
		if (!$this->files_dirty) return;
		$now = time();
		$live = fn(array $m) => array_keys(array_filter($m, fn($e) => $e > $now));
		$known = array_merge($this->static, $live($this->known));
		$files = [
			'bad.txt' => $live($this->bad),
			'known.txt' => $known,
			'known_f.txt' => array_merge($known, $live($this->fail)),
			'fail.txt' => $this->deny_fail_table ? $live($this->fail) : [],
		];
		foreach ($files as $name => $lines) {
			threatshield_write_table_file(THREATSHIELD_DNSBL_DIR . '/' . $name, $lines);
		}
		$this->files_dirty = false;
	}

	/* Loads the files into pf (start, reload, after a filter reload). */
	private function sync_tables(bool $force): void {
		$this->write_files();
		foreach (['bad.txt' => THREATSHIELD_T_BAD, 'known.txt' => THREATSHIELD_T_KNOWN, 'known_f.txt' => THREATSHIELD_T_KNOWNF, 'fail.txt' => THREATSHIELD_T_FAIL] as $file => $table) {
			mwexec("/sbin/pfctl -t {$table} -T replace -f " . escapeshellarg(THREATSHIELD_DNSBL_DIR . '/' . $file), true);
		}
	}

	private function sweep(): void {
		$now = time();
		foreach (['known' => [THREATSHIELD_T_KNOWN, THREATSHIELD_T_KNOWNF], 'bad' => [THREATSHIELD_T_BAD], 'fail' => [THREATSHIELD_T_KNOWNF, THREATSHIELD_T_FAIL]] as $map => $tables) {
			foreach ($this->{$map} as $ip => $expires) {
				if ($expires > $now) continue;
				unset($this->{$map}[$ip]);
				foreach ($tables as $t) {
					/* a failure entry expiring must not drop a clean verdict */
					if ($map === 'fail' && $t === THREATSHIELD_T_KNOWNF && isset($this->known[$ip])) continue;
					$this->queue_pf('delete', $t, $ip);
				}
				$this->files_dirty = true;
			}
		}
		/* over the limit: the entries expiring first go, from pf as well */
		$limits = ['known' => [$this->cache_max, [THREATSHIELD_T_KNOWN, THREATSHIELD_T_KNOWNF]], 'bad' => [$this->cache_max, [THREATSHIELD_T_BAD]],
		    'fail' => [$this->fail_max(), [THREATSHIELD_T_KNOWNF, THREATSHIELD_T_FAIL]]];
		foreach ($limits as $map => [$max, $tables]) {
			$over = count($this->{$map}) - $max;
			if ($over <= 0) continue;
			asort($this->{$map});
			foreach (array_slice(array_keys($this->{$map}), 0, $over) as $ip) {
				unset($this->{$map}[$ip]);
				foreach ($tables as $t) {
					if ($map === 'fail' && $t === THREATSHIELD_T_KNOWNF && isset($this->known[$ip])) continue;
					$this->queue_pf('delete', $t, $ip);
				}
			}
			$this->files_dirty = true;
		}
		if ($this->db !== null) {
			$this->db->exec('DELETE FROM verdicts WHERE expires <= ' . $now);
			/* the cache file keeps at most twice what memory holds */
			$this->db->exec('DELETE FROM verdicts WHERE ip IN (SELECT ip FROM verdicts ORDER BY checked DESC LIMIT -1 OFFSET ' . ($this->cache_max * 2) . ')');
		}
		$this->recent = array_values(array_filter($this->recent, fn($t) => $t > $now - 60));
		/* a filter reload re-reads the files; make sure pf still has what we hold */
		$count = threatshield_pf_table_count(THREATSHIELD_T_KNOWN);
		if ($count !== null && $count < count($this->static)) $this->sync_tables(true);
	}

	private function write_status(string $state = 'running'): void {
		$status = $this->stats + [
			'state' => $state, 'breaker' => $this->breaker ? 'open' : 'closed', 'last_error' => $this->last_error,
			'queue' => count($this->queue), 'inflight' => count($this->inflight), 'qps' => round(count($this->recent) / 60, 2),
			'cached_clean' => count($this->known), 'cached_listed' => count($this->bad), 'failing' => count($this->fail),
			'resolver' => "{$this->server}:{$this->port}", 'zones' => array_keys($this->zones), 'updated' => time(),
		];
		@file_put_contents(THREATSHIELD_DNSBL_STATUS . '.tmp', json_encode($status), LOCK_EX);
		@rename(THREATSHIELD_DNSBL_STATUS . '.tmp', THREATSHIELD_DNSBL_STATUS);
		/* the threat map reads the newest verdicts from here */
		$this->boot = $this->boot ?: time();
		$recent = '/var/run/threatshield_dnsbl.recent.json';
		@file_put_contents($recent . '.tmp', json_encode(['boot' => $this->boot, 'n' => $this->verdict_n, 'v' => $this->verdicts]), LOCK_EX);
		@rename($recent . '.tmp', $recent);
	}
}

$daemon = new ThreatShieldDnsbl();
if (function_exists('pcntl_signal')) {
	pcntl_signal(1, fn() => $daemon->request_reload());     // SIGHUP
	pcntl_signal(15, fn() => $daemon->request_stop());      // SIGTERM
	pcntl_signal(2, fn() => $daemon->request_stop());       // SIGINT
}
$daemon->run();
