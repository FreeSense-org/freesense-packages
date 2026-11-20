<?php
/*
 * fleet_alerts.inc
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2026 The FreeSense Project
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Alerts: what happens in the fleet (a firewall goes offline or comes
 * back, an operation or backup fails, Lock is suspended, a policy fix
 * fails...) is recorded once (the same alert for the same firewall
 * within 15 minutes is merged) and sent to the channels that want it:
 * e-mail (the controller's own notification settings), a webhook,
 * Slack or Teams, Telegram, ntfy or Gotify. Secrets in a channel (tokens,
 * webhook addresses) are kept sealed with the master key. Delivery runs
 * from the minute poll and retries a failed send a few times.
 * A channel can also get a daily report.
 */

require_once('fleet/fleet_store.inc');

define('FLEET_ALERT_TYPES', array(
	'email' => array('E-mail', 'fa-envelope', array()),
	'webhook' => array('Webhook', 'fa-code', array('url' => 'Address (https://...)', 'pin' => 'Trust this certificate (SHA-256, optional)')),
	'slack' => array('Slack or Teams', 'fa-comments', array('url' => 'Incoming webhook address')),
	'telegram' => array('Telegram', 'fa-paper-plane', array('token' => 'Bot token', 'chat' => 'Chat id')),
	'ntfy' => array('ntfy', 'fa-bell', array('url' => 'Topic address (https://ntfy.sh/your-topic)', 'token' => 'Access token (optional)',
	    'pin' => 'Trust this certificate (SHA-256, optional)')),
	'gotify' => array('Gotify', 'fa-tower-broadcast', array('url' => 'Server address', 'token' => 'Application token', 'pin' => 'Trust this certificate (SHA-256, optional)')),
));
/* Fields a channel may leave empty. */
define('FLEET_ALERT_OPTIONAL', array('pin'));
/* Fields that are secret (sealed, never shown again). */
define('FLEET_ALERT_SECRETS', array('url', 'token'));
define('FLEET_ALERT_EVENTS', array(
	'offline' => array('Firewall offline', 'critical'),
	'online' => array('Firewall back online', 'info'),
	'op_failed' => array('An operation failed', 'warning'),
	'backup_failed' => array('A backup failed', 'warning'),
	'breakglass' => array('Lock suspended (break-glass)', 'critical'),
	'policy' => array('A policy fix failed', 'warning'),
	'policy_fail' => array('A firewall started failing a High policy rule', 'warning'),
	'copies' => array('Backup copies or off-site storage failed', 'warning'),
	'approval' => array('A firewall waits for approval', 'info'),
	'path_down' => array('A connection path stopped answering (tunnel used)', 'warning'),
	'path_up' => array('A connection path answers again', 'info'),
	'ha_problem' => array('An HA pair has two MASTERs, none, or a member down', 'critical'),
	'ha_ok' => array('An HA pair is healthy again', 'info'),
	'inet_down' => array('A firewall lost its internet', 'critical'),
	'inet_degraded' => array('The internet of a firewall is poor (loss, latency or jitter)', 'warning'),
	'inet_unstable' => array('The connection of a firewall is unstable (flapping)', 'warning'),
	'inet_failover' => array('A firewall moved to another WAN', 'warning'),
	'inet_up' => array('The internet of a firewall works again', 'info'),
	'inet_wide' => array('Many firewalls lost their internet at once (upstream outage)', 'critical'),
	'join_refused' => array('A join was refused (wrong firewall or key)', 'warning'),
	'controller_takeover' => array('The standby controller took over, or this controller stepped down', 'critical'),
	'standby_problem' => array('The standby controller stopped fetching copies', 'warning'),
	'standby_ok' => array('The standby controller fetches copies again', 'info'),
	'access_blocked' => array('An address was blocked after wrong join keys', 'warning'),
	'test' => array('Test', 'info'),
));
define('FLEET_ALERT_SEVERITIES', array('info' => 1, 'warning' => 2, 'critical' => 3));
define('FLEET_ALERT_MERGE', 900);
define('FLEET_ALERT_TRIES', 8);
/* An alert nobody ever tried to send (no channel yet) is not sent once it is older than this: a new channel does not get the old backlog. */
define('FLEET_ALERT_MAX_AGE', 3600);
/* More alerts than this for one channel in one run go out as one summary message. */
define('FLEET_ALERT_DIGEST', 8);
/* The most time one delivery run spends sending, in seconds (each send has its own timeout too). */
define('FLEET_ALERT_BUDGET', 45);

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: does a channel want this alert? */
function fleet_alert_wanted(array $channel, string $event, string $severity): bool {
	if (empty($channel['enabled'])) {
		return false;
	}
	if (in_array($event, array('test', 'report'), true)) {
		return true;
	}
	return in_array($event, (array)$channel['events'], true) &&
	    (FLEET_ALERT_SEVERITIES[$severity] ?? 1) >= (FLEET_ALERT_SEVERITIES[$channel['min_severity'] ?? 'info'] ?? 1);
}

/*
 * pure: the alert an audit entry means, as array(event, node id or '',
 * text), or null. Every feature already writes its failures to the
 * audit log, so alerts follow from one place.
 */
function fleet_alert_classify(string $action, string $detail, string $node = '', string $code = ''): ?array {
	list($node, $code) = fleet_audit_subject($detail, ($node !== '') ? $node : null, ($code !== '') ? $code : null);
	switch ($action) {
	case 'state':
		if (preg_match('/: (\w+) -> (\w+)/', $detail, $s)) {
			if ($s[2] === 'offline') {
				return array('offline', $node, $detail);
			}
			if (($s[2] === 'online') && ($s[1] === 'offline')) {
				return array('online', $node, $detail);
			}
		}
		return null;
	case 'backup_failed':
		return array('backup_failed', $node, $detail);
	case 'backup_verify':
		return ($code === 'FLEET-E806') ? array('backup_failed', $node, $detail) : null;
	case 'restore_failed':
		return array('op_failed', $node, $detail);
	case 'policy':
		if ($code === 'FLEET-E321') {
			return array('breakglass', $node, $detail);
		}
		return ($code === 'FLEET-E320') ? array('policy', $node, $detail) : null;
	case 'replicas':
		return preg_match('/fail|FLEET-E80[3-7]|could not|unreachable/i', $detail) ? array('copies', '', $detail) : null;
	case 'pending':
		return array('approval', '', $detail);
	case 'binding_mismatch':
	case 'burned':
		return array('join_refused', '', $detail);
	}
	return null;
}

/* Called by fleet_audit(): raise the alert an entry means. Never throws. */
function fleet_alert_from_audit(string $action, string $detail, string $node = '', string $code = ''): void {
	$a = fleet_alert_classify($action, $detail, $node, $code);
	if ($a === null) {
		return;
	}
	try {
		fleet_alert($a[0], $a[1], $a[2]);
	} catch (Throwable $e) {
		/* An alert must never break what raised it. */
	}
}

/* pure: an https (or, for a lab, http) address. */
function fleet_alert_url_ok(string $url): bool {
	if (!preg_match('~^https?://([A-Za-z0-9.\[\]:_-]+?)(:\d+)?(/[^\s]*)?$~D', $url, $m) || (strlen($url) > 500)) {
		return false;
	}
	/* Tests run a sink on 127.0.0.1 and define this; nothing else does. */
	return defined('FLEET_ALERT_ALLOW_LOOPBACK') || !fleet_alert_host_blocked($m[1]);
}

/*
 * pure: a host a webhook must never call: this controller itself (loopback, "localhost"), the unspecified address and
 * link-local addresses (cloud metadata at 169.254.169.254, fe80::). Addresses on the LAN are allowed: a webhook server
 * is often one.
 */
function fleet_alert_host_blocked(string $host): bool {
	$host = strtolower(trim($host, '[]'));
	if (($host === 'localhost') || (substr($host, -10) === '.localhost') || ($host === '0') || ($host === '')) {
		return true;
	}
	if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
		$long = ip2long($host);
		return ($long === false) || (($long >> 24) === 127) || (($long >> 24) === 0) || ((($long >> 16) & 0xffff) === 0xa9fe);
	}
	if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
		$bin = inet_pton($host);
		$mapped = (strlen($bin) === 16) && (substr($bin, 0, 12) === "\0\0\0\0\0\0\0\0\0\0\xff\xff");
		if ($mapped) {
			return fleet_alert_host_blocked(inet_ntop(substr($bin, 12)));
		}
		return ($bin === inet_pton('::1')) || ($bin === inet_pton('::')) || ((ord($bin[0]) === 0xfe) && ((ord($bin[1]) & 0xc0) === 0x80));
	}
	return false;
}

/*
 * pure: a certificate's SHA-256 fingerprint as 64 lower-case hex digits
 * (colons and spaces dropped), '' when empty, or null when it is not one.
 */
function fleet_alert_pin_normalize(string $pin): ?string {
	$pin = strtolower(preg_replace('/[\s:]+/', '', preg_replace('/^sha256\s*fingerprint\s*=\s*/i', '', trim($pin))));
	if ($pin === '') {
		return '';
	}
	return preg_match('/^[0-9a-f]{64}$/D', $pin) ? $pin : null;
}

/*
 * pure: the HTTP request one alert makes for a channel: array(url,
 * headers, body) or null for e-mail. $a: {title, text, severity, node,
 * time, link}.
 */
function fleet_alert_request(string $type, array $cfg, array $a): ?array {
	$line = $a['title'] . (($a['text'] !== '') ? ': ' . $a['text'] : '');
	switch ($type) {
	case 'webhook':
		return array($cfg['url'], array('Content-Type: application/json'), json_encode(array('source' => 'freesense-fleet') + $a, JSON_UNESCAPED_SLASHES));
	case 'slack':
		return array($cfg['url'], array('Content-Type: application/json'), json_encode(array('text' => '[' . strtoupper($a['severity']) . '] ' . $line . (($a['link'] ?? '') !== '' ? "\n" . $a['link'] : ''))));
	case 'telegram':
		return array('https://api.telegram.org/bot' . $cfg['token'] . '/sendMessage', array('Content-Type: application/json'),
		    json_encode(array('chat_id' => $cfg['chat'], 'text' => '[' . strtoupper($a['severity']) . '] ' . $line, 'disable_web_page_preview' => true)));
	case 'ntfy':
		$h = array('Title: ' . preg_replace('/[\r\n]+/', ' ', mb_substr($a['title'], 0, 200)), 'Priority: ' . array('info' => '3', 'warning' => '4', 'critical' => '5')[$a['severity']],
		    'Tags: ' . array('info' => 'information_source', 'warning' => 'warning', 'critical' => 'rotating_light')[$a['severity']]);
		if (($cfg['token'] ?? '') !== '') {
			$h[] = 'Authorization: Bearer ' . $cfg['token'];
		}
		return array($cfg['url'], $h, $a['text']);
	case 'gotify':
		return array(rtrim($cfg['url'], '/') . '/message', array('Content-Type: application/json', 'X-Gotify-Key: ' . $cfg['token']),
		    json_encode(array('title' => $a['title'], 'message' => $a['text'], 'priority' => array('info' => 3, 'warning' => 6, 'critical' => 9)[$a['severity']])));
	}
	return null;
}

/* pure: the text of a daily report from counts. */
function fleet_alert_report_text(array $c): string {
	return sprintf("%d firewalls: %d online, %d degraded, %d offline.\n%d operations in the last 24 hours, %d failed.\n%d backups, %d failed.\nCompliance: %s.\n%d alerts.",
	    $c['boxes'], $c['online'], $c['degraded'], $c['offline'], $c['ops'], $c['ops_failed'], $c['backups'], $c['backups_failed'],
	    ($c['compliance'] === null) ? 'no policies' : $c['compliance'] . '%', $c['alerts']);
}

/* ------------------------------------------------------------------ */
/* Channels                                                            */
/* ------------------------------------------------------------------ */

function fleet_alert_channel_row(array $r): array {
	$r['events'] = json_decode((string)$r['events'], true) ?: array();
	$r['config'] = json_decode((string)$r['config'], true) ?: array();
	return $r;
}

function fleet_alert_channels(): array {
	return array_map('fleet_alert_channel_row', fleet_db()->query('SELECT * FROM alert_channels ORDER BY name COLLATE NOCASE')->fetchAll());
}

function fleet_alert_channel(int $id): ?array {
	$q = fleet_db()->prepare('SELECT * FROM alert_channels WHERE id = ?');
	$q->execute(array($id));
	$r = $q->fetch();
	return is_array($r) ? fleet_alert_channel_row($r) : null;
}

/* A channel's settings with secrets opened (for sending only). */
function fleet_alert_config_open(array $ch): array {
	$out = array();
	foreach ($ch['config'] as $k => $v) {
		$out[$k] = in_array($k, FLEET_ALERT_SECRETS, true) ? (string)fleet_unseal((string)$v, fleet_master_key()) : (string)$v;
	}
	return $out;
}

/* Create or change a channel from its form. A secret left blank on a change keeps the old one. */
function fleet_alert_channel_save(?int $id, array $in, string $who): int {
	$name = trim((string)($in['name'] ?? ''));
	if (($name === '') || (mb_strlen($name) > 60) || preg_match('/[<>\x00-\x1f\x7f]/u', $name)) {
		throw new InvalidArgumentException('Give the channel a name of 1 to 60 characters.');
	}
	$old = ($id !== null) ? fleet_alert_channel($id) : null;
	$type = ($old !== null) ? $old['type'] : (string)($in['type'] ?? '');
	if (!isset(FLEET_ALERT_TYPES[$type])) {
		throw new InvalidArgumentException('Choose how the alerts are sent.');
	}
	$cfg = array();
	foreach (FLEET_ALERT_TYPES[$type][2] as $field => $label) {
		/* The form names each field per type (cfg_<type>_<field>); cfg_<field> still works for other callers. */
		$v = trim((string)($in['cfg_' . $type . '_' . $field] ?? ($in['cfg_' . $field] ?? '')));
		$secret = in_array($field, FLEET_ALERT_SECRETS, true);
		if ($field === 'pin') {
			$pin = fleet_alert_pin_normalize($v);
			if ($pin === null) {
				throw new InvalidArgumentException('A certificate fingerprint is 64 hexadecimal digits (SHA-256); colons are allowed.');
			}
			$cfg[$field] = $pin;
			continue;
		}
		if (($v === '') && $secret && isset($old['config'][$field])) {
			$cfg[$field] = $old['config'][$field];
			continue;
		}
		$optional = (($type === 'ntfy') && ($field === 'token')) || in_array($field, FLEET_ALERT_OPTIONAL, true);
		if (($v === '') && !$optional) {
			throw new InvalidArgumentException(sprintf('Fill in "%s".', $label));
		}
		if (($field === 'url') && !fleet_alert_url_ok($v)) {
			throw new InvalidArgumentException('The address starts with https:// (http:// only in a lab; it is sent unencrypted) and has no spaces.');
		}
		if (($field === 'chat') && !preg_match('/^-?\d{1,20}$|^@[A-Za-z0-9_]{4,64}$/D', $v)) {
			throw new InvalidArgumentException('A Telegram chat id is a number (or @channelname).');
		}
		if (($field === 'token') && ($v !== '') && !preg_match('/^[A-Za-z0-9:_.-]{6,200}$/D', $v)) {
			throw new InvalidArgumentException('The token has characters a token never has.');
		}
		$cfg[$field] = $secret ? fleet_seal($v, fleet_master_key()) : $v;
	}
	$events = array_values(array_intersect((array)($in['events'] ?? array()), array_keys(FLEET_ALERT_EVENTS)));
	$sev = isset(FLEET_ALERT_SEVERITIES[$in['min_severity'] ?? '']) ? (string)$in['min_severity'] : 'info';
	$report = ((string)($in['report_hour'] ?? '') === '') ? null : max(0, min(23, (int)$in['report_hour']));
	$args = array($name, json_encode($cfg), json_encode($events), $sev, empty($in['enabled']) ? 0 : 1, $report);
	if ($id === null) {
		fleet_db()->prepare('INSERT INTO alert_channels (name, config, events, min_severity, enabled, report_hour, type, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
		    ->execute(array_merge($args, array($type, time())));
		$id = (int)fleet_db()->lastInsertId();
	} else {
		fleet_db()->prepare('UPDATE alert_channels SET name = ?, config = ?, events = ?, min_severity = ?, enabled = ?, report_hour = ? WHERE id = ?')
		    ->execute(array_merge($args, array($id)));
	}
	fleet_audit($who, 'alerts', sprintf('Channel %s (%s): %d kinds of alert%s', $name, FLEET_ALERT_TYPES[$type][0], count($events), ($report === null) ? '' : ", daily report at {$report}:00"));
	return $id;
}

function fleet_alert_channel_delete(int $id, string $who): void {
	$ch = fleet_alert_channel($id);
	fleet_db()->prepare('DELETE FROM alert_channels WHERE id = ?')->execute(array($id));
	fleet_audit($who, 'alerts', 'Channel ' . ($ch['name'] ?? $id) . ': deleted');
}

/* ------------------------------------------------------------------ */
/* Raising and sending                                                 */
/* ------------------------------------------------------------------ */

/*
 * Record an alert. The same event for the same firewall within 15
 * minutes is merged (counted, not sent again). Returns its id, or null
 * when merged.
 */
function fleet_alert(string $event, string $node, string $text, ?string $severity = null): ?int {
	if (!isset(FLEET_ALERT_EVENTS[$event])) {
		return null;
	}
	$severity = $severity ?? FLEET_ALERT_EVENTS[$event][1];
	$now = time();
	/* One firewall's repeats merge. An alert about no firewall (an enrollment, the copies) merges only with the same text, so two different ones are both sent. */
	$text = mb_substr($text, 0, 1000);
	$q = fleet_db()->prepare('SELECT id FROM alerts WHERE event = ? AND node_id = ? AND time > ? AND (node_id != ? OR text = ?) ORDER BY id DESC LIMIT 1');
	$q->execute(array($event, $node, $now - FLEET_ALERT_MERGE, '', $text));
	$same = $q->fetchColumn();
	if (($same !== false) && ($event !== 'test')) {
		fleet_db()->prepare('UPDATE alerts SET repeats = repeats + 1 WHERE id = ?')->execute(array((int)$same));
		return null;
	}
	fleet_db()->prepare('INSERT INTO alerts (time, event, severity, node_id, text, sent, tries) VALUES (?, ?, ?, ?, ?, ?, 0)')
	    ->execute(array($now, $event, $severity, $node, $text, '{}'));
	return (int)fleet_db()->lastInsertId();
}

/* Send one alert to one channel. Returns null or the problem. */
function fleet_alert_send(array $ch, array $a): ?string {
	$cfg = fleet_alert_config_open($ch);
	if ($ch['type'] === 'email') {
		if (!function_exists('send_smtp_message')) {
			require_once('notices.inc');
		}
		$r = send_smtp_message($a['title'] . "\n\n" . $a['text'] . (($a['link'] ?? '') !== '' ? "\n\n" . $a['link'] : ''), 'FreeSense Fleet: ' . $a['title'], true);
		return ($r === null) || ($r === true) || ($r === '') ? null : (is_string($r) ? $r : 'The e-mail was not sent (check System > Advanced > Notifications).');
	}
	$req = fleet_alert_request($ch['type'], $cfg, $a);
	if ($req === null) {
		return 'Unknown channel type.';
	}
	list($url, $headers, $body) = $req;
	if ((($cfg['pin'] ?? '') !== '') && (strncasecmp($url, 'https://', 8) === 0)) {
		return fleet_alert_send_pinned($url, $headers, $body, $cfg['pin']);
	}
	$c = curl_init($url);
	curl_setopt_array($c, array(CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_HTTPHEADER => $headers, CURLOPT_RETURNTRANSFER => true,
	    CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_TIMEOUT => 15, CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP));
	curl_exec($c);
	$code = (int)curl_getinfo($c, CURLINFO_RESPONSE_CODE);
	$err = curl_error($c);
	if (($code >= 200) && ($code < 300)) {
		return null;
	}
	/* Never echo the address: it may hold a token. */
	return ($code === 0) ? 'Could not connect (' . $err . ')' : "The service answered HTTP {$code}";
}

/*
 * Send to a receiver whose certificate is not publicly trusted: the TLS
 * handshake succeeds only when the receiver's certificate has this SHA-256
 * fingerprint (PHP checks it before anything is sent). Returns null or the
 * problem.
 */
function fleet_alert_send_pinned(string $url, array $headers, string $body, string $pin): ?string {
	$ctx = stream_context_create(array(
	    'http' => array('method' => 'POST', 'header' => implode("\r\n", $headers), 'content' => $body, 'timeout' => 15, 'ignore_errors' => true, 'follow_location' => 0),
	    'ssl' => array('verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true, 'peer_fingerprint' => array('sha256' => $pin))));
	$err = '';
	set_error_handler(function ($no, $msg) use (&$err) {
		$err = (string)$msg;
		return true;
	});
	try {
		$r = file_get_contents($url, false, $ctx);
	} finally {
		restore_error_handler();
	}
	/* PHP 8.4+: the response headers without the deprecated $http_response_header. */
	$hdrs = http_get_last_response_headers() ?? array();
	$code = (isset($hdrs[0]) && preg_match('~^HTTP/\S+\s+(\d{3})~', $hdrs[0], $m)) ? (int)$m[1] : 0;
	if (($r !== false) && ($code >= 200) && ($code < 300)) {
		return null;
	}
	if ($code !== 0) {
		return "The service answered HTTP {$code}";
	}
	/* PHP reports a fingerprint mismatch as an unknown connect error: read the certificate the receiver shows. Never echo the address: it may hold a token. */
	$seen = fleet_alert_peer_sha256($url);
	if (($seen !== null) && !hash_equals($pin, $seen)) {
		return 'The receiver\'s certificate does not match the trusted fingerprint (it shows ' . implode(':', str_split(strtoupper($seen), 2)) . ')';
	}
	return 'Could not connect' . (($err !== '') ? ' (' . preg_replace('~\S+://\S+~', 'the receiver', $err) . ')' : '');
}

/* The SHA-256 fingerprint (lower-case hex) of the certificate an https receiver shows, or null when it cannot be reached. Nothing is sent. */
function fleet_alert_peer_sha256(string $url): ?string {
	$p = parse_url($url);
	if (!isset($p['host'])) {
		return null;
	}
	$ctx = stream_context_create(array('ssl' => array('verify_peer' => false, 'verify_peer_name' => false, 'capture_peer_cert' => true,
	    'SNI_enabled' => true, 'peer_name' => trim($p['host'], '[]'))));
	$s = @stream_socket_client('ssl://' . $p['host'] . ':' . (int)($p['port'] ?? 443), $no, $msg, 5, STREAM_CLIENT_CONNECT, $ctx);
	if ($s === false) {
		return null;
	}
	$cert = stream_context_get_params($s)['options']['ssl']['peer_certificate'] ?? null;
	fclose($s);
	return ($cert !== null) ? (string)openssl_x509_fingerprint($cert, 'sha256') : null;
}

/* What an alert looks like when it is sent. */
function fleet_alert_message(array $row): array {
	$box = ($row['node_id'] !== '') ? fleet_box_get((string)$row['node_id']) : null;
	$title = FLEET_ALERT_EVENTS[$row['event']][0] . (($box !== null) ? ': ' . $box['label'] : '');
	$s = fleet_ctl_settings();
	$link = (($s['public_host'] ?? '') !== '') ? 'https://' . $s['public_host'] . '/fleet/' . (($box !== null) ? 'fleet_box.php?id=' . rawurlencode($box['node_id']) : 'fleet_dashboard.php') : '';
	return array('title' => $title, 'text' => (string)$row['text'], 'severity' => (string)$row['severity'], 'node' => (string)$row['node_id'],
	    'time' => gmdate('c', (int)$row['time']), 'event' => (string)$row['event'], 'link' => $link);
}

/*
 * pure: what each channel is to be sent now: channel id => array(digest, rows). A row is for a channel when
 * the channel wants its event and severity (and the row is not aimed at another channel) and it was not
 * sent there yet. More than $limit rows for one channel are sent as one summary, not one message each.
 */
function fleet_alerts_plan(array $rows, array $channels, int $limit): array {
	$plan = array();
	foreach ($channels as $ch) {
		$mine = array();
		foreach ($rows as $row) {
			$sent = json_decode((string)$row['sent'], true) ?: array();
			if ((($sent[(string)$ch['id']] ?? null) === 'ok') || ((($row['channel'] ?? null) !== null) && ((int)$row['channel'] !== (int)$ch['id'])) ||
			    !fleet_alert_wanted($ch, (string)$row['event'], (string)$row['severity'])) {
				continue;
			}
			$mine[] = $row;
		}
		if (!empty($mine)) {
			$plan[(int)$ch['id']] = array(count($mine) > $limit, $mine);
		}
	}
	return $plan;
}

/* pure: one message for many alerts (the worst severity, the first lines, how many more). */
function fleet_alerts_digest_message(array $rows, int $now): array {
	$worst = 'info';
	$lines = array();
	foreach ($rows as $row) {
		if ((FLEET_ALERT_SEVERITIES[$row['severity']] ?? 1) > (FLEET_ALERT_SEVERITIES[$worst] ?? 1)) {
			$worst = (string)$row['severity'];
		}
		if (count($lines) < 15) {
			$lines[] = '[' . $row['severity'] . '] ' . mb_substr((string)$row['text'], 0, 160);
		}
	}
	$more = count($rows) - count($lines);
	return array('title' => sprintf('%d alerts from FreeSense Fleet', count($rows)), 'text' => implode("\n", $lines) . (($more > 0) ? "\nand {$more} more. See Activity > Alerts." : ''),
	    'severity' => $worst, 'node' => '', 'time' => gmdate('c', $now), 'event' => 'digest', 'link' => '');
}

/* pure: when a failed alert may be tried again: 1, 2, 4, 8, ... minutes, at most an hour. $tries: how often it was tried. */
function fleet_alert_next_try(int $tries, int $now): int {
	return $now + min(3600, 60 * (2 ** min(10, $tries)));
}

/*
 * From the alert worker (every minute): send what is not sent yet. Alerts nobody ever tried to send and
 * that are older than FLEET_ALERT_MAX_AGE are dropped (no backlog for a new channel). A failed send is
 * tried again later and later, up to FLEET_ALERT_TRIES times; a burst goes out as one summary per
 * channel; and the whole run stops after FLEET_ALERT_BUDGET seconds so a dead webhook cannot hold it.
 */
function fleet_alerts_deliver(?int $now = null, float $budget = FLEET_ALERT_BUDGET): void {
	$now = $now ?? time();
	$db = fleet_db();
	$db->prepare("UPDATE alerts SET done = 1, sent = '{\"expired\":\"too old to send\"}' WHERE done = 0 AND tries = 0 AND time < ?")->execute(array($now - FLEET_ALERT_MAX_AGE));
	$channels = fleet_alert_channels();
	if (empty($channels)) {
		return;
	}
	$q = $db->prepare('SELECT * FROM alerts WHERE done = 0 AND tries < ? AND next_try <= ? ORDER BY id LIMIT 200');
	$q->execute(array(FLEET_ALERT_TRIES, $now));
	$rows = array_column($q->fetchAll(), null, 'id');
	if (empty($rows)) {
		return;
	}
	$start = microtime(true);
	$sent = array();
	foreach ($rows as $id => $row) {
		$sent[$id] = json_decode((string)$row['sent'], true) ?: array();
	}
	$attempted = array();
	$by_id = array_column($channels, null, 'id');
	foreach (fleet_alerts_plan($rows, $channels, FLEET_ALERT_DIGEST) as $cid => list($digest, $mine)) {
		$ch = $by_id[$cid];
		if ($digest) {
			if ((microtime(true) - $start) > $budget) {
				break;
			}
			$problem = fleet_alert_send($ch, fleet_alerts_digest_message($mine, $now));
			foreach ($mine as $row) {
				$sent[(int)$row['id']][(string)$cid] = ($problem === null) ? 'ok' : $problem;
				$attempted[(int)$row['id']] = true;
			}
			continue;
		}
		foreach ($mine as $row) {
			if ((microtime(true) - $start) > $budget) {
				break 2;
			}
			$problem = fleet_alert_send($ch, fleet_alert_message($row));
			$sent[(int)$row['id']][(string)$cid] = ($problem === null) ? 'ok' : $problem;
			$attempted[(int)$row['id']] = true;
		}
	}
	$up = $db->prepare('UPDATE alerts SET sent = ?, tries = tries + 1, done = ?, next_try = ? WHERE id = ?');
	foreach ($rows as $id => $row) {
		$wanted = fleet_alerts_plan(array(array('sent' => '{}') + $row), $channels, 1000);
		if (!isset($attempted[$id]) && !empty($wanted)) {
			continue;
		}
		$open = false;
		foreach (array_keys($wanted) as $cid) {
			$open = $open || (($sent[$id][(string)$cid] ?? null) !== 'ok');
		}
		$up->execute(array(json_encode($sent[$id]), $open ? 0 : 1, $open ? fleet_alert_next_try((int)$row['tries'], $now) : 0, $id));
	}
}

/* Send a test alert to one channel now; returns null or the problem. */
function fleet_alert_test(int $id, string $who): ?string {
	$ch = fleet_alert_channel($id);
	if ($ch === null) {
		return 'That channel no longer exists.';
	}
	$problem = fleet_alert_send(array('enabled' => 1) + $ch, array('title' => 'Test from FreeSense Fleet', 'text' => 'This channel works. Sent by ' . $who . '.',
	    'severity' => 'info', 'node' => '', 'time' => gmdate('c'), 'event' => 'test', 'link' => ''));
	fleet_audit($who, 'alerts', 'Test to ' . $ch['name'] . ': ' . ($problem ?? 'sent'));
	return $problem;
}

/* The daily reports that are due this hour (once a day per channel). */
function fleet_alerts_reports(int $now): void {
	$hour = (int)date('G', $now);
	foreach (fleet_alert_channels() as $ch) {
		if (empty($ch['enabled']) || ($ch['report_hour'] === null) || ((int)$ch['report_hour'] !== $hour) || (date('Y-m-d', (int)($ch['report_sent'] ?? 0)) === date('Y-m-d', $now))) {
			continue;
		}
		$c = fleet_alert_report_counts($now);
		$problem = fleet_alert_send($ch, array('title' => 'Daily fleet report', 'text' => fleet_alert_report_text($c), 'severity' => 'info', 'node' => '',
		    'time' => gmdate('c', $now), 'event' => 'report', 'link' => ''));
		if ($problem === null) {
			fleet_db()->prepare('UPDATE alert_channels SET report_sent = ? WHERE id = ?')->execute(array($now, (int)$ch['id']));
		}
	}
}

function fleet_alert_report_counts(int $now): array {
	$db = fleet_db();
	$st = $db->query('SELECT state, COUNT(*) FROM boxes GROUP BY state')->fetchAll(PDO::FETCH_KEY_PAIR);
	$since = $now - 86400;
	$one = function (string $sql) use ($db, $since) {
		$q = $db->prepare($sql);
		$q->execute(array($since));
		return (int)$q->fetchColumn();
	};
	$counts = fleet_compliance_counts();
	$pass = 0;
	$fail = 0;
	foreach ($counts as $c) {
		$pass += $c['pass'] + $c['excepted'];
		$fail += $c['fail'];
	}
	return array('boxes' => array_sum($st), 'online' => (int)($st['online'] ?? 0), 'degraded' => (int)($st['degraded'] ?? 0), 'offline' => (int)($st['offline'] ?? 0),
	    'ops' => $one('SELECT COUNT(*) FROM ops WHERE parent IS NULL AND started > ?'), 'ops_failed' => $one("SELECT COUNT(*) FROM ops WHERE parent IS NULL AND state = 'failed' AND started > ?"),
	    'backups' => $one('SELECT COUNT(*) FROM backups WHERE time > ?'), 'backups_failed' => $one("SELECT COUNT(*) FROM audit WHERE action = 'backup_failed' AND time > ?"),
	    'compliance' => ($pass + $fail > 0) ? (int)floor(100 * $pass / ($pass + $fail)) : null, 'alerts' => $one('SELECT COUNT(*) FROM alerts WHERE time > ?'));
}

/* The alert history for the page, newest first, filtered and paged. */
function fleet_alerts_find(array $f, int $page): array {
	$where = array('1 = 1');
	$args = array();
	if (isset($f['event'])) {
		$where[] = 'a.event = ?';
		$args[] = $f['event'];
	}
	if (isset($f['severity'])) {
		$where[] = 'a.severity = ?';
		$args[] = $f['severity'];
	}
	if (isset($f['q'])) {
		$where[] = "(a.text LIKE ? ESCAPE '\\' OR b.label LIKE ? ESCAPE '\\')";
		$args[] = fleet_list_like($f['q']);
		$args[] = fleet_list_like($f['q']);
	}
	$sql = ' FROM alerts a LEFT JOIN boxes b ON b.node_id = a.node_id WHERE ' . implode(' AND ', $where);
	$q = fleet_db()->prepare('SELECT COUNT(*)' . $sql);
	$q->execute($args);
	$pg = fleet_list_page((int)$q->fetchColumn(), $page);
	$q = fleet_db()->prepare('SELECT a.*, b.label' . $sql . ' ORDER BY a.id DESC LIMIT ' . (int)$pg['per'] . ' OFFSET ' . (int)$pg['offset']);
	$q->execute($args);
	return array($q->fetchAll(), $pg);
}

/* The views of the Activity tab. */
function fleet_activity_nav(string $current): string {
	$views = array('ops' => array(gettext('Operations'), '/fleet/fleet_activity.php'), 'alerts' => array(gettext('Alerts'), '/fleet/fleet_alerts.php'),
	    'channels' => array(gettext('Alert channels'), '/fleet/fleet_alerts.php?view=channels'));
	$h = '<nav class="fs-viewswitch" aria-label="' . htmlspecialchars(gettext('Activity')) . '">';
	foreach ($views as $k => list($label, $url)) {
		$h .= '<a href="' . $url . '"' . (($k === $current) ? ' aria-current="page"' : '') . '>' . htmlspecialchars($label) . '</a>';
	}
	return $h . '</nav>';
}
