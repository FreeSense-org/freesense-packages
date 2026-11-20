<?php
/* Fleet controller tests: invitations. Loaded by ../run.php (shares its variables). */

$now = 1760000000;
$bad = function (callable $fn) {
	try {
		$fn();
	} catch (InvalidArgumentException $e) {
		return true;
	}
	return false;
};
check($bad(function () use ($now) { fleet_invite_create('root', 'x', 86400, 'admin', 'hq:8443', $now); }) &&
    $bad(function () use ($now) { fleet_invite_create('monitor', '', 86400, 'admin', 'hq:8443', $now); }) &&
    $bad(function () use ($now) { fleet_invite_create('monitor', 'x', 60, 'admin', 'hq:8443', $now); }) &&
    $bad(function () use ($now) { fleet_invite_create('monitor', 'x', 86400, 'admin', 'bad host:x', $now); }), 'invalid invitations are refused');
list($link, $key, $tid) = fleet_invite_create('managed', 'Copenhagen office', 86400, 'admin', 'hq.example.net:8443', $now);
$parsed = fleet_invite_link_parse($link);
check($parsed['cert_sha256'] === $fp && $parsed['token_id'] === $tid && ($parsed['method'] === 'tunnel') && (substr($link, -2) === '.t'), 'the link pins the enrollment certificate and says how the firewall connects');
$lv = fleet_invite_link_build('hq:8443', 'aabbccddeeff', str_repeat('A', 43), str_repeat('AB', 32), 'tailscale', str_repeat('x', 80));
check(($lv === 'https://hq:8443/fleet/join#aabbccddeeff.' . str_repeat('A', 43) . '.' . str_repeat('ab', 32) . '.s.' . str_repeat('x', 80)) &&
    (fleet_invite_link_parse($lv)['ts'] === str_repeat('x', 80)) && (fleet_invite_link_parse($lv)['method'] === 'tailscale') &&
    (fleet_invite_link_parse(fleet_invite_link_build('hq', 'aabbccddeeff', str_repeat('A', 43), str_repeat('ab', 32), 'direct'))['port'] === 443) &&
    (fleet_invite_link_parse('https://hq:8443/fleet/join#aabbccddeeff.' . str_repeat('A', 43) . '.' . str_repeat('ab', 32)) === null) &&
    (fleet_invite_link_parse('https://hq:8443/fleet/join#aabbccddeeff.' . str_repeat('A', 43) . '.' . str_repeat('ab', 32) . '.t.' . str_repeat('x', 80)) === null),
    'join links v2: method t, s or d; only a Tailscale link carries a sealed key; links without a method are refused');
/* Test vector shared with System's join client (fleet_join.inc): same inputs, same blob. */
$tvk = fleet_join_key_normalize('FLT-4CDG-SEP1-HMVV-MF7V-JNWN');
$tvb = fleet_invite_ts_seal('tskey-auth-TEST', (string)$tvk, str_repeat("\x01", 16), str_repeat("\x02", 12));
check(($tvk !== null) && (fleet_invite_ts_open($tvb, $tvk) === 'tskey-auth-TEST') && (fleet_invite_ts_open($tvb, 'WRONGKEYDATA') === null) &&
    (strlen(base64_decode(strtr($tvb, '-_', '+/'))) === 44 + strlen('tskey-auth-TEST')) && (fleet_invite_ts_open('abc', $tvk) === null),
    'the Tailscale key is sealed to the join key (salt 16, nonce 12, tag 16, data; base64url)');
if (function_exists('fleet_seal_with_key')) {
	check(($tvb === fleet_seal_with_key('tskey-auth-TEST', 'FLT-4CDG-SEP1-HMVV-MF7V-JNWN', str_repeat("", 16), str_repeat("", 12))) &&
	    (fleet_unseal_with_key($tvb, 'FLT-4CDG-SEP1-HMVV-MF7V-JNWN') === 'tskey-auth-TEST') && (fleet_join_link_parse($lv)['ts_sealed'] === str_repeat('x', 80)),
	    'the controller seals exactly as the System join client unseals (shared test vector), and System reads v2 links');
}
check(fleet_invite_paste('https://x/fleet/join#a', 'FLT-1') === "FreeSense Fleet invitation\nhttps://x/fleet/join#a\nKey: FLT-1", 'one text to paste: link and key');
$row = fleet_db()->query("SELECT * FROM invitations WHERE token_id = '{$tid}'")->fetch();
check(strpos(json_encode($row), $parsed['token_secret']) === false && strpos(json_encode($row), str_replace('-', '', substr($key, 4))) === false,
    'neither the token secret nor the join key is stored');
