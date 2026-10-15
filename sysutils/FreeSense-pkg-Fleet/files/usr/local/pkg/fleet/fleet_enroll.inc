<?php
/*
 * fleet_enroll.inc
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
 * The controller side of joining: invitations, and the four requests of the
 * enrollment endpoint (begin, enroll, status, complete). The proofs come from
 * the System's fleet_join.inc, so both sides run the same code.
 *
 * An invitation is a token id, a token secret (only its hash is kept) and a
 * join key (only the derived key material is kept, encrypted). A wrong token
 * secret is a plain 401 and never counts against the invitation, so someone
 * without the link cannot burn it; five wrong proofs burn it (E104).
 */

require_once('fleet_join.inc');
require_once('fleet/fleet_store.inc');

define('FLEET_INVITE_TTL_MAX', 30 * 86400);
define('FLEET_CHALLENGE_TTL', 300);
define('FLEET_ENROLL_PENDING_TTL', 3600);
define('FLEET_FIRST_HOST', 16);

/* pure: a label an admin typed for an invitation or box. */
function fleet_valid_label(string $label): bool {
	return ($label !== '') && (strlen($label) <= 80) && !preg_match('/[\x00-\x1f\x7f<>]/', $label);
}

/*
 * Create an invitation. Returns array(link, key as shown, token_id, expires).
 * The key is shown once and never stored.
 */
function fleet_invite_create(string $role, string $label, int $ttl, string $who, string $authority, int $now): array {
	if (!in_array($role, array('monitor', 'managed'), true)) {
		throw new InvalidArgumentException('Choose monitor or managed.');
	}
	if (!fleet_valid_label($label)) {
		throw new InvalidArgumentException('Give the box a label of up to 80 characters.');
	}
	if (($ttl < 3600) || ($ttl > FLEET_INVITE_TTL_MAX)) {
		throw new InvalidArgumentException('An invitation lasts from 1 hour to 30 days.');
	}
	if (!fleet_join_valid_authority($authority)) {
		throw new InvalidArgumentException('Set the address boxes use to reach this controller (host name or IP and port).');
	}
	$cert = fleet_cert_fingerprint(fleet_tls_pem());
	$token_id = bin2hex(random_bytes(6));
	$secret = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
	list($shown, $key_data) = fleet_join_key_generate();
	fleet_db()->prepare('INSERT INTO invitations (token_id, secret_hash, okm, role, label, created, expires, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
	    ->execute(array($token_id, hash('sha256', $secret), fleet_seal(fleet_join_okm($key_data, $cert), fleet_master_key()), $role, $label,
	    $now, $now + $ttl, $who));
	fleet_audit($who, 'invite', "{$token_id} {$role} \"{$label}\"");
	return array(fleet_join_link_build($authority, $token_id, $secret, $cert), $shown, $token_id, $now + $ttl);
}

function fleet_invite_revoke(string $token_id, string $who): bool {
	$st = fleet_db()->prepare("UPDATE invitations SET state = 'revoked' WHERE token_id = ? AND state = 'open'");
	$st->execute(array($token_id));
	if ($st->rowCount() > 0) {
		fleet_audit($who, 'revoke', $token_id);
		return true;
	}
	return false;
}

/* pure: a JSON error answer in the form the join client maps to FLEET codes. */
function fleet_enroll_error(int $status, string $code, string $message): array {
	return array($status, array('error' => array('code' => $code, 'message' => $message)));
}

/* The invitation a request may use: the token secret must match; 401 otherwise. */
function fleet_enroll_invitation(string $token_id, string $bearer, int $now): array {
	$st = fleet_db()->prepare('SELECT * FROM invitations WHERE token_id = ?');
	$st->execute(array($token_id));
	$inv = $st->fetch();
	if (!$inv || !hash_equals((string)$inv['secret_hash'], hash('sha256', $bearer))) {
		throw new FleetEnrollReply(fleet_enroll_error(401, 'unauthorized', 'Unknown invitation.'));
	}
	if ($inv['state'] === 'burned') {
		throw new FleetEnrollReply(fleet_enroll_error(410, 'invitation_burned', 'Too many wrong keys: this invitation is no longer valid.'));
	}
	if (($inv['state'] !== 'open') || ((int)$inv['expires'] < $now)) {
		throw new FleetEnrollReply(fleet_enroll_error(410, 'token_expired', 'The invitation has expired, was used or was revoked.'));
	}
	return $inv;
}

class FleetEnrollReply extends Exception {
	public $reply;

	public function __construct(array $reply) {
		parent::__construct('reply');
		$this->reply = $reply;
	}
}

/*
 * Handle one enrollment request. $ctx: controller_wg_pub (32 raw bytes),
 * endpoint ("host:port" of the controller's WireGuard), on_joined(box) to add
 * the peer. Returns array(HTTP status, JSON body).
 */
function fleet_enroll_handle(string $method, string $path, string $bearer, array $body, string $ip, int $now, array $ctx): array {
	try {
		if (($method === 'POST') && ($path === '/fleet/join/begin')) {
			$inv = fleet_enroll_invitation((string)($body['token_id'] ?? ''), $bearer, $now);
			$challenge = random_bytes(32);
			fleet_db()->prepare('UPDATE invitations SET challenge = ?, challenge_time = ? WHERE token_id = ?')
			    ->execute(array(base64_encode($challenge), $now, $inv['token_id']));
			return array(200, array('challenge' => base64_encode($challenge), 'controller_wg_pub' => base64_encode($ctx['controller_wg_pub']),
			    'time' => $now, 'role' => $inv['role']));
		}
		if (($method === 'POST') && ($path === '/fleet/join/enroll')) {
			return fleet_enroll_enroll($body, $bearer, $ip, $now, $ctx);
		}
		if (($method === 'GET') && preg_match('#^/fleet/join/status/(e-[0-9a-z]{16,40})$#D', $path, $m)) {
			$e = fleet_enroll_get($m[1], $bearer, $now);
			if (($e['state'] === 'pending') && ((int)$e['created'] + FLEET_ENROLL_PENDING_TTL < $now)) {
				return fleet_enroll_error(410, 'token_expired', 'Nobody approved this box in time.');
			}
			return array(200, array('state' => $e['state']));
		}
		if (($method === 'POST') && ($path === '/fleet/join/complete')) {
			return fleet_enroll_complete($body, $bearer, $now, $ctx);
		}
		return fleet_enroll_error(404, 'not_found', 'No such enrollment request.');
	} catch (FleetEnrollReply $r) {
		return $r->reply;
	}
}

function fleet_enroll_enroll(array $body, string $bearer, string $ip, int $now, array $ctx): array {
	$inv = fleet_enroll_invitation((string)($body['token_id'] ?? ''), $bearer, $now);
	$challenge = base64_decode((string)$inv['challenge'], true);
	$nonce = base64_decode((string)($body['nonce'] ?? ''), true);
	$node_pub = base64_decode((string)($body['node_wg_pub'] ?? ''), true);
	if (($challenge === false) || ((int)$inv['challenge_time'] + FLEET_CHALLENGE_TTL < $now)) {
		return fleet_enroll_error(409, 'no_challenge', 'Start again: the challenge expired.');
	}
	if (($nonce === false) || (strlen($nonce) !== 32) || ($node_pub === false) || (strlen($node_pub) !== 32)) {
		return fleet_enroll_error(400, 'invalid_request', 'nonce and node_wg_pub must be 32 bytes, base64.');
	}
	/* A challenge is used once, right or wrong. */
	fleet_db()->prepare('UPDATE invitations SET challenge = NULL WHERE token_id = ?')->execute(array($inv['token_id']));
	$okm = fleet_unseal((string)$inv['okm'], fleet_master_key());
	$cert = fleet_cert_fingerprint(fleet_tls_pem());
	$want = fleet_join_proof((string)$okm, $challenge, $nonce, $inv['token_id'], $node_pub, $cert);
	if (($okm === null) || !hash_equals($want, (string)($body['proof'] ?? ''))) {
		$failures = (int)$inv['failures'] + 1;
		$burned = $failures >= fleet_opt('invite_failures');
		fleet_db()->prepare('UPDATE invitations SET failures = ?, state = ? WHERE token_id = ?')
		    ->execute(array($failures, $burned ? 'burned' : 'open', $inv['token_id']));
		fleet_audit('enrollment', $burned ? 'burned' : 'bad_proof', "{$inv['token_id']} from {$ip} ({$failures})");
		return $burned ? fleet_enroll_error(410, 'invitation_burned', 'Too many wrong keys: this invitation is no longer valid.') :
		    fleet_enroll_error(403, 'bad_proof', 'The join key is wrong.');
	}
	$inventory = is_array($body['inventory'] ?? null) ? $body['inventory'] : array();
	$id = 'e-' . bin2hex(random_bytes(10));
	$code = fleet_join_code($node_pub, $ctx['controller_wg_pub'], $challenge, $nonce);
	fleet_db()->prepare('INSERT INTO enrollments (id, token_id, node_wg_pub, inventory, code, created, source_ip) VALUES (?, ?, ?, ?, ?, ?, ?)')
	    ->execute(array($id, $inv['token_id'], base64_encode($node_pub), json_encode($inventory), $code, $now, $ip));
	fleet_audit('enrollment', 'pending', "{$id} for {$inv['token_id']} from {$ip}, code {$code}");
	return array(200, array('enrollment_id' => $id));
}

function fleet_enroll_get(string $id, string $bearer, int $now): array {
	$st = fleet_db()->prepare('SELECT e.*, i.secret_hash, i.role, i.label FROM enrollments e JOIN invitations i ON i.token_id = e.token_id WHERE e.id = ?');
	$st->execute(array($id));
	$e = $st->fetch();
	if (!$e || !hash_equals((string)$e['secret_hash'], hash('sha256', $bearer))) {
		throw new FleetEnrollReply(fleet_enroll_error(401, 'unauthorized', 'Unknown enrollment.'));
	}
	return $e;
}

/* An admin approves or rejects a pending box (after comparing the code). */
function fleet_enroll_decide(string $id, bool $approve, string $who, int $now): bool {
	$st = fleet_db()->prepare("UPDATE enrollments SET state = ?, decided_by = ?, decided = ? WHERE id = ? AND state = 'pending'");
	$st->execute(array($approve ? 'approved' : 'rejected', $who, $now, $id));
	if ($st->rowCount() === 0) {
		return false;
	}
	fleet_audit($who, $approve ? 'approve' : 'reject', $id);
	return true;
}

function fleet_enroll_complete(array $body, string $bearer, int $now, array $ctx): array {
	$e = fleet_enroll_get((string)($body['enrollment_id'] ?? ''), $bearer, $now);
	if ($e['state'] !== 'approved') {
		return fleet_enroll_error(409, 'not_approved', 'This box has not been approved.');
	}
	$api_key = (string)($body['api_key'] ?? '');
	$cert = strtolower((string)($body['node_cert_sha256'] ?? ''));
	$inv = fleet_enroll_invitation((string)$e['token_id'], $bearer, $now);
	$okm = (string)fleet_unseal((string)$inv['okm'], fleet_master_key());
	if (!preg_match('/^fsk_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$/D', $api_key) || !preg_match('/^[0-9a-f]{64}$/D', $cert) ||
	    !hash_equals(fleet_join_complete_proof($okm, $e['id'], $api_key), (string)($body['proof'] ?? ''))) {
		return fleet_enroll_error(403, 'bad_proof', 'The completion proof is wrong.');
	}
	$db = fleet_db();
	$db->exec('BEGIN IMMEDIATE');
	try {
		$host = max(FLEET_FIRST_HOST, (int)$db->query('SELECT COALESCE(MAX(host_no), 0) + 1 FROM boxes')->fetchColumn());
		$prefix = (string)fleet_setting('overlay_prefix');
		$node_id = 'node-' . bin2hex(random_bytes(8));
		$inventory = json_decode((string)$e['inventory'], true) ?: array();
		$box = array('node_id' => $node_id, 'name' => (string)($inventory['hostname'] ?? $inv['label']), 'label' => $inv['label'],
		    'host_no' => $host, 'overlay' => fleet_overlay_host($prefix, $host), 'wg_pub' => $e['node_wg_pub'], 'role' => $inv['role']);
		$db->prepare('INSERT INTO boxes (node_id, name, label, host_no, overlay, wg_pub, api_key, cert_sha256, role, joined) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
		    ->execute(array($node_id, $box['name'], $box['label'], $host, $box['overlay'], $box['wg_pub'], fleet_seal($api_key, fleet_master_key()),
		    $cert, $box['role'], $now));
		$db->prepare("UPDATE invitations SET state = 'used', okm = '' WHERE token_id = ?")->execute(array($inv['token_id']));
		$db->prepare("UPDATE enrollments SET state = 'joined' WHERE id = ?")->execute(array($e['id']));
		$db->exec('COMMIT');
	} catch (Throwable $t) {
		$db->exec('ROLLBACK');
		throw $t;
	}
	fleet_audit('enrollment', 'joined', "{$node_id} ({$box['label']}) at {$box['overlay']}");
	$ctx['on_joined']($box);
	return array(200, array('node_id' => $node_id, 'signing_key' => fleet_signing_public(), 'method' => 'wireguard',
	    'overlay_address' => $box['overlay'], 'role' => $box['role'], 'hostname' => '',
	    'peers' => array(array('public_key' => base64_encode($ctx['controller_wg_pub']), 'endpoint' => $ctx['endpoint'],
	    'allowed_ips' => array(fleet_overlay_host($prefix, 1) . '/128')))));
}
