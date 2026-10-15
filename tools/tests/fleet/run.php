<?php
/*
 * FreeSense Fleet controller tests, including the integration of both sides:
 * the System's join client (freesense-src/src/etc/inc/fleet_join.inc) joins
 * through this package's enrollment server with a real SQLite store.
 * Run: php tools/tests/fleet/run.php [path to the freesense checkout]
 */

$repo = dirname(__DIR__, 3);
$src = $argv[1] ?? (is_dir("{$repo}/freesense-src") ? "{$repo}/freesense-src" : dirname($repo) . '/freesense');
$data = sys_get_temp_dir() . '/fleet-test-' . getmypid();
mkdir($data, 0700);
putenv("FLEET_DATA={$data}");
set_include_path("{$src}/src/etc/inc" . PATH_SEPARATOR . "{$repo}/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg");
function gettext($t) { return $t; }
require_once('fleet.inc');

function check($condition, $message) {
	if (!$condition) {
		fwrite(STDERR, "FAIL: {$message}\n");
		exit(1);
	}
}
register_shutdown_function(function () use ($data) {
	foreach (glob("{$data}/*") ?: array() as $f) {
		@unlink($f);
	}
	@rmdir($data);
});

/* ---- pure helpers ---- */
check(fleet_unseal(fleet_seal('secret', str_repeat('k', 32)), str_repeat('k', 32)) === 'secret', 'seal round-trip');
check(fleet_unseal(fleet_seal('secret', str_repeat('k', 32)), str_repeat('x', 32)) === null && fleet_unseal('junk', str_repeat('k', 32)) === null,
    'a wrong master key or junk opens nothing');
$ov = fleet_random_overlay();
check(preg_match('/^fd[0-9a-f]{2}:[0-9a-f]{4}:[0-9a-f]{4}:f1::\/64$/D', $ov) === 1 && fleet_random_overlay() !== $ov, 'a random ULA /64');
check(fleet_overlay_host('fd12:3456:789a:f1::/64', 1) === 'fd12:3456:789a:f1::1' && fleet_overlay_host('fd12:3456:789a:f1::/64', 16) === 'fd12:3456:789a:f1::10',
    'overlay host addresses');
$s = fleet_ctl_settings_from(array('enable' => 'on', 'public_host' => ' hq.example.net ', 'enroll_port' => '99999'));
check($s === array('enable' => true, 'public_host' => 'hq.example.net', 'enroll_port' => 8443, 'wg_port' => 51830), 'settings with defaults');
check(fleet_ctl_settings_from(array())['enable'] === false, 'off by default');
check(fleet_hostport('fd12::1', 8443) === '[fd12::1]:8443' && fleet_hostport('hq', 1) === 'hq:1', 'host:port');
$rules = fleet_ctl_filter_rules(fleet_ctl_settings_from(array('enable' => 'on', 'enroll_port' => '9443', 'wg_port' => '51999')));
check(strpos($rules, 'proto tcp from any to (self) port 9443') !== false && strpos($rules, 'proto udp from any to (self) port 51999') !== false &&
    strpos($rules, 'wgfctl0') === false, 'pass rules for both ports');
$early = fleet_ctl_early_rules(fleet_ctl_settings_from(array('enable' => 'on')));
check(strpos($early, 'pass in quick on wgfctl0') !== false && strpos($early, 'pass out quick on wgfctl0') !== false &&
    fleet_ctl_early_rules(fleet_ctl_settings_from(array())) === '',
    'overlay rules in both directions, as early rules (they must come before "Block all IPv6")');
check(fleet_ctl_filter_rules(fleet_ctl_settings_from(array())) === '', 'no rules while off');
$conf = fleet_enroll_nginx_conf(8443, '/fleet/tls.pem');
check(strpos($conf, 'location ^~ /fleet/join/') !== false && strpos($conf, "return 404") !== false && strpos($conf, 'limit_req zone=fleetjoin') !== false &&
    strpos($conf, 'pid /var/run/fleet-enroll.pid;') !== false && !preg_match('#pid /var/run/nginx[^;]*\.pid#', $conf),
    'the enrollment nginx serves only /fleet/join/, rate-limited, with a pid file rc.restart_webgui does not kill');
check(fleet_box_state(0) === 'online' && fleet_box_state(3) === 'degraded' && fleet_box_state(10) === 'offline', 'missed polls');
check(fleet_valid_label('Copenhagen office') && !fleet_valid_label('') && !fleet_valid_label('<b>') && !fleet_valid_label(str_repeat('x', 81)), 'labels');

/* ---- controller init ---- */
fleet_controller_init();
check(is_file("{$data}/master.key") && (fileperms("{$data}/master.key") & 0077) === 0 && strlen(fleet_master_key()) === 32, 'a private master key');
$fp = fleet_cert_fingerprint(fleet_tls_pem());
check(preg_match('/^[0-9a-f]{64}$/D', $fp) === 1, 'an enrollment certificate');
fleet_controller_init();
check(fleet_cert_fingerprint(fleet_tls_pem()) === $fp, 'init is idempotent: the pinned certificate never changes');
check(strpos(fleet_signing_public(), 'BEGIN PUBLIC KEY') !== false, 'a signing key');

/* ---- invitations ---- */
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
$parsed = fleet_join_link_parse($link);
check($parsed['cert_sha256'] === $fp && $parsed['token_id'] === $tid, 'the link pins the enrollment certificate');
$row = fleet_db()->query("SELECT * FROM invitations WHERE token_id = '{$tid}'")->fetch();
check(strpos(json_encode($row), $parsed['token_secret']) === false && strpos(json_encode($row), str_replace('-', '', substr($key, 4))) === false,
    'neither the token secret nor the join key is stored');

/* ---- the System's join client against this enrollment server ---- */
$ctl_pub = random_bytes(32);
$joined = array();
$ctx = array('controller_wg_pub' => $ctl_pub, 'endpoint' => 'hq.example.net:51830', 'on_joined' => function ($box) use (&$joined) { $joined[] = $box; });
$clock = $now;
$approve_after_polls = 1;
$io = function (array &$events, array &$undone, ?string $bearer_override = null) use (&$clock, $ctx, &$approve_after_polls) {
	$polls = 0;
	$server = function ($method, $path, $body, $bearer) use (&$clock, $ctx, &$polls, &$approve_after_polls) {
		if (($method === 'GET') && (++$polls > $approve_after_polls)) {
			$id = substr($path, strlen('/fleet/join/status/'));
			fleet_enroll_decide($id, true, 'admin', $clock);
		}
		return fleet_enroll_handle($method, $path, $bearer, (array)$body, '198.51.100.7', $clock, $ctx);
	};
	return array(
		'post' => function ($p, $b, $bearer) use ($server, $bearer_override) { return $server('POST', $p, $b, $bearer_override ?? $bearer); },
		'get' => function ($p, $bearer) use ($server, $bearer_override) { return $server('GET', $p, null, $bearer_override ?? $bearer); },
		'wg_keypair' => function () { return array('NODE-PRIVATE', random_bytes(32)); },
		'clock' => function () use (&$clock) { return $clock; },
		'create_access' => function ($role) use (&$undone, &$events) {
			$events[] = "role:{$role}";
			return array('fsk_0123456789ab_' . str_repeat('B', 43), function () use (&$undone) { $undone[] = 'access'; },
			    array('cert_sha256' => str_repeat('c', 64), 'certref' => 'r1'));
		},
		'apply' => function ($m) use (&$events) { $events[] = 'apply'; return function () {}; },
		'inventory' => function () { return array('hostname' => 'edge01', 'version' => '1.2.0-DEVELOPMENT', 'serial' => 'S1'); },
		'step' => function ($n, $st, $t) use (&$events) { $events[] = "{$n}:{$st}" . (($t !== '') ? ":{$t}" : ''); },
		'sleep' => function ($s) use (&$clock) { $clock += $s; },
	);
};
$join_error = function (array $link, string $key, array $io) {
	try {
		fleet_join_run($link, fleet_join_key_normalize($key), $io);
	} catch (FleetJoinError $e) {
		return $e->fleet_code;
	}
	return null;
};

/* wrong key: E103, counted */
list($other_key) = fleet_join_key_generate();
$ev = array();
$un = array();
check($join_error($parsed, $other_key, $io($ev, $un)) === 'E103', 'a wrong key is E103 from the real server');
check((int)fleet_db()->query("SELECT failures FROM invitations WHERE token_id = '{$tid}'")->fetchColumn() === 1, 'and counts against the invitation');

/* a wrong token secret is a 401 that does not count */
$ev = array();
check($join_error($parsed, $key, $io($ev, $un, str_repeat('Z', 43))) === 'E103', 'a wrong token secret is refused');
check((int)fleet_db()->query("SELECT failures FROM invitations WHERE token_id = '{$tid}'")->fetchColumn() === 1, 'without counting (nobody can burn an invitation without the link)');

/* the real join */
$ev = array();
$un = array();
$m = fleet_join_run($parsed, fleet_join_key_normalize($key), $io($ev, $un));
$box = fleet_db()->query('SELECT * FROM boxes')->fetch();
$prefix = fleet_setting('overlay_prefix');
check($m['node_id'] === $box['node_id'] && $m['overlay_address'] === fleet_overlay_host($prefix, 16) && $m['role'] === 'managed' &&
    $m['controller_signing_key'] === fleet_signing_public(), 'the box joins with a node id, overlay address, role and signing key');
check(count($m['peers']) === 1 && $m['peers'][0]['allowed_ips'] === array(fleet_overlay_host($prefix, 1) . '/128') &&
    $m['peers'][0]['endpoint'] === 'hq.example.net:51830' && base64_decode($m['peers'][0]['public_key']) === $ctl_pub, 'the controller is the box\'s only peer');
check(count($joined) === 1 && $joined[0]['overlay'] === $box['overlay'], 'the controller adds the box as a peer');
check($box['label'] === 'Copenhagen office' && $box['name'] === 'edge01' && $box['cert_sha256'] === str_repeat('c', 64) &&
    fleet_unseal($box['api_key'], fleet_master_key()) === 'fsk_0123456789ab_' . str_repeat('B', 43) && strpos($box['api_key'], 'fsk_') === false,
    'the box record: label, name, pinned certificate, and the API key encrypted');
check(in_array('role:managed', $ev, true) && count(preg_grep('/^approval:wait:\d{6}$/', $ev)) === 1, 'the role reaches the box; the code is shown');
$enr = fleet_db()->query('SELECT * FROM enrollments WHERE state = \'joined\'')->fetch();
check(in_array("approval:wait:{$enr['code']}", $ev, true), 'the box and the controller show the same code');
check(fleet_db()->query("SELECT state FROM invitations WHERE token_id = '{$tid}'")->fetchColumn() === 'used' &&
    fleet_db()->query("SELECT okm FROM invitations WHERE token_id = '{$tid}'")->fetchColumn() === '', 'the invitation is used up and its key material deleted');

/* the link cannot be used again */
$ev = array();
check($join_error($parsed, $key, $io($ev, $un)) === 'E102', 'a used link is E102');

/* burning: 5 wrong proofs */
list($link2, $key2, $tid2) = fleet_invite_create('monitor', 'Branch', 86400, 'admin', 'hq.example.net:8443', $now);
$p2 = fleet_join_link_parse($link2);
for ($i = 1; $i <= 5; $i++) {
	list($wk) = fleet_join_key_generate();
	$ev = array();
	$code = $join_error($p2, $wk, $io($ev, $un));
}
check($code === 'E104', 'the fifth wrong key burns the invitation (E104)');
$ev = array();
check($join_error($p2, $key2, $io($ev, $un)) === 'E104', 'even the right key no longer works');

/* rejection and expiry */
list($link3, $key3, $tid3) = fleet_invite_create('monitor', 'Rejected', 86400, 'admin', 'hq.example.net:8443', $now);
$approve_after_polls = 1000;
$ev = array();
$un = array();
$p3 = fleet_join_link_parse($link3);
$io3 = $io($ev, $un);
$io3['sleep'] = function ($s) use (&$clock) {
	$clock += $s;
	$id = fleet_db()->query("SELECT id FROM enrollments WHERE state = 'pending'")->fetchColumn();
	if ($id) {
		fleet_enroll_decide($id, false, 'admin', $clock);
	}
};
check($join_error($p3, $key3, $io3) === 'E103' && $un === array(), 'a rejected box gets an error and changes nothing');
list($link4, $key4) = fleet_invite_create('monitor', 'Late', 3600, 'admin', 'hq.example.net:8443', $now);
$clock = $now + 7200;
$ev = array();
check($join_error(fleet_join_link_parse($link4), $key4, $io($ev, $un)) === 'E102', 'an expired invitation is E102');

$audit = fleet_db()->query('SELECT action FROM audit')->fetchAll(PDO::FETCH_COLUMN);
foreach (array('invite', 'bad_proof', 'burned', 'pending', 'approve', 'reject', 'joined') as $a) {
	check(in_array($a, $audit, true), "audited: {$a}");
}

/* ---- dashboard data ---- */
$row = function ($id, $label, $state, $status = array(), $error = '') {
	return array('node_id' => $id, 'name' => $id, 'label' => $label, 'overlay' => 'fd00::10', 'role' => 'managed', 'state' => $state,
	    'last_seen' => 100, 'error' => $error, 'status' => json_encode($status), 'api_key' => 'fsk_SECRET');
};
$dash = fleet_dashboard_data(array($row('n1', 'Zeta', 'online', array('hostname' => 'z.lab', 'version' => '1.1.5-RELEASE', 'rollback_protection' => true)),
    $row('n2', 'alpha', 'online', array('rollback_protection' => false)), $row('n3', 'Beta', 'offline', array(), 'FLEET-E105: down'),
    $row('n4', 'Gamma', 'degraded')), 2, 200);
check(array_column($dash['boxes'], 'label') === array('Beta', 'Gamma', 'alpha', 'Zeta'), 'worst state first, then by label');
check($dash['headline'] === '2 of 4 firewalls need attention' && $dash['counts']['online'] === 2 && $dash['counts']['unprotected'] === 1 &&
    $dash['counts']['pending'] === 2 && $dash['checked'] === 100, 'counts and headline');
check($dash['boxes'][0]['problem'] === 'FLEET-E105: down' && $dash['boxes'][3]['problem'] === '' && $dash['boxes'][3]['host'] === 'z.lab' &&
    $dash['boxes'][3]['rollback'] === true && $dash['boxes'][2]['rollback'] === false && $dash['boxes'][1]['rollback'] === null, 'per-box facts');
check(strpos(json_encode($dash), 'SECRET') === false, 'no API key reaches the dashboard');
check(fleet_dashboard_data(array(), 0, 1)['headline'] === 'No firewalls yet' &&
    fleet_dashboard_data(array($row('n1', 'A', 'online')), 0, 1)['headline'] === 'The firewall is online' &&
    fleet_dashboard_data(array($row('n1', 'A', 'online'), $row('n2', 'B', 'online')), 0, 1)['headline'] === 'All 2 firewalls are online', 'headlines');

check(fleet_poll_problem('E105', 'hq is unreachable (No route to host). Check the address.') === 'FLEET-E105: The box did not answer over the tunnel (No route to host). Check that it is powered on and online.' && fleet_poll_problem('E999', 'x') === 'FLEET-E999: x', 'poll problems speak from the controller side');
/* ---- Open WebUI ---- */
$tok = str_repeat('a', 43);
$st = array('webgui' => array(array('name' => 'LAN', 'url' => 'https://192.168.1.1')));
check(fleet_handoff_url($st, 'https://192.168.1.1', "/?fleet_handoff={$tok}") === "https://192.168.1.1/?fleet_handoff={$tok}", 'a reported address and a handoff path');
check(fleet_handoff_url($st, 'https://evil.example', "/?fleet_handoff={$tok}") === null && fleet_handoff_url(array(), 'https://192.168.1.1', "/?fleet_handoff={$tok}") === null,
    'never an address the box did not report (no open redirect)');
check(fleet_handoff_url($st, 'https://192.168.1.1', '//evil.example/') === null && fleet_handoff_url($st, 'https://192.168.1.1', "/?fleet_handoff={$tok}&x=1") === null,
    'only a handoff path');
check(fleet_box_target(array('overlay' => 'fd00::10', 'cert_sha256' => 'ab'))['authority'] === '[fd00::10]:8444', 'the box API over the tunnel');
$privs = file_get_contents(__DIR__ . '/../../../sysutils/FreeSense-pkg-Fleet/files/etc/inc/priv/fleet.priv.inc');
check(strpos($privs, "'page-status-fleet-dashboard'") !== false && strpos($privs, 'fleet/fleet_box.php*') !== false, 'a read-only privilege for the dashboard and box pages');

check(fleet_event_text('node-1', 'joined', 'node-1 (Lab) at fd00::10') === array('Joined the fleet', 'tunnel address fd00::10') &&
    fleet_event_text('node-1', 'state', 'node-1 (Lab): online -> degraded (FLEET-E105: x)') === array('Online to degraded', 'FLEET-E105: x') &&
    fleet_event_text('node-1', 'state', 'node-1 (Lab): degraded -> online') === array('Degraded to online', '') &&
    fleet_event_text('node-1', 'handoff', 'node-1 (Lab): WebUI as admin via https://192.0.2.1') === array('Opened the WebUI', 'as admin via https://192.0.2.1'),
    'event lines without the box\'s own ID');
check(fleet_event_text('node-1', 'backup', 'node-1 (Lab): Nightly, 0123456789ab') === array('Backed up', 'Nightly') &&
    fleet_event_text('node-1', 'backup', 'node-1 (Lab): Backed up by hand, 0123456789ab') === array('Backed up', 'by hand') &&
    fleet_event_text('node-1', 'backup_failed', 'node-1 (Lab): FLEET-E105: x') === array('Backup failed', 'FLEET-E105: x') &&
    fleet_event_text('node-1', 'backup_download', 'node-1 (Lab): backup of 2026-10-15 20:28') === array('Downloaded a backup', 'from 2026-10-15 20:28'),
    'backup events in words');

/* ---- backups ---- */
$conf = "<?xml version=\"1.0\"?>\n<freesense>\n\t<version>24.5</version>\n\t<system><hostname>lab</hostname></system>\n" .
    "\t<revision><time>1760000000</time><description><![CDATA[admin@192.0.2.1 (Local Database): Firewall rules changed]]></description></revision>\n</freesense>\n";
check(fleet_backup_problem($conf) === null && fleet_backup_problem('') !== null && fleet_backup_problem('<html></html>') !== null &&
    fleet_backup_problem('<freesense><version>1</version>') !== null, 'only a whole FreeSense configuration is a backup');
check(fleet_backup_meta($conf) === array('config_time' => 1760000000, 'description' => 'admin@192.0.2.1 (Local Database): Firewall rules changed', 'version' => '24.5'),
    'when, why and which config version');
$sha = hash('sha256', $conf);
$st = array('config_revision' => array('sha256' => $sha, 'time' => 1000));
check(fleet_backup_due(null, $st, 1000 + FLEET_BACKUP_QUIET) && !fleet_backup_due(null, $st, 1000 + FLEET_BACKUP_QUIET - 1),
    'a new configuration is backed up after it has been quiet for a while');
check(!fleet_backup_due(array('sha256' => $sha), $st, 99999) && !fleet_backup_due(null, array(), 99999), 'an unchanged configuration is not');
check(fleet_backup_file('node-1/../x', 1760000000, $sha) === 'node-1x/20251009-085320-' . substr($sha, 0, 12) . '.xml.enc', 'file names stay inside the backup directory');
$bbox = array('node_id' => 'node-bk', 'label' => 'Backup test');
list($r1, $row1) = fleet_backup_store($bbox, $conf, 'manual', 'tester', 1760000100);
list($r2) = fleet_backup_store($bbox, $conf, 'nightly', 'schedule', 1760000200);
check($r1 === 'stored' && $r2 === 'unchanged' && count(fleet_backup_list('node-bk')) === 1, 'stored once; the same configuration again is not stored twice');
check(fleet_backup_read(fleet_backup_get($row1['id'])) === $conf, 'a backup reads back exactly');
check(strpos((string)file_get_contents(FLEET_BACKUP_DIR . '/' . $row1['file']), 'hostname') === false && (fileperms(FLEET_BACKUP_DIR . '/' . $row1['file']) & 0077) === 0,
    'the file is encrypted and only root can read it');
$conf2 = str_replace('<hostname>lab</hostname>', '<hostname>lab2</hostname>', $conf);
list($r3, $row3) = fleet_backup_store($bbox, $conf2, 'change', 'system', 1760000300);
check($r3 === 'stored' && fleet_backup_latest('node-bk')['id'] === $row3['id'], 'a changed configuration is a new backup');
try {
	fleet_backup_store($bbox, '<html/>', 'manual', 'tester', 1760000400);
	check(false, 'junk is refused');
} catch (RuntimeException $e) {
	check(count(fleet_backup_list('node-bk')) === 2, 'junk is refused and nothing is stored');
}
file_put_contents(FLEET_BACKUP_DIR . '/' . $row3['file'], 'v1:damaged');
check(fleet_backup_read(fleet_backup_get($row3['id'])) === null, 'a damaged file is noticed (E802)');
check(fleet_backup_reason_text('change') === 'Configuration changed' && fleet_backup_reason_text('nightly') === 'Nightly', 'reasons in words');
if (is_executable('/usr/bin/diff')) {
	$d = fleet_backup_diff($conf, $conf2);
	check(strpos($d, "-\t<system><hostname>lab</hostname></system>") !== false && strpos($d, "+\t<system><hostname>lab2</hostname></system>") !== false &&
	    strpos($d, '/tmp') === false, 'a diff shows the changed lines without temporary file names');
}

/* ---- packaging: every file in files/ is installed by the Makefile ---- */
$port = dirname(__DIR__, 3) . '/sysutils/FreeSense-pkg-Fleet';
$make = str_replace('${PORTNAME}', 'FreeSense-pkg-Fleet', (string)file_get_contents("{$port}/Makefile"));
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator("{$port}/files", FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
	$rel = substr(str_replace('\\', '/', $f->getPathname()), strlen("{$port}/files"));
	if (preg_match('#^/pkg-(install|deinstall)#', $rel)) {
		continue;
	}
	$made = str_replace('/usr/local/', '${PREFIX}/', $rel);
	$ext = pathinfo($made, PATHINFO_EXTENSION);
	check(strpos($make, '${FILESDIR}' . $made . ' ') !== false || strpos($make, '${FILESDIR}' . dirname($made) . '/*.' . $ext . ' ') !== false ||
	    strpos($make, '${FILESDIR}' . dirname($made) . '/* ') !== false, "the Makefile installs {$rel}");
}

echo "Fleet controller tests: OK\n";
