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
check($s === array('enable' => true, 'public_host' => 'hq.example.net', 'enroll_port' => 8443, 'wg_port' => 51830, 'poll_interval' => 15), 'settings with defaults');
check(fleet_ctl_settings_from(array('poll_interval' => '30'))['poll_interval'] === 30 && fleet_ctl_settings_from(array('poll_interval' => '7'))['poll_interval'] === 15, 'status interval: 10, 15, 30 or 60 s');
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

check(fleet_box_error(422, array('error' => array('message' => 'The request failed validation.', 'details' => array('fields' => array('config' => 'The configuration is from a newer FreeSense.'))))) === 'The configuration is from a newer FreeSense.' &&
    fleet_box_error(500, array('error' => array('message' => 'Disk full.'))) === 'Disk full.' &&
    fleet_box_error(502, array()) === 'The box answered HTTP 502.' && fleet_backup_reason_text('safety') === 'Before a restore', 'restore messages');
check(fleet_event_text('node-1', 'restore', 'node-1 (Lab): backup of 2026-10-15 20:28') === array('Restored a backup', 'from 2026-10-15 20:28'), 'restore events in words');

/* ---- groups ---- */
check(fleet_group_name_problem('Retail', array()) === null && fleet_group_name_problem('', array()) !== null &&
    fleet_group_name_problem(str_repeat('x', 41), array()) !== null && fleet_group_name_problem('a<b', array()) !== null &&
    fleet_group_name_problem('all firewalls', array()) !== null && fleet_group_name_problem('RETAIL', array('Retail')) !== null,
    'group names: 1-40 characters, no markup, unique ignoring case, "All firewalls" is built in');
check(fleet_group_color('3') === '3' && fleet_group_color('red; x') === '1', 'only the eight series colours');
$g1 = fleet_group_save(null, 'Denmark', 'Danish sites', '2', 'tester');
$g2 = fleet_group_save(null, 'Retail', '', '9', 'tester');
try {
	fleet_group_save(null, 'denmark', '', '1', 'tester');
	check(false, 'a second Denmark is refused');
} catch (InvalidArgumentException $e) {
}
check(fleet_group_get($g2)['color'] === '1' && fleet_group_save($g1, 'Denmark', 'Danish sites and shops', '2', 'tester') === $g1 &&
    fleet_group_get($g1)['description'] === 'Danish sites and shops', 'create and change');
$gbox = array('node_id' => 'node-g', 'label' => 'Group test');
fleet_box_set_groups($gbox, array($g1, (string)$g2, 999, $g1), 'tester');
check(array_column(fleet_box_groups('node-g'), 'name') === array('Denmark', 'Retail'), 'a firewall in several groups; unknown ids and repeats are ignored');
check(array_column(fleet_groups_all(), 'members', 'name') === array('Denmark' => 1, 'Retail' => 1), 'member counts');
$byb = fleet_groups_by_box();
check($byb['node-g'] === array(array('id' => $g1, 'name' => 'Denmark', 'color' => '2'), array('id' => $g2, 'name' => 'Retail', 'color' => '1')),
    'groups per firewall for the dashboard');
$gdash = fleet_dashboard_data(array($row('node-g', 'G', 'online')), 0, 1, $byb);
check($gdash['boxes'][0]['groups'][0]['name'] === 'Denmark' && fleet_dashboard_data(array($row('x', 'X', 'online')), 0, 1, $byb)['boxes'][0]['groups'] === array(),
    'dashboard tiles carry their groups');
fleet_group_delete($g2, 'tester');
check(array_column(fleet_box_groups('node-g'), 'name') === array('Denmark') && fleet_group_get($g2) === null, 'deleting a group leaves its firewalls in the others');
fleet_box_set_groups($gbox, array(), 'tester');
check(fleet_box_groups('node-g') === array(), 'a firewall in no group');

foreach (glob(dirname(__DIR__, 3) . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/www/fleet/*.php') as $page) {
	check(preg_match('/\$g\b/', (string)file_get_contents($page)) === 0, basename($page) . ' does not use $g (the WebUI\'s global settings; the footer reads it)');
}

/* ---- managing a firewall ---- */
check(fleet_manage_allowed(array('role' => 'managed')) && !fleet_manage_allowed(array('role' => 'monitor')) && !fleet_manage_allowed(array()),
    'only a Managed firewall can be changed');
$svcs = fleet_services_from(array('data' => array(
    array('name' => 'unbound', 'description' => 'DNS Resolver', 'running' => true),
    array('name' => 'openvpn', 'description' => 'OpenVPN server: Office', 'running' => false, 'mode' => 'server', 'vpnid' => 2),
    array('name' => 'bad name; rm', 'description' => 'x'), 'junk',
    array('name' => 'dpinger', 'description' => 'Gateway Monitoring &amp; alerts', 'running' => true))));
check(array_column($svcs, 'name') === array('unbound', 'dpinger', 'openvpn') && $svcs[1]['description'] === 'Gateway Monitoring & alerts' &&
    $svcs[2]['vpnid'] === 2 && $svcs[2]['running'] === false, 'services from the box, sorted, junk names dropped');
check(fleet_service_body($svcs[2]) === array('confirm' => true, 'mode' => 'server', 'vpnid' => 2) &&
    fleet_service_body($svcs[1]) === array('confirm' => true), 'an OpenVPN instance is addressed by mode and vpnid');
try {
	fleet_box_reboot(array('role' => 'monitor', 'node_id' => 'n', 'label' => 'L'), 'tester');
	check(false, 'no reboot of a monitor-only firewall');
} catch (RuntimeException $e) {
	check(strpos($e->getMessage(), 'Monitor only') !== false, 'a monitor-only firewall is refused before anything is sent');
}
check(fleet_event_text('n', 'reboot', 'n (L): reboot started') === array('Rebooted', 'by the controller') &&
    fleet_event_text('n', 'service', 'n (L): restart DNS Resolver') === array('Service', 'restart DNS Resolver') &&
    fleet_event_text('n', 'groups', 'n (L): in Denmark, Retail') === array('Groups changed', 'in Denmark, Retail'), 'manage events in words');

/* ---- live state and operations ---- */
check(fleet_box_state_for(20, 10) === 'online' && fleet_box_state_for(60, 10) === 'degraded' && fleet_box_state_for(300, 10) === 'offline' &&
    fleet_box_state_for(120, 60) === 'online' && fleet_box_state_for(180, 60) === 'degraded' && fleet_box_state_for(600, 60) === 'offline',
    'degraded after 1 min of silence and offline after 5 min, whatever the interval (longer when checks are rarer)');
$rop = array('started' => 1000, 'text' => 'Rebooting');
check(fleet_op_reboot_step($rop, array('boot_time' => 900), 1010) === array('running', 'Waiting for it to go down') &&
    fleet_op_reboot_step($rop, null, 1030) === array('running', 'Restarting') &&
    fleet_op_reboot_step(array('started' => 1000, 'text' => 'Restarting'), null, 1040) === null &&
    fleet_op_reboot_step($rop, array('boot_time' => 1050), 1070) === array('done', 'Back online after 1 min 10 s') &&
    fleet_op_reboot_step($rop, null, 1000 + FLEET_OP_REBOOT_TIMEOUT + 1)[0] === 'failed', 'a reboot is done only when the box answers with a new boot time');
check(fleet_op_duration(45) === '45 s' && fleet_op_duration(120) === '2 min' && fleet_op_duration(-3) === '0 s', 'durations in words');
check(fleet_op_view(array('id' => 1, 'kind' => 'reboot', 'state' => 'done', 'text' => 'x', 'started' => 1, 'who' => 'a', 'finished' => 100), 100 + FLEET_OP_SHOW_DONE + 1) === null &&
    fleet_op_view(array('id' => 1, 'kind' => 'reboot', 'state' => 'running', 'text' => 'x', 'started' => 1, 'who' => 'a', 'finished' => null), 99999)['state'] === 'running',
    'a finished operation leaves the tile after a moment; a running one stays');
$oid = fleet_op_start('node-op', 'reboot', 'Rebooting', 'tester');
check(fleet_op_running('node-op')['id'] == $oid && isset(fleet_ops_for_tiles(time())['node-op']), 'a running operation shows on its tile');
fleet_ops_follow(array('node_id' => 'node-op', 'label' => 'Op'), array('boot_time' => time() + 5), time() + 60);
check(fleet_op_running('node-op') === null && fleet_ops_for_tiles(time() + 60)['node-op']['state'] === 'done', 'the poll finishes the reboot when the box is back');
check(fleet_dashboard_data(array($row('node-op', 'Op', 'online')), 0, time(), array(), fleet_ops_for_tiles(time()))['boxes'][0]['op']['kind'] === 'reboot',
    'the tile data carries the operation');

/* ---- group operations ---- */
check(fleet_op_progress(array('done', 'failed', 'running', 'queued')) === array('total' => 4, 'finished' => 2, 'failed' => 1, 'skipped' => 0, 'percent' => 50) &&
    fleet_op_progress(array())['percent'] === 100, 'group progress counts finished tasks');
check(fleet_op_summary(array('total' => 8, 'finished' => 5, 'failed' => 0), false) === '5 of 8 done' && fleet_op_summary(array('total' => 8, 'finished' => 8, 'failed' => 0), true) === 'All 8 done' &&
    fleet_op_summary(array('total' => 8, 'finished' => 8, 'failed' => 2), true) === '2 of 8 failed', 'group progress in words');
check(fleet_op_summary(array('total' => 3, 'finished' => 3, 'failed' => 1, 'skipped' => 2), true) === '1 of 3 failed, 2 left alone', 'a stopped rolling operation says what was left alone');
$gop = fleet_op_group_start('backup_all', 'Back up Denmark', 'tester');
$t1 = fleet_op_start('node-ga', 'backup', 'Waiting', 'tester', $gop, 'queued');
$t2 = fleet_op_start('node-gb', 'backup', 'Waiting', 'tester', $gop, 'queued');
check(fleet_op_running('node-ga')['id'] == $t1 && fleet_ops_groups_running()[0]['title'] === 'Back up Denmark' && !isset(fleet_ops_for_tiles(time())['']), 'a waiting task makes its firewall busy; the group shows in the strip, not as a tile');
fleet_op_set($t1, 'done', 'Backed up and checked');
check(fleet_op_group_update($gop)['finished'] === 1 && fleet_ops_groups_running()[0]['text'] === '1 of 2 done', 'progress after one task');
fleet_op_set($t2, 'failed', 'Backup failed: x');
fleet_op_group_update($gop);
check(fleet_ops_groups_running() === array() && fleet_ops_history(5)[0]['state'] === 'failed' && fleet_ops_history(5)[0]['text'] === '1 of 2 failed' &&
    count(fleet_op_tasks($gop)) === 2 && fleet_op_tasks($gop)[0]['state'] === 'failed', 'a group with a failed task ends failed; failures listed first; tasks are not in the history');

check(fleet_event_text('n', 'reboot_done', 'n (L): Back online after 1 min 22 s') === array('Back online', 'after 1 min 22 s'), 'a finished reboot in words');
/* ---- lists: filters, search, paging ---- */
check(fleet_list_filters(array('state' => 'failed', 'kind' => 'evil', 'q' => "  cph\x01 ", 'since' => '7', 'x' => 'y'),
    array('q' => null, 'state' => FLEET_OPS_STATES, 'kind' => FLEET_OPS_KINDS, 'since' => FLEET_OPS_SINCE)) === array('q' => 'cph', 'state' => 'failed', 'since' => '7'),
    'only known filter values survive; search is trimmed and cleaned');
check(fleet_list_page(0, 3) === array('page' => 1, 'pages' => 1, 'per' => 25, 'offset' => 0, 'total' => 0, 'first' => 0, 'last' => 0) &&
    fleet_list_page(340, 2)['first'] === 26 && fleet_list_page(340, 2)['last'] === 50 && fleet_list_page(340, 99)['page'] === 14, 'paging, past the end shows the last page');
check(fleet_list_page_links(1, 1) === array(1) && fleet_list_page_links(7, 14) === array(1, 0, 6, 7, 8, 0, 14) && fleet_list_page_links(2, 4) === array(1, 2, 3, 4),
    'page links with gaps');
check(fleet_list_like('50%_off') === '%50\%\_off%', 'a search for % or _ is literal');
check(strpos(fleet_list_url(array('op' => 3), array('state' => 'failed', 'page' => 4), array('q' => 'x')), 'page') === false &&
    fleet_list_url(array(), array('state' => 'failed'), array('page' => 2)) === '?state=failed&page=2', 'changing a filter goes back to page 1');
for ($i = 0; $i < 30; $i++) {
	fleet_op_set(fleet_op_start('node-list', 'reboot', 'Rebooting', ($i % 2) ? 'alice' : 'bob'), ($i % 3) ? 'done' : 'failed', '50%_done');
}
list($rows, $pg) = fleet_ops_find(array('kind' => 'reboot', 'q' => 'alice'), 1, time());
check($pg['total'] === 15 && count($rows) === 15, 'filter by action and search by person');
list($rows, $pg) = fleet_ops_find(array('kind' => 'reboot'), 2, time());
check($pg['page'] === 2 && count($rows) === min(25, $pg['total'] - 25), 'the second page holds the rest');
list(, $pg) = fleet_ops_find(array('state' => 'failed', 'q' => '50%_'), 1, time());
check($pg['total'] === 10, 'state filter plus a literal % search');
list(, $pg2) = fleet_ops_find(array('q' => 'no such thing'), 1, time());
check($pg2['total'] === 0, 'no match is zero, not everything');
list(, $pg) = fleet_ops_find(array('q' => 'node-gb'), 1, time());
check($pg['total'] === 1, 'a group operation is found by one of its firewalls');
fleet_audit('poll', 'state', 'node-ev (Ev): online -> offline');
fleet_audit('admin', 'reboot', 'node-ev (Ev): reboot started');
fleet_audit('admin', 'backup', 'node-ev (Ev): stored');
list($evs, $epg) = fleet_events_find('node-ev', array('type' => 'manage'), 1, time());
check($epg['total'] === 1 && $evs[0]['action'] === 'reboot', 'events filtered by type');
list(, $epg) = fleet_events_find('node-ev', array('q' => 'offline'), 1, time());
check($epg['total'] === 1, 'events searched');

/* ---- group reboot: plan and rolling order ---- */
check(fleet_rolling_next(array('queued', 'queued')) === array('do' => 'start', 'index' => 0) &&
    fleet_rolling_next(array('done', 'running', 'queued')) === array('do' => 'wait') &&
    fleet_rolling_next(array('done', 'done', 'queued')) === array('do' => 'start', 'index' => 2) &&
    fleet_rolling_next(array('done', 'failed', 'queued')) === array('do' => 'stop') &&
    fleet_rolling_next(array('done', 'skipped', 'done')) === array('do' => 'done') && fleet_rolling_next(array()) === array('do' => 'done'),
    'one at a time; the first failure stops the rest');
$plan = fleet_group_reboot_plan(array(
    array('node_id' => 'b', 'label' => 'Bravo', 'role' => 'managed', 'state' => 'online'),
    array('node_id' => 'a', 'label' => 'alpha', 'role' => 'managed', 'state' => 'degraded'),
    array('node_id' => 'm', 'label' => 'Mon', 'role' => 'monitor', 'state' => 'online'),
    array('node_id' => 'o', 'label' => 'Off', 'role' => 'managed', 'state' => 'offline'),
    array('node_id' => 'x', 'label' => 'Busy', 'role' => 'managed', 'state' => 'online')), array('x' => 'Backing up'));
check(array_column($plan['go'], 'node_id') === array('a', 'b') &&
    array_map(function ($s) { return $s[1]; }, $plan['skip']) === array('Busy: backing up', 'Monitor only: the controller may not reboot it', 'Offline'),
    'the review lists who reboots in order and who is left alone and why');
$rop = fleet_op_group_start('reboot_group', 'Reboot Canary', 'tester');
$ra = fleet_op_start('node-ra', 'reboot', 'Waiting', 'tester', $rop, 'queued');
check(fleet_rolling_next(array_column(fleet_op_tasks($rop), 'state'))['index'] === 0, 'tasks run in the order they were planned');
fleet_db()->prepare("UPDATE ops SET state = 'running', text = 'Rebooting', started = ? WHERE id = ?")->execute(array(time() - 30, $ra));
fleet_ops_follow(array('node_id' => 'node-ra', 'label' => 'RA'), array('boot_time' => time()), time());
check(fleet_op_group_update($rop)['finished'] === 1 && fleet_ops_history(1)[0]['text'] === 'Done', 'the poll finishes a group task the same way as a single reboot');

echo "Fleet controller tests: OK\n";
