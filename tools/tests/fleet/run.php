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
check($s === array('enable' => true, 'public_host' => 'hq.example.net', 'enroll_port' => 8443, 'wg_port' => 51830) + fleet_tunables_from(array()), 'settings with defaults');
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
check(fleet_backup_due(null, $st, 1000 + 60 * fleet_opt('backup_quiet')) && !fleet_backup_due(null, $st, 1000 + 60 * fleet_opt('backup_quiet') - 1),
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
check(fleet_op_reboot_step($rop, array('boot_time' => 900), 1010) === array('running', 'Waiting for it to go down', 25) &&
    fleet_op_reboot_step($rop, null, 1030) === array('running', 'Restarting', 50) &&
    fleet_op_reboot_step(array('started' => 1000, 'text' => 'Restarting'), null, 1040) === null &&
    fleet_op_reboot_step($rop, array('boot_time' => 1050), 1070) === array('done', 'Back online after 1 min 10 s', 100) &&
    fleet_op_reboot_step($rop, null, 1000 + 60 * fleet_opt('reboot_timeout') + 1)[0] === 'failed', 'a reboot is done only when the box answers with a new boot time');
check(fleet_op_duration(45) === '45 s' && fleet_op_duration(120) === '2 min' && fleet_op_duration(-3) === '0 s', 'durations in words');
check(fleet_op_view(array('id' => 1, 'kind' => 'reboot', 'state' => 'done', 'text' => 'x', 'started' => 1, 'who' => 'a', 'finished' => 100), 100 + fleet_opt('show_done') + 1) === null &&
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
check(fleet_op_running('node-ga') === null && fleet_ops_for_tiles(time())['node-ga']['state'] === 'queued' && fleet_ops_groups_running()[0]['title'] === 'Back up Denmark' &&
    !isset(fleet_ops_for_tiles(time())['']), 'a waiting task shows on its tile but does not make the firewall busy; the group shows in the strip, not as a tile');
fleet_op_set($t1, 'done', 'Backed up and checked');
check(fleet_op_group_update($gop)['finished'] === 1 && fleet_ops_groups_running()[0]['text'] === '1 of 2 done', 'progress after one task');
fleet_op_set($t2, 'failed', 'Backup failed: x');
fleet_op_group_update($gop);
check(fleet_ops_groups_running() === array() && fleet_ops_history(5)[0]['state'] === 'failed' && fleet_ops_history(5)[0]['text'] === '1 of 2 failed' &&
    count(fleet_op_tasks($gop)) === 2 && fleet_op_tasks($gop)[0]['state'] === 'failed', 'a group with a failed task ends failed; failures listed first; tasks are not in the history');

check(fleet_event_text('n', 'reboot_done', 'n (L): Back online after 1 min 22 s') === array('Back online', 'after 1 min 22 s'), 'a finished reboot in words');
check(fleet_op_progress(array('done', 'running', 'queued', 'queued'), array(50))['percent'] === 37, 'a firewall half way moves the group bar');
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
    array_map(function ($s) { return $s[1]; }, $plan['skip']) === array('Busy: backing up', 'Monitor only: the controller may not change it', 'Offline'),
    'the review lists who reboots in order and who is left alone and why');
$rop = fleet_op_group_start('reboot_group', 'Reboot Canary', 'tester');
$ra = fleet_op_start('node-ra', 'reboot', 'Waiting', 'tester', $rop, 'queued');
check(fleet_rolling_next(array_column(fleet_op_tasks($rop), 'state'))['index'] === 0, 'tasks run in the order they were planned');
fleet_db()->prepare("UPDATE ops SET state = 'running', text = 'Rebooting', started = ? WHERE id = ?")->execute(array(time() - 30, $ra));
fleet_ops_follow(array('node_id' => 'node-ra', 'label' => 'RA'), array('boot_time' => time()), time());
check(fleet_op_group_update($rop)['finished'] === 1 && fleet_ops_history(1)[0]['text'] === 'Done', 'the poll finishes a group task the same way as a single reboot');

check(strpos(fleet_progress_bar('running', null, 'x'), 'data-indeterminate') !== false && strpos(fleet_progress_bar('running', 40, 'x'), 'aria-valuenow="40"') !== false &&
    strpos(fleet_progress_bar('done', null, 'x'), 'width: 100%') !== false, 'one bar: sliding when unknown, filling when known, full when over');
$pop = fleet_op_start('node-pg', 'reboot', 'Rebooting', 'tester');
fleet_op_set($pop, 'running', 'Restarting', 50);
fleet_op_set($pop, 'running', 'Still restarting');
check(fleet_ops_for_tiles(time())['node-pg']['progress'] === 50, 'progress is kept when a step does not say');
fleet_op_set($pop, 'done', 'Back');
check(fleet_ops_for_tiles(time())['node-pg']['progress'] === 100, 'a finished operation is at 100');

/* ---- top-bar item ---- */
check(fleet_nav_item(0, 0)['hidden'] === true && fleet_nav_item(2, 0)['busy'] === true && fleet_nav_item(2, 0)['badge'] === 2 && fleet_nav_item(2, 1)['kind'] === 'info' &&
    fleet_nav_item(0, 1)['kind'] === 'block' && fleet_nav_item(0, 1)['label'] === 'FreeSense Fleet: 1 action failed' && !fleet_nav_item(0, 1)['hidden'], 'quiet: hidden; running: spinner and count; failed lately: red count');
check(is_array(fleet_nav_now(time())), 'the top-bar item from the store');
$nav = fleet_nav_item(3, 0);
require_once($argv[1] . '/src/usr/local/www/includes/fs_menu.inc');
check(fs_nav_plugin_item('fleet', $nav) !== null, 'System accepts the Fleet item as it is');

/* ---- settings ---- */
$t = fleet_tunables_from(array('silent_offline' => '30', 'backup_parallel' => '0', 'toast_done' => 'off', 'per_page' => '50', 'reboot_timeout' => '7.5', 'show_done' => 'x'));
check($t['silent_offline'] === 30 && $t['backup_parallel'] === 10 && $t['toast_done'] === false && $t['toast_failed'] === true && $t['per_page'] === 50 &&
    $t['reboot_timeout'] === 10 && $t['show_done'] === 90, 'tunables: in range kept, out of range or not whole is the default, booleans on/off');
foreach (FLEET_TUNABLES as $k => $def) {
	check(array_key_exists($def[0], FLEET_SETTINGS_SECTIONS) && $def[5] !== '' && $def[6] !== '', "setting {$k} has a section, a label and help");
}
check(fleet_opt('reboot_timeout') === 10 && fleet_opt('per_page') === 25, 'defaults without a configuration');

/* ---- notices ---- */
$fin = array(array('id' => 1, 'state' => 'done', 'text' => 'Done', 'name' => 'Reboot Lab'), array('id' => 2, 'state' => 'failed', 'text' => 'Backup failed: x', 'name' => 'Back up Aarhus'), array('id' => 3, 'state' => 'running', 'text' => 'x', 'name' => 'y'));
$ts = fleet_nav_toasts($fin, true, true);
check(count($ts) === 2 && $ts[0] === array('text' => 'Reboot Lab: Done', 'kind' => 'pass', 'href' => '/fleet/fleet_activity.php?op=1', 'sticky' => false) && $ts[1]['sticky'] === true && $ts[1]['kind'] === 'block',
    'a notice per finished action; failures stay');
check(count(fleet_nav_toasts($fin, false, true)) === 1 && fleet_nav_toasts($fin, false, false) === array(), 'the settings turn them off');
require_once($argv[1] . '/src/usr/local/www/includes/fs_menu.inc');
check(fs_nav_toasts($ts) === $ts, 'System shows the Fleet notices as they are');
check(fleet_ops_finished_since(0, time() + 100)[0]['name'] !== '', 'finished operations have a name');

/* ---- updates ---- */
check(fleet_version_number('1.1.5-RELEASE') === '1.1.5' && fleet_version_number('1.1.6_1') === '1.1.6' && fleet_version_number('x') === '' &&
    fleet_version_same('1.1.6-RELEASE', '1.1.6') && !fleet_version_same('1.1.6', '1.1.60') && !fleet_version_same('', ''), 'versions compared by their numbers');
$ui = fleet_update_info_from(200, array('data' => array('installed_version' => '1.1.5', 'latest_version' => '1.1.6', 'update_available' => true, 'channel' => 'stable')), 50);
check($ui['available'] && $ui['latest'] === '1.1.6' && $ui['error'] === null && fleet_update_verdict($ui) === array('info', 'Update: 1.1.6'), 'an available update');
$ue = fleet_update_info_from(502, array('error' => array('message' => 'Unable to check for updates.', 'details' => array('messages' => array('DNS servers not available')))), 50);
check($ue['error'] === 'The firewall could not check for updates: DNS servers not available' && fleet_update_verdict($ue)[1] === 'Update check failed' &&
    fleet_update_verdict(array('available' => false, 'error' => null)) === null && fleet_update_verdict(null) === null, 'a failed check says why; up to date says nothing');
$uop = array('started' => 1000, 'text' => 'Downloading and installing', 'data' => json_encode(array('from' => '1.1.5', 'to' => '1.1.6')));
$old = array('version' => '1.1.5-RELEASE', 'boot_time' => 900);
check(fleet_op_update_step($uop, $old, 1060, 360, 3600) === null || fleet_op_update_step($uop, $old, 1060, 360, 3600)[0] === 'running', 'installing: still running');
check(fleet_op_update_step($uop, null, 1300, 360, 3600)[1] === 'Restarting', 'no answer: restarting');
$s1 = fleet_op_update_step($uop, array('version' => '1.1.6-RELEASE', 'boot_time' => 1400), 1500, 360, 3600);
check($s1[0] === 'running' && $s1[1] === 'Checking that it stays healthy' && $s1[3]['reached'] === 1500, 'new version: waiting out the rollback window');
$uop2 = array('started' => 1000, 'text' => 'Checking that it stays healthy', 'data' => json_encode($s1[3]));
check(fleet_op_update_step($uop2, array('version' => '1.1.6-RELEASE', 'boot_time' => 1400), 1700, 360, 3600)[0] === 'running' &&
    fleet_op_update_step($uop2, array('version' => '1.1.6-RELEASE', 'boot_time' => 1400), 1860, 360, 3600)[1] === 'Updated to 1.1.6 in 14 min 20 s',
    'done only when the new version stayed up for the whole window');
check(strpos(fleet_op_update_step($uop2, array('version' => '1.1.5-RELEASE', 'boot_time' => 1700), 1750, 360, 3600)[1], 'Rolled back to 1.1.5') === 0,
    'back on the old version after a reboot: rolled back');
check(fleet_op_update_step($uop, $old, 1000 + 3601, 360, 3600)[0] === 'failed' && fleet_op_update_step($uop, null, 1000 + 3601, 360, 3600)[0] === 'failed', 'no result in time: failed');
$gp = fleet_group_update_plan(array(
    array('node_id' => 'u1', 'label' => 'A', 'role' => 'managed', 'state' => 'online', 'status' => json_encode(array('rollback_protection' => true))),
    array('node_id' => 'u2', 'label' => 'B', 'role' => 'managed', 'state' => 'online', 'status' => json_encode(array('rollback_protection' => false))),
    array('node_id' => 'u3', 'label' => 'C', 'role' => 'managed', 'state' => 'online', 'status' => '{}'),
    array('node_id' => 'u4', 'label' => 'D', 'role' => 'managed', 'state' => 'online', 'status' => '{}')), array(),
    array('u1' => $ui, 'u2' => $ui, 'u3' => array('available' => false, 'installed' => '1.1.6', 'error' => null), 'u4' => $ue), false);
check(array_column($gp['go'], 'node_id') === array('u1') && count($gp['skip']) === 3 &&
    in_array('No rollback (UFS): update it by itself', array_map(function ($s) { return $s[1]; }, $gp['skip']), true), 'a group update leaves out the up to date, the unchecked and (by default) UFS');
check(count(fleet_group_update_plan(array(array('node_id' => 'u2', 'label' => 'B', 'role' => 'managed', 'state' => 'online', 'status' => json_encode(array('rollback_protection' => false)))),
    array(), array('u2' => $ui), true)['go']) === 1, 'UFS joins when the setting allows it');

/* ---- maintenance windows and rollouts ---- */
$w = fleet_window_from(array('name' => 'Nights', 'days' => array('1', '2', '3', '4', '5', '9'), 'start' => '23:00', 'length' => '180'));
check($w === array('name' => 'Nights', 'days' => array(1, 2, 3, 4, 5), 'start' => 1380, 'length' => 180) && fleet_window_text($w) === 'Mon-Fri 23:00, 3 h', 'a window from the form');
foreach (array(array('name' => ''), array('name' => 'x', 'days' => array()), array('name' => 'x', 'days' => array(1), 'start' => '25:00'),
    array('name' => 'x', 'days' => array(1), 'start' => '01:00', 'length' => '10')) as $bad) {
	try {
		fleet_window_from($bad + array('days' => array(1), 'start' => '01:00', 'length' => '60'));
		check(false, 'a bad window is refused');
	} catch (InvalidArgumentException $e) {
	}
}
/* 2026-10-16 is a Friday. */
$fri2330 = (new DateTimeImmutable('2026-10-16 23:30:00', new DateTimeZone('Europe/Copenhagen')))->getTimestamp();
$sat0130 = $fri2330 + 2 * 3600;
$sat0300 = $fri2330 + 3.5 * 3600;
check(fleet_window_state($w, $fri2330, 'Europe/Copenhagen') === array(true, 9000) && fleet_window_state($w, $sat0130, 'Europe/Copenhagen') === array(true, 1800) &&
    fleet_window_state($w, (int)$sat0300, 'Europe/Copenhagen') === array(false, 0), 'a window running past midnight is open the next morning, then closes');
check(fleet_window_next($w, (int)$sat0300, 'Europe/Copenhagen') === (new DateTimeImmutable('2026-10-19 23:00:00', new DateTimeZone('Europe/Copenhagen')))->getTimestamp(),
    'after Friday night the next window is Monday night');
check(fleet_rollout_rings(array(3, 1, 0), array(3 => array('a', 'b'), 1 => array('b', 'c', 'x')), array('a', 'b', 'c', 'd')) === array(array('a', 'b'), array('c'), array('d')),
    'rings: a firewall goes in the first ring that has it; the last ring is everyone else');
$open = array('name' => 'Always', 'days' => array(1, 2, 3, 4, 5, 6, 7), 'start' => 0, 'length' => 1440);
check(fleet_rollout_next(array(array(null, array('done', 'queued'))), array(), 1000, 86400, 3600) === array('do' => 'start', 'ring' => 0, 'task' => 1), 'next firewall in the ring');
check(fleet_rollout_next(array(array(null, array('done', 'running'))), array(), 1000, 86400, 3600)['do'] === 'wait', 'one at a time');
check(fleet_rollout_next(array(array(null, array('failed', 'queued'))), array(), 1000, 86400, 3600) === array('do' => 'pause', 'ring' => 0), 'a failure pauses the rollout');
check(fleet_rollout_next(array(array(null, array('done')), array(null, array('queued'))), array(0 => 1000), 2000, 86400, 3600) === array('do' => 'wait', 'why' => 'Waiting before the next ring', 'until' => 87400) &&
    fleet_rollout_next(array(array(null, array('done')), array(null, array('queued'))), array(0 => 1000), 87400, 86400, 3600)['do'] === 'start', 'the next ring waits for the gap');
$late = fleet_rollout_next(array(array($w, array('queued'))), array(), (int)($sat0130), 0, 3600, 'Europe/Copenhagen');
check($late['do'] === 'wait' && $late['why'] === 'Waiting for the maintenance window' && $late['until'] === (new DateTimeImmutable('2026-10-19 23:00:00', new DateTimeZone('Europe/Copenhagen')))->getTimestamp(),
    'an update is not started when the window has too little time left');
check(fleet_rollout_next(array(array($open, array('done', 'skipped')), array(null, array())), array(), 1000, 0, 3600) === array('do' => 'done'), 'all rings done');

/* ---- schedules ---- */
$sc = fleet_schedule_from(array('name' => 'Nightly Retail', 'kind' => 'backup', 'group_id' => '2', 'days' => array('1', '2', '3', '4', '5', '6', '7'), 'time' => '02:30', 'enabled' => '1'));
check($sc['time'] === 150 && $sc['days'] === array(1, 2, 3, 4, 5, 6, 7) && $sc['enabled'] && fleet_schedule_text($sc) === 'Every day 02:30', 'a schedule from the form');
try {
	fleet_schedule_from(array('name' => 'x', 'kind' => 'format', 'days' => array(1), 'time' => '02:00'));
	check(false, 'an unknown job is refused');
} catch (InvalidArgumentException $e) {
}
$utc = function ($s) { return (new DateTimeImmutable($s, new DateTimeZone('UTC')))->getTimestamp(); };
$sun = array('days' => array(7), 'time' => 240);
check(fleet_schedule_due($sun, $utc('2026-10-11 00:00'), $utc('2026-10-18 04:03'), 900) === array('run', $utc('2026-10-18 04:00')), 'due a few minutes after its time');
check(fleet_schedule_due($sun, $utc('2026-10-18 04:00'), $utc('2026-10-18 04:05'), 900) === null, 'runs once');
check(fleet_schedule_due($sun, $utc('2026-10-11 00:00'), $utc('2026-10-18 09:00'), 900) === array('missed', $utc('2026-10-18 04:00')), 'too late: missed, not run late');
check(fleet_schedule_due($sun, $utc('2026-10-18 03:00'), $utc('2026-10-18 03:59'), 900) === null, 'not before its time');
check(fleet_schedule_next($sun, $utc('2026-10-18 04:00')) === $utc('2026-10-25 04:00') && fleet_schedule_next($sc, $utc('2026-10-16 03:00')) === $utc('2026-10-17 02:30'), 'next run');

$s1 = fleet_schedule_from(array('name' => 'Edge', 'kind' => 'reboot', 'targets' => array('n:node-abc', 'g:2', 'g:2'), 'days' => array(7), 'time' => '04:00'));
check($s1['targets'] === array('g:2', 'n:node-abc') && fleet_targets_from(array('g:1', 'all')) === array('all') && fleet_targets_from('n:x') === array('n:x'),
    'targets: any mix of groups and firewalls, no repeats; All wins');
foreach (array(array(), array('x:1'), array('n:a b')) as $bad) {
	try {
		fleet_targets_from($bad);
		check(false, 'bad targets are refused');
	} catch (InvalidArgumentException $e) {
	}
}
$tb = array(array('node_id' => 'a', 'label' => 'A'), array('node_id' => 'b', 'label' => 'B'), array('node_id' => 'c', 'label' => 'C'));
list($tl, $tg) = fleet_targets_resolve(array('g:1', 'g:9', 'n:c', 'n:gone'), $tb, array(1 => array('a', 'c')));
check(array_column($tl, 'node_id') === array('a', 'c') && $tg === array('g:9', 'n:gone') && count(fleet_targets_resolve(array('all'), $tb, array())[0]) === 3,
    'targets resolve to each firewall once and name what no longer exists');
check(fleet_targets_text(array('g:1', 'n:c', 'n:gone'), array('g:1' => 'Canary', 'n:c' => 'C')) === 'Canary, C, removed firewall', 'targets as text');
/* ---- backup retention ---- */
$day = 86400;
$now0 = (new DateTimeImmutable('2026-10-16 12:00:00', new DateTimeZone('UTC')))->getTimestamp();
$rows = array();
for ($i = 0; $i < 60; $i++) {
	/* two backups a day for 30 days, newest first */
	$rows[] = array('id' => 100 + $i, 'time' => $now0 - (int)($i * $day / 2), 'reason' => 'change', 'pinned' => 0);
}
$rows[] = array('id' => 900, 'time' => $now0 - 200 * $day, 'reason' => 'manual', 'pinned' => 1);
$rows[] = array('id' => 901, 'time' => $now0 - 3 * $day - 3600, 'reason' => 'safety', 'pinned' => 0);
$rows[] = array('id' => 902, 'time' => $now0 - 90 * $day, 'reason' => 'safety', 'pinned' => 0);
$k = fleet_backup_keep($rows, array(array('last' => 3, 'daily' => 7, 'weekly' => 0, 'monthly' => 0)), $now0, 30);
check(isset($k[100], $k[101], $k[102]) && $k[100] === 'Newest' && $k[900] === 'Pinned' && $k[901] === 'Safety backup' && !isset($k[902]), 'newest, pinned and recent safety backups are kept; old safety ones are not');
$daily = array_keys(array_filter($k, function ($w) { return $w === 'Daily'; }));
check(count($daily) === 5 && !isset($k[116]), 'one a day for 7 days (days already kept by "last" count), nothing older');
$k2 = fleet_backup_keep($rows, array(array('last' => 1, 'daily' => 0, 'weekly' => 0, 'monthly' => 0), array('last' => 1, 'daily' => 0, 'weekly' => 3, 'monthly' => 0)), $now0, 30);
check(count(array_filter($k2, function ($w) { return $w === 'Weekly'; })) === 2 && count($k2) === 5, 'several sets: the union of their rules (weekly picks the newest of each week)');
check(fleet_backup_keep(array(), array(fleet_keep_rule_from(array('keep_last' => '1', 'keep_daily' => '0', 'keep_weekly' => '0', 'keep_monthly' => '0'))), $now0, 30) === array(), 'nothing to keep in an empty list');
try {
	fleet_keep_rule_from(array('keep_last' => '0', 'keep_daily' => '1', 'keep_weekly' => '1', 'keep_monthly' => '1'));
	check(false, 'keep at least one');
} catch (InvalidArgumentException $e) {
}
check(fleet_keep_rule_text(array('last' => 10, 'daily' => 14, 'weekly' => 0, 'monthly' => 12)) === 'last 10, 14 daily, 12 monthly', 'rule as text');

/* ---- backup copies and Recover fleet ---- */
$rk = fleet_recovery_key_new(str_repeat("\x5a", 20));
check(preg_match('/^FRK(-[0-9A-HJKMNP-TV-Z]{4}){8}$/', $rk) === 1 && fleet_recovery_key_bytes($rk) === str_repeat("\x5a", 20) &&
    fleet_recovery_key_bytes(strtolower(str_replace('-', ' ', $rk))) === str_repeat("\x5a", 20) && fleet_recovery_key_bytes('FRK-1234') === null,
    'recovery keys: 160 bits in Crockford base32, typed loosely');
$rw = fleet_replica_wanted(array(array('id' => 7, 'node_id' => 'n1', 'time' => 5, 'file' => 'n1/a.enc', 'file_sha' => 'aa'),
    array('id' => 8, 'node_id' => 'n1', 'time' => 6, 'file' => 'n1/b.enc', 'file_sha' => '')), array('id' => 'ctl.self.9', 'sha256' => 'ss', 'created' => 9), 'ee', 10);
check(array_keys($rw) === array('cfg.n1.7', 'ctl.self.9', 'ctl.recovery') && $rw['cfg.n1.7']['label'] === 'n1/a.enc', 'a peer holds every backup file, the newest self-backup and the envelope');
check(fleet_replica_plan($rw, array('cfg.n1.7' => 'aa', 'ctl.self.1' => 'x', 'theirs' => 'y', 'ctl.recovery' => 'old')) === array(array('ctl.self.9', 'ctl.recovery'), array('ctl.self.1')),
    'sync uploads what is missing or changed and removes only Fleet\'s own leftovers');
$rk2 = fleet_recovery_create('test');
$exp = fleet_archive_export();
$udir = FLEET_DATA . '/unpack-test';
@mkdir($udir);
exec('tar -xzf ' . escapeshellarg($exp) . ' -C ' . escapeshellarg($udir), $o, $trc);
check($trc === 0 && is_file("{$udir}/ctl.recovery.blob") && count(glob("{$udir}/ctl.self.*.blob")) === 1, 'the export is a vault archive with the envelope and a self-backup');
try {
	fleet_recover_open($udir, fleet_recovery_key_new());
	check(false, 'a wrong recovery key does not open the archive');
} catch (InvalidArgumentException $e) {
	check(strpos($e->getMessage(), 'FLEET-E805') === 0, 'a wrong recovery key says so');
}
$opened = fleet_recover_open($udir, $rk2);
$sum = fleet_recover_summary($opened);
$boxes_before = (int)fleet_db()->query('SELECT COUNT(*) FROM boxes')->fetchColumn();
check($opened[0] === fleet_master_key() && $sum['boxes'] === $boxes_before, 'the right key opens it: master key and the database are back');
fleet_db()->exec("INSERT INTO settings (name, value) VALUES ('after_export', '1')");
try {
	if ($boxes_before > 0) {
		fleet_recover_apply($opened, false, 'test');
		check(false, 'recovering over a controller with firewalls needs a confirmation');
	}
} catch (RuntimeException $e) {
}
fleet_recover_apply($opened, true, 'test');
check(fleet_setting('after_export') === null && (int)fleet_db()->query('SELECT COUNT(*) FROM boxes')->fetchColumn() === $boxes_before,
    'Recover fleet puts the database back as it was in the copy');
exec('rm -rf ' . escapeshellarg($udir));

list($ob, $oj) = fleet_offsite_names('cfg.n1.7', str_repeat('ab', 32));
check($ob === 'fleet-cfg.n1.7.abababababab.blob' && $oj === 'fleet-cfg.n1.7.abababababab.json', 'off-site names carry the id and a short hash');
check(fleet_offsite_held(array($ob, $oj, 'fleet-ctl.self.9.0123456789ab.blob', 'fw1-20261016-010000-deadbeef.xml', 'fleet-x.y.zz.blob')) === array('cfg.n1.7' => 'abababababab'),
    'only complete Fleet pairs count as held; System\'s own remote backups are never touched');

/* ---- policies ---- */
$pcfg = simplexml_load_string('<freesense><system><hostname>dk-cph-edge01</hostname><domain>lab.arpa</domain><timezone>Europe/Copenhagen</timezone>' .
    '<timeservers>pool.ntp.org</timeservers><ssh><enable>enabled</enable><sshdkeyonly>enabled</sshdkeyonly><port>22</port></ssh>' .
    '<webgui><protocol>https</protocol></webgui></system></freesense>');
$pf = array('version' => '1.1.5-RELEASE', 'channel' => 'stable', 'rollback' => false, 'last_backup' => 1000, 'config' => $pcfg, 'now' => 1000 + 3 * 86400);
check(fleet_policy_check('VER-001', array('version' => '1.1.5'), $pf)[0] === 'pass' && fleet_policy_check('VER-001', array('version' => '1.1.6'), $pf)[0] === 'fail' &&
    fleet_policy_check('VER-002', array('version' => '1.1.5'), $pf)[0] === 'pass' && fleet_policy_check('VER-003', array('versions' => '1.1.6, 1.2.0'), $pf)[1] === 'Runs 1.1.5, allowed: 1.1.6, 1.2.0' &&
    fleet_policy_check('VER-004', array('channel' => 'testing'), $pf)[0] === 'fail', 'version rules: minimum, pinned, allowed, channel');
check(fleet_policy_check('OPS-010', array('days' => '2'), $pf)[0] === 'fail' && fleet_policy_check('OPS-020', array(), $pf)[0] === 'fail' &&
    fleet_policy_check('OPS-001', array(), $pf)[0] === 'pass' && fleet_policy_check('OPS-002', array(), $pf)[0] === 'fail' &&
    fleet_policy_check('OPS-003', array('value' => 'Europe/Copenhagen'), $pf)[0] === 'pass', 'operations rules');
check(fleet_policy_check('SEC-001', array(), $pf)[0] === 'pass' && fleet_policy_check('SEC-002', array(), $pf)[0] === 'pass' &&
    fleet_policy_check('NAME-001', array('regex' => '^[a-z]{2}-[a-z0-9]+-[a-z]+[0-9]{2}$'), $pf)[0] === 'pass' &&
    fleet_policy_check('NAME-002', array('value' => 'corp.net'), $pf)[1] === 'system/domain: "lab.arpa" (equals corp.net)', 'security and naming rules against the configuration backup');
check(fleet_policy_check('CUSTOM:1', array('path' => 'system/ssh/port', 'op' => 'max', 'value' => '1024', 'title' => 'x'), $pf)[0] === 'pass' &&
    fleet_policy_check('SEC-001', array(), array('config' => null) + $pf)[0] === 'unknown', 'custom path rules; no backup is unknown, not failed');
list($r1) = fleet_policy_rule_from('CUSTOM:3', array('path' => 'system/ssh/port', 'op' => 'equals', 'value' => '22', 'title' => 'Port'));
check($r1 === 'CUSTOM:3', 'a custom rule from the form');
foreach (array(array('VER-001', array('version' => 'abc')), array('CUSTOM:1', array('path' => '../etc', 'op' => 'equals', 'value' => '1', 'title' => 't')),
    array('NAME-001', array('regex' => '([')), array('CUSTOM', array())) as list($rid, $in)) {
	try {
		fleet_policy_rule_from($rid, $in);
		check(false, "rule {$rid} with bad settings is refused");
	} catch (InvalidArgumentException $e) {
	}
}
$pols = array(
	array('id' => 1, 'name' => 'Baseline', 'enabled' => 1, 'targets' => array('all'), 'rules' => array('VER-001' => array(array('version' => '1.1.5'), 'audit'), 'SEC-002' => array(array(), 'audit'))),
	array('id' => 2, 'name' => 'Retail', 'enabled' => 1, 'targets' => array('g:2'), 'rules' => array('VER-001' => array(array('version' => '1.1.6'), 'audit'))),
	array('id' => 3, 'name' => 'Denmark', 'enabled' => 1, 'targets' => array('g:1'), 'rules' => array('VER-001' => array(array('version' => '1.1.4'), 'audit'))),
	array('id' => 4, 'name' => 'Shop 7', 'enabled' => 1, 'targets' => array('n:shop7'), 'rules' => array('VER-002' => array(array('version' => '1.1.5'), 'audit'))),
	array('id' => 5, 'name' => 'Off', 'enabled' => 0, 'targets' => array('all'), 'rules' => array('OPS-020' => array(array(), 'audit'))));
$eff = fleet_policy_effective($pols, 'shop7', array(1, 2));
check($eff['VER-001'][2] === 3 && $eff['VER-001'][4] === 'Retail' && $eff['SEC-002'][3] === 'Baseline' && $eff['VER-002'][3] === 'Shop 7' && !isset($eff['OPS-020']),
    'effective rules: firewall over group over all; two groups that disagree are a conflict; disabled policies do nothing');
check(fleet_policy_effective($pols, 'x', array(2))['VER-001'][4] === null, 'one group: no conflict');
check(fleet_policy_update_block(fleet_policy_version_limits($eff), '1.1.6') === 'Pinned to 1.1.5 by policy' &&
    fleet_policy_update_block(array(null, array('1.1.6')), '1.1.6') === null && fleet_policy_update_block(array(null, array('1.1.5')), '1.1.6') === 'Policy allows only 1.1.5',
    'version rules stop updates they do not allow');
check(fleet_policy_update_block(array('1.1.5', null), '') === 'Pinned to 1.1.5 by policy' && fleet_policy_update_block(array(null, array('1.1.6')), '') !== null &&
    fleet_policy_update_block(array(null, null), '') === null, 'an unknown offered version: a pin or an allowed list still blocks');
check(fleet_policy_excepted(array(array('node_id' => 'a', 'rule_id' => 'SEC-002', 'expires' => 50)), 'a', 'SEC-002', 40) !== null &&
    fleet_policy_excepted(array(array('node_id' => 'a', 'rule_id' => 'SEC-002', 'expires' => 50)), 'a', 'SEC-002', 60) === null, 'exceptions expire');

$pid = fleet_policy_save(null, array('name' => 'Test baseline', 'targets' => array('all'), 'enabled' => '1',
    'use' => array('VER-001' => '1', 'OPS-010' => '1'), 'rule' => array('VER-001' => array('version' => '1.1.5'), 'OPS-010' => array('days' => '2'))), 'test');
$crows = fleet_db()->query('SELECT * FROM compliance')->fetchAll();
$nboxes = (int)fleet_db()->query('SELECT COUNT(*) FROM boxes')->fetchColumn();
check(($nboxes === 0) || (count($crows) === 2 * $nboxes), 'saving a policy checks every firewall against it');
try {
	fleet_policy_save(null, array('name' => 'Test baseline', 'targets' => array('all'), 'use' => array('VER-001' => '1'), 'rule' => array('VER-001' => array('version' => '1.1.5'))), 'test');
	check(false, 'policy names are unique');
} catch (InvalidArgumentException $e) {
}
try {
	fleet_policy_save(null, array('name' => 'Empty', 'targets' => array('all')), 'test');
	check(false, 'a policy needs a rule');
} catch (InvalidArgumentException $e) {
}
if ($nboxes > 0) {
	$anode = (string)fleet_db()->query('SELECT node_id FROM boxes LIMIT 1')->fetchColumn();
	fleet_policy_exception_add($anode, 'OPS-010', 'Lab box, backups by hand', date('Y-m-d', time() + 30 * 86400), 'test');
	$st = (string)fleet_db()->query("SELECT state FROM compliance WHERE node_id = " . fleet_db()->quote($anode) . " AND rule_id = 'OPS-010'")->fetchColumn();
	check(in_array($st, array('excepted', 'pass'), true), 'an exception turns a failure into excepted');
}
fleet_policy_delete($pid, 'test');
check((int)fleet_db()->query('SELECT COUNT(*) FROM compliance')->fetchColumn() === 0, 'deleting the last policy clears compliance');

/* ---- lock ---- */
check(fleet_policy_lockable('SEC-002') && fleet_policy_lockable('CUSTOM') && !fleet_policy_lockable('VER-001') && !fleet_policy_lockable('SEC-001'), 'only configuration rules can be locked');
try {
	fleet_policy_rule_from('VER-001', array('version' => '1.1.5', 'mode' => 'lock'));
	check(false, 'a version rule cannot be locked');
} catch (InvalidArgumentException $e) {
}
$lr = fleet_policy_lock_rules(array('SEC-002' => array(array(), 'lock', 1, 'B', null), 'OPS-001' => array(array(), 'lock', 1, 'B', null),
    'CUSTOM:4' => array(array('path' => 'system/ssh/port', 'op' => 'equals', 'value' => '22', 'title' => 'SSH port'), 'lock', 1, 'B', null),
    'NAME-002' => array(array('value' => 'x.net'), 'audit', 1, 'B', null), 'VER-001' => array(array('version' => '1.1.5'), 'lock', 1, 'B', null)));
check(count($lr) === 3 && $lr[0] === array('id' => 'SEC-002', 'title' => 'WebGUI over HTTPS', 'mode' => 'lock', 'path' => 'system/webgui/protocol', 'op' => 'equals', 'value' => 'https') &&
    $lr[1]['op'] === 'regex' && $lr[1]['value'] === '.' && $lr[2]['id'] === 'CUS-004' && $lr[2]['title'] === 'SSH port', 'lock rules in the firewall\'s form; audit and non-config rules stay home');
if (is_file($src . "/src/etc/inc/fleet_guard.inc")) {
	require_once($src . "/src/etc/inc/fleet_guard.inc");
	/* The firewall's own checker accepts every rule Fleet sends. */
	foreach ($lr as $r) {
		check(fleet_rule_valid($r), "the firewall accepts lock rule {$r['id']}");
	}
	$cfgs = array('system/webgui/protocol' => 'https', 'system/timeservers' => 'pool.ntp.org', 'system/ssh/port' => '22');
	$newc = array('system/webgui/protocol' => 'http') + $cfgs;
	$v = fleet_lock_new_violations($lr, function ($p) use ($newc) { return $newc[$p] ?? null; }, function ($p) use ($cfgs) { return $cfgs[$p] ?? null; });
	check(count($v) === 1 && $v[0]['id'] === 'SEC-002', 'a save switching the WebGUI to HTTP is refused by the firewall');
}

/* ---- remediate ---- */
foreach (array(array('SEC-002', 'https'), array('VER-001', null), array('NAME-001', null)) as list($rid, $x)) {
	try {
		fleet_policy_rule_from($rid, ($rid === 'VER-001') ? array('version' => '1.1.5', 'mode' => 'remediate') : (($rid === 'NAME-001') ? array('regex' => '^a', 'mode' => 'remediate') : array('mode' => 'remediate')));
		check(false, "{$rid} cannot be set to fix itself");
	} catch (InvalidArgumentException $e) {
	}
}
list(, $rp, $rmode) = fleet_policy_rule_from('OPS-001', array('fix' => 'pool.ntp.org time.example', 'mode' => 'remediate'));
check($rmode === 'remediate' && $rp['fix'] === 'pool.ntp.org time.example', 'NTP can be fixed, with the servers to set');
$br = fleet_policy_lock_rules(array('OPS-001' => array($rp, 'remediate', 1, 'B', null), 'OPS-003' => array(array('value' => 'Europe/Copenhagen'), 'remediate', 1, 'B', null),
    'SEC-003' => array(array(), 'lock', 1, 'B', null), 'NAME-002' => array(array('value' => 'x.net'), 'audit', 1, 'B', null)));
check(count($br) === 3 && $br[0]['mode'] === 'remediate' && $br[0]['fix'] === 'pool.ntp.org time.example' && $br[2]['mode'] === 'lock', 'the bundle holds lock and remediate rules, not audit ones');
if (function_exists('fleet_remediate_plan')) {
	check(fleet_remediate_plan($br[0], null) === array('set', 'pool.ntp.org time.example') && fleet_remediate_plan($br[1], 'Etc/UTC') === array('set', 'Europe/Copenhagen') &&
	    fleet_remediate_plan($br[2], '') === null, 'the firewall plans the same fixes (and never fixes a lock rule)');
}
$h = hash('sha256', json_encode($rp));
check(fleet_remediate_due(array('OPS-001' => $rp), array(), 1000, false) === array('OPS-001' => $h), 'a new failure is fixed');
check(fleet_remediate_due(array('OPS-001' => $rp), array('OPS-001' => array('time' => 10, 'hash' => $h, 'result' => 'failed')), 99999, false) === array() &&
    fleet_remediate_due(array('OPS-001' => $rp), array('OPS-001' => array('time' => 10, 'hash' => $h, 'result' => 'failed')), 99999, true) === array('OPS-001' => $h),
    'a failed fix is not retried by itself; Fix now tries again');
check(fleet_remediate_due(array('OPS-001' => $rp), array('OPS-001' => array('time' => 10, 'hash' => 'old', 'result' => 'failed')), 99999, false) === array('OPS-001' => $h),
    'changed settings are tried again');
check(fleet_remediate_due(array('OPS-001' => $rp), array('OPS-001' => array('time' => 1000, 'hash' => $h, 'result' => 'fixed')), 2000, false) === array(),
    'a fix that worked waits for the next backup to show it');

/* ---- templates ---- */
$ta = fleet_template_alias_from(array('name' => 'office_nets', 'type' => 'network', 'description' => 'Offices', 'entries' => "10.0.0.0/24  # HQ\n\n192.168.10.0/24\n2001:db8::/48 # v6"));
check($ta['entries'] === array(array('address' => '10.0.0.0/24', 'detail' => 'HQ'), array('address' => '192.168.10.0/24', 'detail' => ''), array('address' => '2001:db8::/48', 'detail' => 'v6')),
    'alias entries from lines with notes');
check(fleet_template_entries_text($ta['entries']) === "10.0.0.0/24  # HQ\n192.168.10.0/24\n2001:db8::/48  # v6", 'and back to text');
foreach (array(array('name' => 'bad name', 'type' => 'host', 'entries' => '1.2.3.4'), array('name' => '_x', 'type' => 'host', 'entries' => '1.2.3.4'),
    array('name' => 'n', 'type' => 'network', 'entries' => '10.0.0.0/33'), array('name' => 'p', 'type' => 'port', 'entries' => '70000'),
    array('name' => 'p', 'type' => 'port', 'entries' => '90:80'), array('name' => 'u', 'type' => 'url', 'entries' => 'http://x'), array('name' => 'e', 'type' => 'host', 'entries' => '')) as $bad) {
	try {
		fleet_template_alias_from($bad);
		check(false, 'a bad alias is refused: ' . json_encode($bad));
	} catch (InvalidArgumentException $e) {
	}
}
check(fleet_template_alias_from(array('name' => 'web', 'type' => 'port', 'entries' => "443\n8000:8080\nhttps_ports"))['entries'][1]['address'] === '8000:8080', 'ports and port ranges');
check(fleet_template_owner('[Fleet:T7] Offices') === 7 && fleet_template_owner('Offices [Fleet:T7]') === null && fleet_template_owner('') === null, 'the ownership marker');
$tb = fleet_template_alias_body(7, $ta);
$remote = array(
	array('name' => 'OFFICE_NETS', 'type' => 'network', 'description' => '[Fleet:T7] Offices', 'entries' => array_slice($ta['entries'], 0, 2)),
	array('name' => 'old_one', 'type' => 'host', 'description' => '[Fleet:T7] gone', 'entries' => array()),
	array('name' => 'local_srv', 'type' => 'host', 'description' => 'made on the box', 'entries' => array()),
	array('name' => 'other_t', 'type' => 'host', 'description' => '[Fleet:T9] x', 'entries' => array()),
);
$items = array($ta, array('name' => 'local_srv', 'type' => 'host', 'description' => '', 'entries' => array(array('address' => '1.1.1.1', 'detail' => ''))),
    array('name' => 'other_t', 'type' => 'host', 'description' => '', 'entries' => array(array('address' => '1.1.1.1', 'detail' => ''))),
    array('name' => 'new_one', 'type' => 'port', 'description' => '', 'entries' => array(array('address' => '22', 'detail' => ''))));
$tp = fleet_template_plan(7, $items, $remote);
$by = array_column($tp, null, 'name');
check($by['office_nets']['action'] === 'update' && $by['office_nets']['detail'] === '+1 -0 entries' && $by['local_srv']['action'] === 'conflict' &&
    $by['other_t']['action'] === 'conflict' && strpos($by['other_t']['detail'], 'Template 9') === 0 && $by['new_one']['action'] === 'create' && $by['old_one']['action'] === 'delete',
    'plan: change, conflicts (local and another template), create, and remove what the template no longer holds');
check(fleet_template_plan_counts($tp) === array('create' => 1, 'update' => 1, 'delete' => 1, 'same' => 0, 'conflict' => 2), 'plan counts');
check(fleet_template_plan(7, array($ta), array($tb))[0]['action'] === 'same', 'a pushed alias is in sync');
check(fleet_template_plan(8, array(), $remote) === array(), 'an empty template never touches other templates\' or local aliases');
$cx = '<freesense><aliases><alias><name>office_nets</name><type>network</type><address>10.0.0.0/24 192.168.10.0/24 2001:db8::/48</address>' .
    '<descr>[Fleet:T7] Offices</descr><detail>HQ||||v6</detail></alias></aliases></freesense>';
check(fleet_template_plan(7, array($ta), fleet_template_aliases_in_config($cx))[0]['action'] === 'same', 'drift from a configuration backup: in sync');
$tid = fleet_template_save(null, array('name' => 'Test nets', 'targets' => array('all'), 'alias' => array(array('name' => 'office_nets', 'type' => 'network', 'entries' => '10.0.0.0/24'))), 'test');
try {
	fleet_template_save(null, array('name' => 'Other', 'targets' => array('all'), 'alias' => array(array('name' => 'OFFICE_NETS', 'type' => 'host', 'entries' => '1.2.3.4'))), 'test');
	check((int)fleet_db()->query('SELECT COUNT(*) FROM boxes')->fetchColumn() === 0, 'two templates cannot push the same alias to the same firewalls');
} catch (InvalidArgumentException $e) {
}
check(fleet_template_get($tid)['items'][0]['name'] === 'office_nets', 'a template is stored');
fleet_template_delete($tid, 'test');
check(fleet_template_get($tid) === null, 'and deleted');

foreach (fleet_template_starters() as $sk => $st) {
	foreach ($st['aliases'] as $sa) {
		fleet_template_alias_from($sa);
	}
	check(count($st['aliases']) > 0, "starter {$sk} is valid");
}

/* ---- users ---- */
check(fleet_users_valid_name('anna.b') && !fleet_users_valid_name('admin') && !fleet_users_valid_name('Admins') && !fleet_users_valid_name('9x y'), 'account names; the firewall\'s own names are refused');
$ug = array(1 => array('name' => 'shop-support', 'description' => 'Status', 'privs' => array('page-dashboard-all')),
    2 => array('name' => 'netteam', 'description' => '', 'privs' => array('page-all')));
$fu = array(array('name' => 'anna', 'fullname' => 'Anna', 'hash' => 'h1', 'ssh_keys' => '', 'expires' => '', 'disabled' => 0, 'groups' => array(1, 2)),
    array('name' => 'bob', 'fullname' => '', 'hash' => 'h2', 'ssh_keys' => '', 'expires' => '', 'disabled' => 1, 'groups' => array(2)),
    array('name' => 'cid', 'fullname' => '', 'hash' => 'h3', 'ssh_keys' => '', 'expires' => '', 'disabled' => 0, 'groups' => array()));
$ud = fleet_users_desired($fu, $ug, array(1));
check($ud['format'] === 'fleet-users-v1' && array_column($ud['groups'], 'name') === array('shop-support') && count($ud['users']) === 1 &&
    $ud['users'][0]['groups'] === array('shop-support') && $ud['users'][0]['bcrypt_hash'] === 'h1', 'a firewall gets only the groups for it and their members');
$ud2 = fleet_users_desired($fu, $ug, array(1, 2));
check(count($ud2['users']) === 2 && $ud2['users'][1]['disabled'] === true, 'disabled users are sent disabled; users without a group go nowhere');
check(fleet_users_plan_counts(array('users' => array('a' => 'create', 'b' => 'same'), 'groups' => array('g' => 'delete'), 'clashes' => array('user admin'), 'skipped_privs' => array('g' => array('x', 'y')))) ===
    array('create' => 1, 'update' => 0, 'delete' => 1, 'same' => 1, 'clashes' => 1, 'skipped' => 2), 'plan counts');
if (is_file($src . '/src/etc/inc/fleet_accounts.inc')) {
	require_once($src . '/src/etc/inc/fleet_accounts.inc');
	/* What the controller sends is what the firewall accepts. */
	$fu[0]['hash'] = password_hash('x', PASSWORD_BCRYPT);
	check(count(fleet_accounts_desired(fleet_users_desired(array($fu[0]), $ug, array(1, 2)))['users']) === 1, 'the firewall accepts the controller\'s set');
}

$ue = fleet_users_from_entry(array('descr' => 'Anna B', 'bcrypt-hash' => '$2y$10$x', 'authorizedkeys' => base64_encode("ssh-ed25519 AAAA k\n"), 'expires' => '01/31/2027', 'disabled' => ''));
check($ue === array('fullname' => 'Anna B', 'hash' => '$2y$10$x', 'ssh_keys' => 'ssh-ed25519 AAAA k', 'expires' => '2027-01-31', 'disabled' => 1), 'adopt reads a firewall user back');
list($btext) = fleet_bundle_make('n1', array(), 5, true);
check(json_decode($btext, true)['lock_accounts'] === true && !isset(json_decode(fleet_bundle_make('n1', array(), 5)[0], true)['lock_accounts']), 'the bundle carries the account lock only when it is on');

/* ---- naming per group ---- */
check(fleet_naming_pattern_problem('{site}-fw{nn}') === null && fleet_naming_pattern_problem('') === null &&
    fleet_naming_pattern_problem('{city}-fw') !== null && fleet_naming_pattern_problem('{nn}-{nnn}') !== null && fleet_naming_pattern_problem('Shop_{nn}') !== null, 'hostname patterns');
check(fleet_naming_domain_ok('shops.example.local') && fleet_naming_domain_ok('hello.fish') && fleet_naming_domain_ok('') && !fleet_naming_domain_ok('local') && !fleet_naming_domain_ok('-x.fish'), 'group domains');
check(fleet_naming_render('{site}-fw{nn}', array('site' => 'Copenhagen HQ'), 3) === 'copenhagen-hq-fw03' && fleet_naming_render('{group}{nnn}', array('group' => 'Retail'), 7) === 'retail007' &&
    fleet_naming_render('{site}-fw', array('site' => ''), 1) === null, 'names from patterns (an empty token cannot make a valid name)');
check(fleet_naming_scope(4, '{site}-fw{nn}', array('site' => 'CPH')) === '4:cph-fw#' && fleet_naming_scope(4, '{site}-fw{nn}', array('site' => 'aar')) !== '4:cph-fw#', 'counters per group and site');
check(fleet_naming_next('{site}-fw{nn}', array('site' => 'cph'), 1, array('cph-fw01', 'CPH-FW02')) === array('cph-fw03', 3) &&
    fleet_naming_next('{site}-fw{nn}', array('site' => 'cph'), 5, array()) === array('cph-fw05', 5), 'the next free name; numbers only go up');
check(fleet_naming_next('edge', array(), 1, array('edge')) === null, 'a pattern without a counter cannot be used twice');
$nre = '/' . fleet_naming_regex('{site}-fw{nn}') . '/';
check(preg_match($nre, 'cph-fw01') === 1 && preg_match($nre, 'copenhagen-hq-fw12') === 1 && preg_match($nre, 'FreeSense') === 0 && preg_match($nre, 'cph-fwx') === 0, 'a hostname follows a pattern');
check(fleet_policy_group_params('domain', array('name' => 'Retail', 'naming_domain' => 'shops.example.local', 'naming_pattern' => '')) === array('value' => 'shops.example.local', '_group' => 'Retail') &&
    fleet_policy_group_params('pattern', array('name' => 'Retail', 'naming_domain' => 'x.y', 'naming_pattern' => '')) === array('_none' => 1) &&
    fleet_policy_group_params('domain', null) === array('_none' => 1), 'rules take the value from the firewall\'s naming group');
check(fleet_policy_check('NAME-003', array('value' => 'shops.example.local'), $pf)[1] === 'system/domain: "lab.arpa" (equals shops.example.local)' &&
    fleet_policy_check('NAME-004', array('regex' => fleet_naming_regex('{site}-{role}{nn}')), $pf)[0] === 'pass' &&
    fleet_policy_check('NAME-003', array('_none' => 1), $pf)[0] === 'unknown', 'group domain and pattern checked against the configuration');
check(fleet_policy_lock_rules(array('NAME-003' => array(array('_none' => 1), 'remediate', 1, 'B', null))) === array() &&
    fleet_policy_lock_rules(array('NAME-003' => array(array('value' => 'a.b'), 'remediate', 1, 'B', null)))[0]['value'] === 'a.b', 'the firewall gets its own group\'s domain to fix');

/* ---- deployment factory ---- */
$frows = fleet_factory_rows("site,label,serial,instance_id,hostname\ncph,Copenhagen 1,PT-1,,\n\ncph;Copenhagen 2;PT-2;;\naar,Aarhus,,i-9,AAR-EDGE\n");
check(count($frows) === 3 && $frows[1]['label'] === 'Copenhagen 2' && $frows[1]['serial'] === 'PT-2' && $frows[2]['hostname'] === 'aar-edge' && $frows[0]['line'] === 2,
    'rows from pasted CSV (header skipped, comma or semicolon)');
$fnaming = array('gid' => 3, 'group' => 'Retail', 'pattern' => '{site}-fw{nn}', 'domain' => 'shops.example.local');
list($fplan, $fcount) = fleet_factory_plan($frows, array('mode' => 'attended'), $fnaming, array('3:cph-fw#' => 4), array('cph-fw05'));
check($fplan[0]['hostname'] === 'cph-fw04' && $fplan[1]['hostname'] === 'cph-fw06' && $fplan[2]['hostname'] === 'aar-edge' && $fplan[0]['domain'] === 'shops.example.local' &&
    $fcount['3:cph-fw#'] === 7 && empty($fplan[0]['problems']), 'rows are named from the group: counters go on, taken names are skipped, a typed name wins');
list($fbad) = fleet_factory_plan(fleet_factory_rows("cph,Shop,,,\ncph,shop,,,\n,Pop-up,,,\nx,Bad,a b,,\nosl,Taken,,,aar-edge"), array('mode' => 'unattended'), $fnaming, array(), array('aar-edge'));
check(strpos(implode(' ', $fbad[1]['problems']), 'same label') !== false && strpos(implode(' ', $fbad[2]['problems']), 'site') !== false &&
    strpos(implode(' ', $fbad[3]['problems']), 'serial') !== false && strpos(implode(' ', $fbad[4]['problems']), 'already') !== false &&
    strpos(implode(' ', $fbad[0]['problems']), 'Unattended needs') !== false, 'E120 problems: duplicate label, no site for the pattern, bad serial, taken name, unattended without binding');
check(fleet_enroll_binding_ok('', '', array()) && fleet_enroll_binding_ok('PT-1', '', array('serial' => 'PT-1')) && !fleet_enroll_binding_ok('PT-1', '', array('serial' => 'PT-2')) &&
    fleet_enroll_binding_ok('PT-1', 'i-9', array('serial' => '', 'instance_id' => 'i-9')) && !fleet_enroll_binding_ok('', 'i-9', array()), 'binding to a serial or instance id (E121 otherwise)');
$fenc = fleet_factory_encrypt('bundle bytes', 'correct horse battery', 1000);
check(fleet_factory_decrypt($fenc, 'correct horse battery', 1000) === 'bundle bytes' && fleet_factory_decrypt($fenc, 'wrong', 1000) === null && strncmp($fenc, 'Salted__', 8) === 0,
    'the bundle encryption (OpenSSL salted format)');
if (trim((string)@shell_exec('command -v openssl')) !== '') {
	$ftmp = tempnam(sys_get_temp_dir(), 'fenc');
	file_put_contents($ftmp, fleet_factory_encrypt('opens anywhere', 'correct horse battery', 1000));
	check(trim((string)shell_exec('openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000 -pass pass:"correct horse battery" -in ' . escapeshellarg($ftmp))) === 'opens anywhere',
	    'the openssl command opens the bundle');
	@unlink($ftmp);
}
check(fleet_factory_passphrase_problem('short') !== null && fleet_factory_passphrase_problem('aaaaaaaaaaaaaaa') !== null && fleet_factory_passphrase_problem('Spring rollout 2026') === null, 'bundle passphrases');
$fseed = fleet_factory_seed(fleet_join_link_build('fw.example.net:8443', 'aabbccddeeff', str_repeat('A', 43), str_repeat('ab', 32)), 'pin', 'FLT-AAAA-BBBB', '123456');
check(!isset($fseed['key']) && isset($fseed['sealed_key']['data']) && !isset(fleet_factory_seed('l', 'attended', 'FLT-X', null)['sealed_key']) &&
    fleet_factory_seed('l', 'unattended', 'FLT-X', null)['key'] === 'FLT-X', 'seeds: attended without key, PIN sealed, unattended with key');
if (is_file($src . '/src/etc/inc/fleet_seed.inc')) {
	require_once($src . '/src/etc/inc/fleet_seed.inc');
	check(fleet_seed_open_key($fseed['sealed_key'], '123456') === 'FLT-AAAA-BBBB' && fleet_seed_open_key($fseed['sealed_key'], '654321') === null,
	    'the firewall opens a Factory PIN seed with the right PIN only');
	check(fleet_seed_parse(json_encode($fseed))['mode'] === 'pin', 'the firewall accepts the Factory seed');
}
check(fleet_batch_row_state(array('box' => null, 'inv_state' => 'open', 'expires' => 10), 20) === 'expired' && fleet_batch_row_state(array('box' => 'n1', 'inv_state' => 'used', 'expires' => 0), 20) === 'joined' &&
    fleet_batch_row_state(array('box' => null, 'inv_state' => 'open', 'expires' => 99), 20) === 'waiting', 'batch row states');

fleet_db()->prepare('INSERT INTO batches (name, settings, created, who) VALUES (?, ?, ?, ?)')->execute(array('t', '{}', 1, 't'));
check(is_array(fleet_batch_rows((int)fleet_db()->lastInsertId())), 'batch rows can be read (the query matches the schema)');

/* ---- firewalls list ---- */
$fwb = function ($label, $state, $version, $gids, $extra = array()) {
	return array_merge(array('id' => $label, 'label' => $label, 'host' => strtolower($label), 'overlay' => 'fd00::1', 'state' => $state, 'version' => $version,
	    'groups' => array_map(function ($g) { return array('id' => $g, 'name' => 'g' . $g, 'color' => ''); }, $gids), 'breakglass' => false, 'rollback' => true,
	    'policy' => 0, 'update' => null, 'seen' => 0, 'managed' => true), $extra);
};
$fwall = array($fwb('Alpha', 'online', '1.1.5', array(1)), $fwb('Bravo', 'offline', '1.1.4', array(1, 2)), $fwb('Charlie', 'online', '1.1.5', array(), array('policy' => 2, 'update' => array('info', 'Update: 1.1.6'))),
    $fwb('Delta', 'degraded', '1.1.5', array(2), array('rollback' => false)));
$names = function ($l) { return implode(',', array_column($l, 'label')); };
check($names(fleet_firewalls_filter($fwall, array('q' => 'char'))) === 'Charlie' && $names(fleet_firewalls_filter($fwall, array('state' => 'online'))) === 'Alpha,Charlie' &&
    $names(fleet_firewalls_filter($fwall, array('group' => '2'))) === 'Bravo,Delta' && $names(fleet_firewalls_filter($fwall, array('version' => '1.1.4'))) === 'Bravo',
    'firewall list: search, state, group and version filters');
check($names(fleet_firewalls_filter($fwall, array('problem' => 'attention'))) === 'Bravo,Delta' && $names(fleet_firewalls_filter($fwall, array('problem' => 'update'))) === 'Charlie' &&
    $names(fleet_firewalls_filter($fwall, array('problem' => 'policy'))) === 'Charlie' && $names(fleet_firewalls_filter($fwall, array('problem' => 'unprotected'))) === 'Delta',
    'firewall list: quick filters');
check($names(fleet_firewalls_filter($fwall, array('sort' => 'version'))) === 'Alpha,Charlie,Delta,Bravo' && array_keys(fleet_firewalls_versions($fwall)) === array('1.1.5', '1.1.4'),
    'firewall list: version sort and the version filter');

echo "Fleet controller tests: OK\n";
