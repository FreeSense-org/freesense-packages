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
if (!function_exists('gettext')) {
	function gettext($t) { return $t; }
}
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
check((fleet_nav_item(0, 0)['hidden'] === false) && (fleet_nav_item(0, 0)['kind'] === 'pass') && (fleet_nav_item(0, 0)['badge'] === 0) &&
    (fleet_nav_item(2, 0)['busy'] === true) && (fleet_nav_item(2, 0)['badge'] === 2) && (fleet_nav_item(2, 0)['kind'] === 'info') &&
    (fleet_nav_item(2, 1)['kind'] === 'block') && (fleet_nav_item(0, 1)['label'] === 'FreeSense Fleet: 1 action failed') &&
    (fleet_nav_item(0, 0, 3, 1)['kind'] === 'block') && (fleet_nav_item(0, 0, 3, 1)['badge'] === 3) && (fleet_nav_item(1, 0, 0, 2)['kind'] === 'warn') &&
    (fleet_nav_item(0, 0)['panel'] === '/fleet/fleet_nav.php?panel=1'),
    'top bar: always there, green when fine; failures, then offline, then degraded, then running decide the count; it opens a panel');
check(strpos(fleet_nav_panel_html(time()), 'fs-navpanel-counts') !== false, 'the top-bar panel from the store');
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

/* ---- alerts ---- */
check(fleet_alert_classify('state', 'n-abc123 (Shop): online -> offline (FLEET-E105)')[0] === 'offline' && fleet_alert_classify('state', 'n-abc123 (Shop): online -> offline')[1] === 'n-abc123' &&
    fleet_alert_classify('state', 'n-abc123 (Shop): offline -> online')[0] === 'online' && fleet_alert_classify('state', 'n-abc123 (Shop): new -> online') === null &&
    fleet_alert_classify('state', 'n-abc123 (Shop): online -> degraded') === null, 'alerts from state changes: offline and back, not first contact or degraded');
check(fleet_alert_classify('policy', 'FLEET-E321: Lock suspended on Shop')[0] === 'breakglass' && fleet_alert_classify('policy', 'FLEET-E320: Shop: the fix failed')[0] === 'policy' &&
    fleet_alert_classify('policy', 'Baseline: 4 rules for all') === null && fleet_alert_classify('replicas', 'Sync failed: x')[0] === 'copies' &&
    fleet_alert_classify('replicas', 'Copies synced to 2 firewalls (3 items each)') === null && fleet_alert_classify('pending', 'e-1 for t')[0] === 'approval' &&
    fleet_alert_classify('groups', 'x') === null, 'alerts from audit entries: only failures and things that need someone');
$ach = array('enabled' => 1, 'events' => array('offline', 'op_failed'), 'min_severity' => 'warning');
check(fleet_alert_wanted($ach, 'offline', 'critical') && !fleet_alert_wanted($ach, 'online', 'info') && !fleet_alert_wanted($ach, 'op_failed', 'info') && fleet_alert_wanted($ach, 'test', 'info') &&
    !fleet_alert_wanted(array('enabled' => 0) + $ach, 'offline', 'critical'), 'a channel gets the alerts it chose, at its severity, and nothing when off');
$amsg = array('title' => 'Firewall offline: Shop', 'text' => 'No answer', 'severity' => 'critical', 'node' => 'n1', 'time' => 'now', 'event' => 'offline', 'link' => 'https://ctl/fleet/x');
$tg = fleet_alert_request('telegram', array('token' => '123:abc', 'chat' => '-100'), $amsg);
$nt = fleet_alert_request('ntfy', array('url' => 'https://ntfy.sh/t', 'token' => ''), $amsg);
$go = fleet_alert_request('gotify', array('url' => 'https://g.example/', 'token' => 'tok'), $amsg);
check($tg[0] === 'https://api.telegram.org/bot123:abc/sendMessage' && json_decode($tg[2], true)['chat_id'] === '-100' && in_array('Priority: 5', $nt[1], true) && $nt[2] === 'No answer' &&
    $go[0] === 'https://g.example/message' && in_array('X-Gotify-Key: tok', $go[1], true) && strpos(json_decode(fleet_alert_request('slack', array('url' => 'https://h'), $amsg)[2], true)['text'], '[CRITICAL]') === 0 &&
    json_decode(fleet_alert_request('webhook', array('url' => 'https://h'), $amsg)[2], true)['source'] === 'freesense-fleet' && fleet_alert_request('email', array(), $amsg) === null,
    'the request each channel type makes');
check(fleet_alert_url_ok('https://hooks.slack.com/services/A/B/C') && !fleet_alert_url_ok('javascript:alert(1)') && !fleet_alert_url_ok('https://a b'), 'channel addresses');
$a1 = fleet_alert('offline', 'n-merge', 'first');
$a2 = fleet_alert('offline', 'n-merge', 'again');
check(is_int($a1) && ($a2 === null) && (int)fleet_db()->query("SELECT repeats FROM alerts WHERE id = {$a1}")->fetchColumn() === 1, 'the same alert within 15 minutes is merged, not sent again');
fleet_audit('poll', 'state', 'n-audit1 (Shop): online -> offline');
check((int)fleet_db()->query("SELECT COUNT(*) FROM alerts WHERE event = 'offline' AND node_id = 'n-audit1'")->fetchColumn() === 1, 'an audit entry raises its alert');
$aop = fleet_op_start('n-op1', 'reboot', 'Reboot', 'test');
fleet_op_set($aop, 'failed', 'No answer');
fleet_op_set($aop, 'failed', 'Still no answer');
check((int)fleet_db()->query("SELECT COUNT(*) FROM alerts WHERE event = 'op_failed' AND node_id = 'n-op1'")->fetchColumn() === 1, 'a failed operation raises one alert');
$cid = fleet_alert_channel_save(null, array('name' => 'NOC', 'type' => 'telegram', 'cfg_token' => '123456:secret-token', 'cfg_chat' => '-1001', 'events' => array('offline', 'bogus'), 'enabled' => '1'), 'test');
$crow = fleet_alert_channel($cid);
check(strpos(json_encode($crow['config']), 'secret-token') === false && fleet_alert_config_open($crow)['token'] === '123456:secret-token' && $crow['events'] === array('offline'),
    'channel secrets are stored sealed; unknown alert kinds are dropped');
fleet_alert_channel_save($cid, array('name' => 'NOC 2', 'cfg_token' => '', 'cfg_chat' => '-1002', 'events' => array('offline'), 'enabled' => '1'), 'test');
check(fleet_alert_config_open(fleet_alert_channel($cid))['token'] === '123456:secret-token' && fleet_alert_channel($cid)['config']['chat'] === '-1002', 'an empty secret on a change keeps the stored one');
$thrown = false;
try {
	fleet_alert_channel_save(null, array('name' => 'Bad', 'type' => 'webhook', 'cfg_url' => 'ftp://x'), 'test');
} catch (InvalidArgumentException $e) {
	$thrown = true;
}
check($thrown, 'a bad webhook address is refused');
check(strpos(fleet_alert_report_text(array('boxes' => 3, 'online' => 2, 'degraded' => 0, 'offline' => 1, 'ops' => 5, 'ops_failed' => 1, 'backups' => 3, 'backups_failed' => 0, 'compliance' => 90, 'alerts' => 2)), '3 firewalls: 2 online') === 0,
    'the daily report text');
check(is_array(fleet_alert_report_counts(time())), 'the daily report counts (queries match the schema)');

/* ---- NOC screens ---- */
list($kn, $kp) = fleet_kiosk_networks("10.20.0.15\n10.20.5.0/24, fd00::/64");
check($kp === null && $kn === array('10.20.0.15/32', '10.20.5.0/24', 'fd00::/64'), 'screen networks: addresses become /32 or /128, lists split on lines and commas');
check(fleet_kiosk_networks('0.0.0.0/0')[1] !== null && fleet_kiosk_networks('')[1] !== null && fleet_kiosk_networks('10.0.0.0/33')[1] !== null && fleet_kiosk_networks('kiosk')[1] !== null,
    'screen networks: everywhere, nothing, a bad prefix and text are refused');
check(fleet_kiosk_ip_allowed('10.20.5.77', $kn) && fleet_kiosk_ip_allowed('10.20.0.15', $kn) && !fleet_kiosk_ip_allowed('10.20.0.16', $kn) && !fleet_kiosk_ip_allowed('10.20.6.1', $kn) &&
    fleet_kiosk_ip_allowed('fd00::1234', $kn) && !fleet_kiosk_ip_allowed('fd01::1', $kn) && !fleet_kiosk_ip_allowed('junk', $kn) &&
    fleet_kiosk_ip_allowed('192.168.1.130', array('192.168.1.128/25')) && !fleet_kiosk_ip_allowed('192.168.1.127', array('192.168.1.128/25')), 'a screen works only from its networks');
$kdata = array('headline' => 'x', 'total' => 2, 'counts' => array('online' => 1, 'offline' => 1), 'checked' => 1, 'now' => 2, 'boxes' => array(
    array('label' => 'Copenhagen HQ', 'host' => 'cph-fw01', 'state' => 'offline', 'groups' => array(array('id' => 1, 'name' => 'Retail', 'color' => '')), 'version' => '1.1.5', 'seen' => 1,
        'policy' => 0, 'breakglass' => false, 'update' => null, 'op' => null, 'problem' => 'FLEET-E105: no answer from 100.64.0.3'),
    array('label' => 'Oslo', 'host' => 'osl-fw01', 'state' => 'online', 'groups' => array(), 'version' => '1.1.5', 'seen' => 1, 'policy' => 1, 'breakglass' => false,
        'update' => array('info', 'Update'), 'op' => array('text' => 'Updating cph', 'progress' => 40), 'problem' => '')));
$khid = fleet_kiosk_view($kdata, array(array('title' => 'Update Retail', 'done' => 1, 'total' => 3, 'percent' => 33)), true, 'NOC');
$kjson = json_encode($khid);
check(strpos($kjson, 'Copenhagen') === false && strpos($kjson, 'cph-fw01') === false && strpos($kjson, '100.64') === false && strpos($kjson, 'Retail') === false,
    'hidden names: no labels, hostnames, group names, addresses, error texts or operation titles');
check($khid['boxes'][0]['name'] === 'Firewall 1' && $khid['boxes'][0]['problem'] === '' && $khid['boxes'][1]['update'] === true && $khid['ops'][0]['title'] === 'Fleet operation',
    'hidden names: firewalls are numbered and error texts are left out');
check(fleet_kiosk_view($kdata, array(), false, 'NOC')['boxes'][0]['name'] === 'Copenhagen HQ', 'shown names: the labels are there');
list($kid, $kkey) = fleet_kiosk_create(array('name' => 'Wall', 'networks' => '10.20.5.0/24'), 'test');
check(strpos($kkey, 'fkk_') === 0 && strpos(json_encode(fleet_db()->query("SELECT * FROM kiosk_keys WHERE id = {$kid}")->fetch()), $kkey) === false, 'a kiosk key is kept only as a hash');
check(fleet_kiosk_check($kkey, '10.20.5.9', time())[0]['name'] === 'Wall' && fleet_kiosk_check($kkey, '10.30.0.1', time())[0] === null &&
    fleet_kiosk_check($kkey . 'x', '10.20.5.9', time())[0] === null && fleet_kiosk_check('nope', '10.20.5.9', time())[0] === null, 'a key works from its networks only, and only that key');
fleet_kiosk_revoke($kid, 'test');
check(fleet_kiosk_check($kkey, '10.20.5.9', time())[0] === null, 'a revoked key stops at once');

/* ---- settings templates ---- */
$tsbad = function (string $kind, array $in) {
	try {
		fleet_tset_from($kind, $in);
	} catch (InvalidArgumentException $e) {
		return true;
	}
	return false;
};
check(fleet_tset_from('time', array('set_timezone' => 'Europe/Copenhagen', 'set_timeservers' => "0.pool.ntp.org, 1.pool.ntp.org\n10.0.0.1")) ===
    array('timezone' => 'Europe/Copenhagen', 'timeservers' => array('0.pool.ntp.org', '1.pool.ntp.org', '10.0.0.1')) &&
    $tsbad('time', array('set_timezone' => 'Mars/Base', 'set_timeservers' => 'a.b')) && $tsbad('time', array('set_timezone' => 'UTC', 'set_timeservers' => 'bad host!')),
    'time templates: a real time zone and up to 5 NTP servers');
check(fleet_tset_from('dns', array('set_dnsservers' => "9.9.9.9\n2620:fe::fe", 'set_dnsallowoverride' => '1')) === array('dnsservers' => array('9.9.9.9', '2620:fe::fe'), 'dnsallowoverride' => true) &&
    $tsbad('dns', array('set_dnsservers' => 'dns.example.com')) && $tsbad('dns', array('set_dnsservers' => '')), 'DNS templates: addresses only, at least one');
check($tsbad('snmp', array('set_enable' => '1', 'set_rocommunity' => 'public')) && $tsbad('snmp', array('set_enable' => '1', 'set_rocommunity' => 'abc')) &&
    fleet_tset_from('snmp', array('set_enable' => '1', 'set_rocommunity' => ''), array('rocommunity' => 'kept-secret'))['rocommunity'] === 'kept-secret' &&
    !$tsbad('snmp', array()), 'SNMP templates: never "public", a short community is refused, an empty one on a change keeps the old');
check($tsbad('syslog', array('set_enable' => '1', 'set_servers' => '')) && $tsbad('syslog', array('set_enable' => '1', 'set_servers' => '12345')) &&
    $tsbad('syslog', array('set_enable' => '1', 'set_servers' => 'a.example b.example c.example d.example')) &&
    fleet_tset_from('syslog', array('set_enable' => '1', 'set_servers' => 'logs.example.net:5514', 'set_contents' => 'some', 'set_contents_list' => array('filter', 'bogus')))['contents'] === array('filter'),
    'syslog templates: 1 to 3 servers (a bare number is refused), only known log kinds');
$tsxml = '<?xml version="1.0"?><freesense><system><timezone>Etc/UTC</timezone><timeservers>pool.ntp.org</timeservers><dnsserver>1.1.1.1</dnsserver><dnsserver>8.8.8.8</dnsserver>' .
    '</system><snmpd><syslocation>HQ</syslocation><syscontact></syscontact><rocommunity>s3cret</rocommunity></snmpd><syslog><enable></enable><remoteserver>10.0.9.5</remoteserver>' .
    '<filter></filter><system></system></syslog></freesense>';
check(fleet_tset_from_config('time', $tsxml) === array('timezone' => 'Etc/UTC', 'timeservers' => array('pool.ntp.org')) &&
    fleet_tset_from_config('dns', $tsxml) === array('dnsservers' => array('1.1.1.1', '8.8.8.8'), 'dnsallowoverride' => false) &&
    fleet_tset_from_config('snmp', $tsxml) === array('enable' => false, 'syslocation' => 'HQ', 'syscontact' => '') &&
    fleet_tset_from_config('syslog', $tsxml) === array('enable' => true, 'servers' => array('10.0.9.5'), 'ipproto' => 'ipv4', 'contents' => array('system', 'filter')) &&
    fleet_tset_from_config('time', 'not xml') === null, 'settings read from a config backup');
check(fleet_tset_current('dns', array('dnsservers' => array(array('address' => '1.1.1.1', 'hostname' => ''), array('address' => '8.8.8.8')), 'dnsallowoverride' => false)) ===
    fleet_tset_from_config('dns', $tsxml) && fleet_tset_current('time', array('timezone' => 'Etc/UTC', 'timeservers' => 'pool.ntp.org')) === fleet_tset_from_config('time', $tsxml),
    'the route and the backup give the same comparable settings');
$tsd = fleet_tset_diff('time', array('timezone' => 'Europe/Copenhagen', 'timeservers' => array('pool.ntp.org')), fleet_tset_from_config('time', $tsxml));
check(count($tsd) === 1 && $tsd[0][0] === 'timezone' && $tsd[0][2] === 'Etc/UTC' && $tsd[0][3] === 'Europe/Copenhagen' &&
    fleet_tset_diff('dns', array('dnsservers' => array('8.8.8.8', '1.1.1.1'), 'dnsallowoverride' => false), fleet_tset_from_config('dns', $tsxml))[0][0] === 'dnsservers' &&
    fleet_tset_diff('syslog', array('enable' => false, 'servers' => array(), 'ipproto' => 'ipv4', 'contents' => 'all'), array('enable' => false, 'servers' => array('x'), 'ipproto' => 'ipv6', 'contents' => 'all')) === array() &&
    fleet_tset_diff('snmp', array('enable' => true, 'syslocation' => 'HQ', 'syscontact' => '', 'rocommunity' => 'x'), fleet_tset_from_config('snmp', $tsxml))[0][0] === 'enable',
    'the difference: changed fields only, DNS order matters, nothing else counts while a service stays off, the community is never compared');
check(fleet_tset_body('time', array('timezone' => 'UTC', 'timeservers' => array('a', 'b'))) === array('timezone' => 'UTC', 'timeservers' => 'a b') &&
    fleet_tset_body('dns', array('dnsservers' => array('9.9.9.9'), 'dnsallowoverride' => false))['dnsservers'] === array(array('address' => '9.9.9.9')) &&
    fleet_tset_body('syslog', array('enable' => false, 'servers' => array('x'), 'ipproto' => 'ipv4', 'contents' => 'all')) === array('enable' => false, 'servers' => array()),
    'the request bodies');
$tsid = fleet_template_save(null, array('name' => 'Lab SNMP', 'kind' => 'snmp', 'targets' => array('all'), 'set_enable' => '1', 'set_syslocation' => 'Lab', 'set_rocommunity' => 'lab-community-1'), 'test');
$tst = fleet_template_get($tsid);
check($tst['kind'] === 'snmp' && strpos(json_encode($tst['settings']), 'lab-community-1') === false && fleet_template_settings_open($tst)['rocommunity'] === 'lab-community-1',
    'the SNMP community is stored sealed');
$tsthrown = false;
try {
	fleet_template_save(null, array('name' => 'Second SNMP', 'kind' => 'snmp', 'targets' => array('all'), 'set_enable' => '1', 'set_rocommunity' => 'other-community'), 'test');
} catch (InvalidArgumentException $e) {
	$tsthrown = strpos($e->getMessage(), 'one of each') !== false;
}
check($tsthrown, 'two templates of the same kind cannot meet on a firewall');
fleet_template_save($tsid, array('name' => 'Lab SNMP', 'targets' => array('all'), 'set_enable' => '1', 'set_syslocation' => 'Lab 2', 'set_rocommunity' => ''), 'test');
check(fleet_template_settings_open(fleet_template_get($tsid))['rocommunity'] === 'lab-community-1' && fleet_template_get($tsid)['settings']['syslocation'] === 'Lab 2',
    'changing a settings template keeps its kind and its community');
check(fleet_template_settings_plan('time', array())[0]['action'] === 'same' && fleet_template_settings_plan('time', $tsd)[0]['action'] === 'update' &&
    fleet_template_plan_counts(fleet_template_settings_plan('time', $tsd))['update'] === 1, 'settings differences count like alias changes');
fleet_template_delete($tsid, 'test');

/* ---- template drift ---- */
$dt = array('id' => 7, 'kind' => 'aliases', 'items' => array(
    array('name' => 'office', 'type' => 'network', 'description' => 'Offices', 'entries' => array(array('address' => '10.0.0.0/24', 'detail' => 'HQ'))),
    array('name' => 'ports', 'type' => 'port', 'description' => 'Ports', 'entries' => array(array('address' => '443', 'detail' => '')))));
$dremote = array(
    array('name' => 'office', 'type' => 'network', 'description' => '[Fleet:T7] Offices (local)', 'entries' => array(array('address' => '10.0.0.0/24', 'detail' => 'HQ'), array('address' => '10.9.0.0/24', 'detail' => 'Annex'))),
    array('name' => 'ports', 'type' => 'port', 'description' => '[Fleet:T7] Ports', 'entries' => array(array('address' => '443', 'detail' => ''))),
    array('name' => 'theirs', 'type' => 'host', 'description' => 'local', 'entries' => array()));
list($dfields, $dchanged) = fleet_template_adopted($dt, $dremote);
check($dchanged === array('office') && count($dfields['items'][0]['entries']) === 2 && $dfields['items'][0]['description'] === 'Offices (local)' &&
    $dfields['items'][1] === $dt['items'][1] && count($dfields['items']) === 2, 'adopt takes the firewall\'s version of the template\'s own aliases only');
check(fleet_template_plan(7, $dfields['items'], $dremote)[0]['action'] === 'same', 'after adopting, that firewall is in sync');
list(, $dnone) = fleet_template_adopted(array('id' => 7, 'kind' => 'aliases', 'items' => $dt['items']), array(array('name' => 'office', 'type' => 'network',
    'description' => 'Someone else', 'entries' => array())));
check($dnone === array(), 'an alias another owner holds is never adopted');
list($dset, $dsc) = fleet_template_adopted(array('id' => 8, 'kind' => 'snmp', 'settings' => array('enable' => true, 'syslocation' => 'HQ', 'syscontact' => '', 'rocommunity' => 'sealed')),
    array('enable' => true, 'syslocation' => 'Rack 4', 'syscontact' => ''));
check($dset['settings']['syslocation'] === 'Rack 4' && $dset['settings']['rocommunity'] === 'sealed' && $dsc === array('Location'), 'adopt takes settings, keeps the secret');
$dtid = fleet_template_save(null, array('name' => 'Drift test', 'kind' => 'time', 'targets' => array('all'), 'set_timezone' => 'Etc/UTC', 'set_timeservers' => 'pool.ntp.org'), 'test');
$dtt = fleet_template_get($dtid);
$dthrown = false;
try {
	fleet_template_ignore($dtt, 'n-x', '  ', 'test');
} catch (InvalidArgumentException $e) {
	$dthrown = true;
}
fleet_template_ignore($dtt, 'n-x', 'Ships in another time zone', 'test');
check($dthrown && fleet_template_ignores($dtid)['n-x']['reason'] === 'Ships in another time zone', 'ignoring a firewall needs a reason');
fleet_template_unignore($dtt, 'n-x', 'test');
check(fleet_template_ignores($dtid) === array(), 'stop ignoring');
fleet_template_delete($dtid, 'test');

/* ---- connection manager ---- */
$cfleet = array('method' => 'wireguard', 'iface' => 'lan');
check(fleet_conn_effective(array('method' => ''), array(), $cfleet) === array('wireguard', 'lan', 'fleet', null) &&
    fleet_conn_effective(array('method' => ''), array('Retail' => array('method' => 'direct', 'iface' => 'opt2'), 'All' => array('method' => '')), $cfleet) === array('direct', 'opt2', 'group:Retail', null) &&
    fleet_conn_effective(array('method' => 'tailscale', 'iface' => 'tailscale'), array('Retail' => array('method' => 'direct', 'iface' => 'opt2')), $cfleet)[2] === 'firewall',
    'the most specific choice wins: firewall, then group, then the fleet');
$cconf = fleet_conn_effective(array('method' => ''), array('Retail' => array('method' => 'direct', 'iface' => 'lan'), 'Denmark' => array('method' => 'tailscale', 'iface' => 'tailscale')), $cfleet);
check($cconf[3] === array('Denmark', 'Retail') && $cconf[2] === 'group:Denmark', 'two groups that disagree are a conflict, shown, never silent');
check(fleet_conn_effective(array('method' => ''), array('A' => array('method' => 'direct', 'iface' => 'lan'), 'B' => array('method' => 'direct', 'iface' => 'lan')), $cfleet)[3] === null,
    'groups that agree are no conflict');
check(fleet_conn_advise(array('public' => 'yes', 'private' => 'no', 'thirdparty' => 'no', 'udp' => 'yes'))[0] === 'wireguard' &&
    fleet_conn_advise(array('public' => 'no', 'private' => 'yes', 'thirdparty' => 'no', 'udp' => 'no'))[0] === 'direct' &&
    fleet_conn_advise(array('public' => 'no', 'private' => 'no', 'thirdparty' => 'yes', 'udp' => 'unsure'))[0] === 'tailscale' &&
    fleet_conn_advise(array('public' => 'yes', 'private' => 'no', 'thirdparty' => 'unsure', 'udp' => 'no'))[0] === 'tailscale' &&
    fleet_conn_advise(array('public' => 'no', 'private' => 'no', 'thirdparty' => 'no', 'udp' => 'no'))[0] === 'wireguard',
    'the advisor: public + UDP -> tunnel, shared network -> direct, no public address or no UDP -> Tailscale when allowed');
check(count(fleet_conn_advise(array('public' => 'no', 'private' => 'no', 'thirdparty' => 'yes', 'udp' => 'yes'))[2]) >= 2 && !empty(fleet_conn_requirements('direct')),
    'every recommendation says what it needs');
$cst = array('method' => 'direct', 'address' => '10.0.0.1', 'ok' => true, 'since' => 1, 'checked' => 1);
list($cdown, $calert) = fleet_conn_after($cst, false, 'timed out', 100);
list($cup, $calert2) = fleet_conn_after($cdown, true, '', 200);
list(, $calert3) = fleet_conn_after($cup, true, '', 300);
check(($calert === 'down') && ($cdown['error'] === 'timed out') && ($calert2 === 'up') && ($calert3 === null) && ($cup['since'] === 200), 'a path that stops or starts answering is noted once each way');
check(!fleet_conn_use_path(null, 100) && fleet_conn_use_path($cst, 100) && !fleet_conn_use_path($cdown, 100 + 60) && fleet_conn_use_path($cdown, 100 + FLEET_CONN_RETRY) &&
    !fleet_conn_use_path(array('method' => 'wireguard', 'address' => 'x', 'ok' => true), 1), 'a path is used while it answers, and tried again after a pause');
check(fleet_conn_pending(array('want' => array('direct', 'lan', 'fleet', null), 'state' => null)) && !fleet_conn_pending(array('want' => array('wireguard', '', 'fleet', null), 'state' => null)) &&
    fleet_conn_pending(array('want' => array('direct', 'opt2', 'fleet', null), 'state' => array('method' => 'direct', 'iface' => 'lan'))) &&
    fleet_conn_pending(array('want' => array('wireguard', '', 'fleet', null), 'state' => array('method' => 'tailscale', 'iface' => 'tailscale'))),
    'a change is pending when the method or the direct interface differs');
$cbad = function (array $in, bool $fleet) {
	try {
		fleet_conn_cfg_from($in, $fleet);
	} catch (InvalidArgumentException $e) {
		return true;
	}
	return false;
};
check($cbad(array('conn_method' => 'direct', 'conn_iface' => 'wan'), false) && $cbad(array('conn_method' => 'direct', 'conn_iface' => ''), false) && $cbad(array('conn_method' => ''), true) &&
    $cbad(array('conn_method' => 'ssh'), false) && fleet_conn_cfg_from(array('conn_method' => ''), false) === array('method' => '', 'iface' => '') &&
    fleet_conn_cfg_from(array('conn_method' => 'tailscale', 'conn_iface' => 'lan'), false)['iface'] === 'tailscale', 'connection choices: never WAN, the fleet needs a method, Tailscale always on tailscale0');
fleet_db()->exec("INSERT INTO fleet_groups (name, description, color, created) VALUES ('ConnTest', '', '', 1)");
$cgid = (int)fleet_db()->lastInsertId();
fleet_conn_set_group($cgid, array('conn_method' => 'direct', 'conn_iface' => 'opt2'), 'test');
check(fleet_group_get($cgid)['conn_method'] === 'direct' && is_array(fleet_conn_overview()), 'group choices are stored and the overview reads');
fleet_db()->exec("DELETE FROM fleet_groups WHERE id = {$cgid}");

/* ---- Tailscale API checks ---- */
check(fleet_ts_token_valid('tskey-api-kAbC123CNTRL-xyzXYZ0123456789') && !fleet_ts_token_valid('tskey-auth-kAbC123CNTRL-xyz0123456789') && !fleet_ts_token_valid('tskey-api-x y'),
    'only an API access token is taken');
$tsdev = array(array('id' => '1', 'addresses' => array('100.64.0.5', 'fd7a::5')), array('id' => '2', 'addresses' => array('100.64.0.9')));
check((fleet_ts_device_for($tsdev, '100.64.0.9')['id'] === '2') && (fleet_ts_device_for($tsdev, '100.64.0.1') === null), 'a firewall\'s device is found by its tailnet address');
$tsnow = 1800000000;
$tsp = function (array $d) use ($tsnow) {
	return array_map(function ($p) { return $p[0] . '/' . $p[1]; }, fleet_ts_device_problems($d, $tsnow));
};
check($tsp(array('authorized' => true, 'keyExpiryDisabled' => true, 'connectedToControl' => true)) === array() &&
    $tsp(array('keyExpiryDisabled' => false, 'expires' => gmdate('c', $tsnow + 90 * 86400))) === array('FLEET-E136/warn') &&
    $tsp(array('keyExpiryDisabled' => false, 'expires' => gmdate('c', $tsnow + 3 * 86400))) === array('FLEET-E136/error') &&
    $tsp(array('keyExpiryDisabled' => false, 'expires' => gmdate('c', $tsnow - 60))) === array('FLEET-E136/error') &&
    $tsp(array('authorized' => false, 'keyExpiryDisabled' => true, 'connectedToControl' => false)) === array('/error', '/warn'),
    'key expiry on is FLEET-E136 (an error when close or past), unapproved and offline devices are named');
check(fleet_ts_check(array()) === null, 'without a token Tailscale paths are only probed');

/* ---- joining over Tailscale ---- */
$tsb = fleet_ts_authkey_body('Aarhus <office> & co', 30 * 86400);
check(($tsb['capabilities']['devices']['create'] === array('reusable' => false, 'ephemeral' => false, 'preauthorized' => true)) &&
    ($tsb['description'] === 'FreeSense Fleet Aarhus office  co') && ($tsb['expirySeconds'] === 30 * 86400) &&
    (fleet_ts_authkey_body('x', 400 * 86400)['expirySeconds'] === 90 * 86400) && (strlen(fleet_ts_authkey_body(str_repeat('a', 80), 3600)['description']) <= 50),
    'a Tailscale key per firewall: single use, pre-approved, not ephemeral, at most 90 days, a description Tailscale accepts');
check((count(fleet_ts_join_problems(null, null)) === 2) && (fleet_ts_join_problems('', '100.64.0.1') === array()) &&
    (fleet_ts_join_problems('The token expired.', '100.64.0.1') === array('The token expired.')),
    'joining over Tailscale needs a working API token and a controller in the tailnet');

/* ---- Deployment Factory over Tailscale ---- */
require_once('fleet_seed.inc');
list($fshown) = fleet_join_key_generate();
$flink = 'https://100.64.0.1:8443/fleet/join#abcdef012345.' . str_repeat('A', 43) . '.' . str_repeat('a', 64);
$ftsk = 'tskey-auth-kTEST123CNTRL-abcdefghijkl';
$fa = fleet_seed_parse(json_encode(fleet_factory_seed($flink, 'attended', $fshown, null, $ftsk)));
$fp = fleet_seed_parse(json_encode(fleet_factory_seed($flink, 'pin', $fshown, '482913', $ftsk)));
$fu = fleet_seed_parse(json_encode(fleet_factory_seed($flink, 'unattended', $fshown, null, $ftsk)));
check((fleet_seed_tailscale_key($fa, (string)fleet_join_key_normalize($fshown)) === $ftsk) && !isset($fa['tailscale']['key']) &&
    (fleet_seed_tailscale_key($fp, '482913') === $ftsk) && !isset($fp['tailscale']['key']) && (fleet_seed_tailscale_key($fu, '') === $ftsk) &&
    !isset(fleet_factory_seed($flink, 'attended', $fshown, null)['tailscale']),
    'Factory seeds carry the Tailscale key the way System opens it: sealed to the join key or PIN, plain only unattended');
check(fleet_factory_settings(array('name' => 'B', 'mode' => 'pin', 'via' => 'tailscale'))['via'] === 'tailscale' && fleet_factory_settings(array('name' => 'B', 'via' => 'x'))['via'] === '',
    'a batch is over the internet or over Tailscale');

/* ---- NOC looks and the live view ---- */
check((fleet_kiosk_look('hacker', 'light') === array('hacker', 'light')) && (fleet_kiosk_look('<x>', 'neon') === array('freesense', 'auto')) && (count(FLEET_KIOSK_STYLES) === 5),
    'five NOC styles in light, dark or the screen\'s own setting; anything else is the default');
$nocp = fleet_kiosk_page(true, 'blueprint', 'dark', true, array('css' => 1, 'js' => 2));
$nock = fleet_kiosk_page(false, 'pro', 'auto', false, array());
check((strpos($nocp, 'class="k--blueprint" data-theme="dark"') !== false) && (strpos($nocp, 'id="k-style"') !== false) && (strpos($nocp, 'data-mode="live"') !== false) &&
    (strpos($nock, 'id="k-style"') === false) && (strpos($nock, 'data-theme=') === false || strpos($nock, ' data-theme="') === false) && (stripos($nocp . $nock, '<script>') === false) && (stripos($nocp . $nock, 'style="') === false),
    'the live view has a style picker, a wall screen does not, and neither page has inline script or style (the CSP)');
$nocv = fleet_kiosk_view(array('boxes' => array(array('node_id' => 'n1', 'state' => 'online', 'groups' => array(), 'version' => '', 'seen' => 0, 'policy' => 0, 'breakglass' => false,
    'update' => null, 'op' => null, 'label' => 'A', 'host' => 'a', 'problem' => '')), 'headline' => '', 'total' => 1, 'counts' => array(), 'checked' => 0, 'now' => 0), array(), true, 'T', array('control', 'dark'));
check(!isset($nocv['boxes'][0]['id']) && ($nocv['style'] === 'control') && ($nocv['theme'] === 'dark'), 'a screen that hides names gets no firewall ids, and every screen gets its saved look');

/* ---- rule and port forward templates ---- */
$tlbad = function (string $kind, array $in) {
	try {
		fleet_tlist_item_from($kind, $in);
	} catch (InvalidArgumentException $e) {
		return true;
	}
	return false;
};
$tlr = fleet_tlist_item_from('rules', array('key' => 'Allow-DNS', 'action' => 'pass', 'iface' => 'lan', 'proto' => 'tcp/udp', 'src' => 'lan', 'dst' => 'lanip', 'port' => '53', 'log' => '1', 'descr' => 'DNS'));
check(($tlr['key'] === 'allow-dns') && $tlr['log'] && $tlbad('rules', array('key' => 'x', 'iface' => 'eth0')) && $tlbad('rules', array('key' => 'x', 'iface' => 'lan', 'proto' => 'icmp', 'port' => '80')) &&
    $tlbad('rules', array('key' => 'x', 'iface' => 'lan', 'src' => '10.0.0.0/33')) && !$tlbad('rules', array('key' => 'x', 'iface' => 'opt2', 'src' => 'office_nets', 'dst' => '2001:db8::/64')) &&
    $tlbad('nat', array('key' => 'w', 'iface' => 'wan', 'proto' => 'tcp', 'port' => '443', 'target' => '10.0.0.0/24')) && $tlbad('nat', array('key' => 'w', 'iface' => 'wan', 'proto' => 'any', 'port' => '443', 'target' => '10.0.0.5')),
    'rule and port forward entries are checked: interfaces, addresses, networks, aliases, ports only with TCP or UDP, one forward target');
check(fleet_tlist_items_from('rules', array(array('key' => '', 'action' => 'pass', 'proto' => 'any', 'iface' => 'lan'), array('key' => 'a', 'iface' => 'lan'))) !== array() &&
    $tlbad('rules', array('key' => 'a b', 'iface' => 'lan')), 'empty rows are skipped; names are short and plain');
$tlb = fleet_tlist_body('rules', 7, $tlr);
check(($tlb['descr'] === '[Fleet:T7:allow-dns] DNS') && ($tlb['srctype'] === 'lan') && ($tlb['dsttype'] === 'lanip') && ($tlb['dstbeginport'] === '53') &&
    (fleet_tlist_body('rules', 7, array('src' => '10.1.0.0/16', 'dst' => 'web_servers', 'port' => '8000-8080') + $tlr)['srcmask'] === '16') &&
    (fleet_tlist_body('rules', 7, array('src' => '10.1.0.0/16', 'dst' => 'web_servers', 'port' => '8000-8080') + $tlr)['dstendport'] === '8080') &&
    (fleet_tlist_owner($tlb['descr']) === array(7, 'allow-dns')) && (fleet_tlist_owner('NAT ' . $tlb['descr']) === null),
    'the REST body carries the marker; addresses, masks and port ranges map to the edit form');
$tlraw = array('id' => 4, 'type' => 'pass', 'interface' => 'lan', 'protocol' => 'tcp/udp', 'source' => array('network' => 'lan'), 'destination' => array('network' => 'lanip', 'port' => '53'),
    'log' => '', 'descr' => '[Fleet:T7:allow-dns] DNS');
$tlother = array('id' => 5, 'type' => 'pass', 'interface' => 'lan', 'source' => array('any' => ''), 'destination' => array('any' => ''), 'descr' => 'Default allow LAN');
$tlold = array('id' => 6, 'type' => 'block', 'interface' => 'lan', 'source' => array('any' => ''), 'destination' => array('any' => ''), 'descr' => '[Fleet:T7:gone] old');
$tlp = fleet_tlist_plan('rules', 7, array($tlr), array($tlother, $tlraw, $tlold));
check((array_column($tlp, 'action', 'name') === array('allow-dns' => 'same', 'gone' => 'delete')) && ($tlp[1]['id'] === 6),
    'a matching rule is left alone, a rule the template dropped is removed, the firewall\'s own rule is never touched');
$tlp2 = fleet_tlist_plan('rules', 7, array(array('port' => '853') + $tlr), array($tlraw));
check(($tlp2[0]['action'] === 'update') && ($tlp2[0]['id'] === 4) && (fleet_tlist_plan('rules', 8, array($tlr), array($tlraw))[0]['action'] === 'create'),
    'a changed rule is updated in place; another template\'s marker is not this one\'s');
check((fleet_tlist_rule_order(7, array($tlr), array($tlother, $tlraw)) === array('lan' => array(4, 5))) && (fleet_tlist_rule_order(7, array($tlr), array($tlraw, $tlother)) === array()),
    'the template\'s rules come first on their interface; nothing to reorder when they already are');
check(fleet_tlist_item_from_raw('rules', 'allow-dns', $tlraw) === $tlr, 'adopting reads a firewall\'s rule back into the template\'s words');
$tln = fleet_tlist_item_from('nat', array('key' => 'web', 'iface' => 'wan', 'proto' => 'tcp', 'port' => '443', 'target' => '10.0.0.10', 'local' => '', 'descr' => 'Web'));
$tlnraw = array('id' => 0, 'interface' => 'wan', 'protocol' => 'tcp', 'destination' => array('network' => 'wanip', 'port' => '443'), 'target' => '10.0.0.10', 'local-port' => '443',
    'descr' => '[Fleet:T9:web] Web');
check(($tln['local'] === '443') && (fleet_tlist_plan('nat', 9, array($tln), array($tlnraw))[0]['action'] === 'same') &&
    (fleet_tlist_body('nat', 9, $tln)['filter-rule-association'] === 'add-associated') && (fleet_tlist_body('nat', 9, $tln)['dsttype'] === 'wanip'),
    'a port forward keeps its port when no local port is given, comes with its firewall rule, and matches the stored form');
$tlxml = '<?xml version="1.0"?><freesense><filter><rule><type>pass</type><interface>lan</interface><protocol>tcp/udp</protocol><source><network>lan</network></source>' .
    '<destination><network>lanip</network><port>53</port></destination><log/><descr>[Fleet:T7:allow-dns] DNS</descr></rule></filter><nat></nat></freesense>';
$tlcfg = fleet_tlist_from_config('rules', $tlxml);
check((count($tlcfg) === 1) && (fleet_tlist_plan('rules', 7, array($tlr), $tlcfg)[0]['action'] === 'same') && (fleet_tlist_from_config('nat', $tlxml) === array()),
    'drift is read from a configuration backup in the same form');

/* ---- Factory: cloud files and recipes ---- */
$fmr = array('site' => 'cph', 'label' => 'Copenhagen', 'serial' => '', 'instance_id' => '', 'domain' => 'shops.example', 'hostname' => 'cph-fw01');
$fmseed = array('version' => 1, 'link' => 'https://fleet.example:8443/fleet/join#x', 'mode' => 'unattended', 'key' => 'FLT-X');
$fmc = fleet_factory_cloud_files($fmr, 'cph-fw01', 'cph-fw01', $fmseed);
$fmud = json_decode(substr($fmc['user-data'], strlen("#cloud-config\n")), true);
check((strpos($fmc['user-data'], "#cloud-config\n") === 0) && ($fmud['freesense']['fleet'] === $fmseed) && ($fmud['fqdn'] === 'cph-fw01.shops.example') &&
    (strpos($fmc['meta-data'], "instance-id: fleet-cph-fw01\n") === 0) &&
    (strpos(fleet_factory_cloud_files(array('instance_id' => 'i-abc') + $fmr, 'x', '', $fmseed)['meta-data'], 'instance-id: i-abc') === 0),
    'cloud-init for each firewall: the seed under freesense.fleet, its name, and the instance id it is bound to');
$fmrec = fleet_factory_recipes(array('name' => 'Spring'), array('cph-fw01' => array('name' => 'cph-fw01', 'instance_id' => 'fleet-cph-fw01')));
check((strpos($fmrec['proxmox-qm.sh'], 'local:iso/cph-fw01-cidata.iso') !== false) && (strpos($fmrec['virt-install.sh'], "'cph-fw01-cidata.iso',device=cdrom") !== false) &&
    (strpos($fmrec['terraform/main.tf'], 'local:iso/${each.value.cidata_iso}') !== false) &&
    (json_decode($fmrec['terraform/instances.auto.tfvars.json'], true)['firewalls']['cph-fw01']['instance_id'] === 'fleet-cph-fw01'),
    'the batch recipes make one VM per firewall with its own cidata.iso (qm, virt-install, Terraform)');

/* ---- Fleet is 1.2 only ---- */
$gpkg = dirname(__DIR__, 3) . '/sysutils/FreeSense-pkg-Fleet/files/pkg-install.in';
$gmk = (string)@file_get_contents(dirname(__DIR__, 3) . '/Mk/bsd.freesense-package.mk');
$gsrc = (string)@file_get_contents($gpkg);
check((strpos($gmk, 'RUN_DEPENDS+=	FreeSense-platform-abi=${FREESENSE_PACKAGE_TRAIN}.0') !== false) &&
    (strpos($gsrc, '"PRE-INSTALL"') !== false) && (strpos($gsrc, '-lt 11') !== false) && (strpos($gsrc, 'fleet_agent.inc') !== false) && (strpos($gsrc, 'exit 1') !== false),
    'Fleet installs only on FreeSense 1.2: the package pins its release train, and its install script refuses a System without the agent and API level 11');

/* ---- HA pairs ---- */
$hab = function (string $n, string $state, array $vips, string $peer = '', array $sec = array()) {
	return array('node_id' => $n, 'label' => strtoupper($n), 'state' => $state, 'status' => json_encode(array(
	    'carp_vips' => array_map(function ($v) { return array('vhid' => $v[0], 'address' => $v[1], 'state' => $v[2]); }, $vips),
	    'hasync' => array('peer' => $peer, 'sections' => $sec))));
};
$hboxes = array(
	$hab('a', 'online', array(array(1, '10.0.0.1/24', 'MASTER'), array(2, '192.0.2.1/24', 'MASTER')), '10.9.9.2', array('aliases', 'rules')),
	$hab('b', 'online', array(array(1, '10.0.0.1/24', 'BACKUP'), array(2, '192.0.2.1/24', 'BACKUP'))),
	$hab('c', 'online', array(array(5, '10.5.0.1/24', 'MASTER'))),
	$hab('d', 'online', array()),
);
$hp = fleet_ha_pairs($hboxes);
check((count($hp) === 1) && ($hp[0]['nodes'] === array('a', 'b')) && ($hp[0]['masters'] === array('a')) && ($hp[0]['primary'] === 'a') && ($hp[0]['problem'] === null),
    'HA pairs: firewalls sharing a CARP address are one pair, with its MASTER and its sync primary; a lone CARP firewall is no pair');
$hboxes[1] = $hab('b', 'online', array(array(1, '10.0.0.1/24', 'MASTER'), array(2, '192.0.2.1/24', 'BACKUP')));
check(fleet_ha_pairs($hboxes)[0]['problem'] === array('split', '1@10.0.0.1/24'), 'two MASTERs for one address is split-brain');
$hboxes[1] = $hab('b', 'offline', array(array(1, '10.0.0.1/24', 'MASTER'), array(2, '192.0.2.1/24', 'MASTER')));
check(fleet_ha_pairs($hboxes)[0]['problem'] === null, 'an offline partner\'s old state does not count');
$hboxes[0] = $hab('a', 'online', array(array(1, '10.0.0.1/24', 'BACKUP'), array(2, '192.0.2.1/24', 'MASTER')), '10.9.9.2', array('aliases', 'rules'));
check(fleet_ha_pairs($hboxes)[0]['problem'] === array('nomaster', '1@10.0.0.1/24'), 'no online MASTER for an address is a problem');
$hboxes[0] = $hab('a', 'online', array(array(1, '10.0.0.1/24', 'MASTER'), array(2, '192.0.2.1/24', 'MASTER')), '10.9.9.2', array('aliases', 'rules'));
$hboxes[1] = $hab('b', 'online', array(array(1, '10.0.0.1/24', 'BACKUP'), array(2, '192.0.2.1/24', 'BACKUP')));
$hp = fleet_ha_pairs($hboxes);
check((array_column(array_values(fleet_ha_order($hboxes, $hp)), 'node_id') === array('b', 'c', 'd', 'a')) && (fleet_ha_order(array('a', 'b'), $hp) === array(1 => 'b', 0 => 'a')) &&
    (array_key_first(fleet_ha_order(array(7 => 'a', 9 => 'b'), $hp)) === 9),
    'working order: a pair\'s MASTER after everything else');
check(fleet_ha_rings(array(array('a', 'c'), array('b')), $hp) === array(array('c'), array('b', 'a')), 'a rollout moves the MASTER into its partner\'s later ring, after it');
check((fleet_ha_wait_reason($hp[0], 'a', array('a' => 'online', 'b' => 'offline'), array('b' => 'B')) === 'Waiting for its HA partner B to be online') &&
    (fleet_ha_wait_reason($hp[0], 'a', array('a' => 'online', 'b' => 'online'), array()) === null) && (fleet_ha_wait_reason(null, 'c', array(), array()) === null),
    'Fleet waits for the partner before working on a pair firewall');
$hst = array('a' => array('hasync' => array('sections' => array('aliases', 'rules'))));
check((fleet_ha_synced_from($hp[0], 'b', 'rules', $hst) === 'a') && (fleet_ha_synced_from($hp[0], 'b', 'nat', $hst) === null) &&
    (fleet_ha_synced_from($hp[0], 'a', 'rules', $hst) === null) && (fleet_ha_synced_from($hp[0], 'b', 'dns', $hst) === null),
    'HA config sync: the secondary gets synced kinds from its primary, not from Fleet');

check((fleet_uptime_text(34369) === '9 h 32 min') && (fleet_uptime_text(3 * 86400 + 7200) === '3 days 2 h') && (fleet_uptime_text(86400) === '1 day') && (fleet_uptime_text(59) === '0 min'),
    'uptime in days, hours and minutes');
/* ---- Availability ---- */
$sb = fleet_stats_box('online', array(array(1100, 'offline'), array(1400, 'online'), array(1800, 'degraded')), 1000, 2000);
check(($sb['up'] === 700) && ($sb['known'] === 1000) && ($sb['outages'] === array(array(1100, 1400))) && (fleet_stats_percent(700, 1000) === 70.0),
    'availability: online and degraded are up; an offline period is one outage');
$sb = fleet_stats_box(null, array(array(1500, 'online'), array(1900, 'offline')), 1000, 2000);
check(($sb['known'] === 500) && ($sb['up'] === 400) && ($sb['outages'] === array(array(1900, 2000))),
    'a firewall that joined during the range counts only from then; one still down has an open outage to the end');
check((fleet_stats_box('offline', array(), 0, 100)['outages'] === array(array(0, 100))) && (fleet_stats_percent(0, 0) === null), 'down the whole range; nothing known is no percentage');
$stl = fleet_stats_timeline(array('a' => array('online', array(array(50, 'offline'))), 'b' => array('online', array())), 0, 100, 4);
check(($stl['up'] === array(2, 2, 1, 1)) && ($stl['in'] === array(2, 2, 2, 2)), 'the timeline counts the firewalls up, and in the fleet, in each part of the range');
check((fleet_stats_audit_line('demo-909 (Demo: Pop-up store): online -> degraded (FLEET-E105: x)') === array('demo-909', 'online', 'degraded')) &&
    (fleet_stats_audit_line('something else') === null), 'state changes are read back from the audit log');
check(strpos(fleet_stats_svg($stl, 2, 0, 400, 100, function ($t) { return (string)$t; }, 'Up'), '<polyline') !== false, 'the timeline draws as SVG');

/* ---- HA pair setup ---- */
check((fleet_ha_bits('255.255.255.0') === 24) && (fleet_ha_bits('24') === 24) && (fleet_ha_bits('255.0.255.0') === null) && fleet_ha_in_net('10.1.0.9', '10.1.0.1', 24) && !fleet_ha_in_net('10.2.0.9', '10.1.0.1', 24),
    'HA setup: masks and networks');
$hfa = array('label' => 'A', 'role' => 'managed', 'state' => 'online', 'api_level' => 12, 'in_pair' => false, 'hasync_peer' => '', 'vhids' => array(1),
    'ifaces' => fleet_ha_ifaces(array(array('name' => 'lan', 'description' => 'LAN', 'ipaddr' => '10.1.0.2', 'subnet' => '255.255.255.0', 'status' => 'up'),
    array('name' => 'opt1', 'description' => 'SYNC', 'ipaddr' => '10.9.0.1', 'subnet' => '255.255.255.252', 'status' => 'up'))));
$hfb = array('label' => 'B', 'gui_cert' => str_repeat('ab', 32), 'vhids' => array(2), 'ifaces' => fleet_ha_ifaces(array(array('name' => 'lan', 'description' => 'LAN', 'ipaddr' => '10.1.0.3', 'subnet' => '255.255.255.0', 'status' => 'up'),
    array('name' => 'opt1', 'description' => 'SYNC', 'ipaddr' => '10.9.0.2', 'subnet' => '255.255.255.252', 'status' => 'up')))) + $hfa;
$hin = array('primary' => 'a', 'secondary' => 'b', 'vips' => array(array('iface' => 'lan', 'address' => '10.1.0.1')), 'sync_iface' => 'opt1', 'sections' => array('rules', 'users'));
list($herr, $hplan) = fleet_ha_setup_plan($hin, $hfa, $hfb);
check(empty($herr) && ($hplan['vips'][0]['vhid'] === 3) && ($hplan['vips'][0]['bits'] === 24) && ($hplan['secondary_sync_ip'] === '10.9.0.2') && ($hplan['sections'] === array('rules')),
    'HA setup plan: a free VHID on both, the subnet from the interface, the peer from the sync interface; users are never synced');
list($herr) = fleet_ha_setup_plan(array('vips' => array(array('iface' => 'lan', 'address' => '10.1.0.2'))) + $hin, $hfa, array('role' => 'monitor', 'hasync_peer' => '10.0.0.9') + $hfb);
check((count($herr) === 4) && (strpos(implode(' ', $herr), 'monitor only') !== false) && (strpos(implode(' ', $herr), 'own address') !== false),
    'HA setup refuses a monitored firewall, one that already syncs, and a firewall\'s own address as the shared one');
list($herr) = fleet_ha_setup_plan(array('vips' => array(array('iface' => 'lan', 'address' => '10.7.0.1', 'vhid' => 2))) + $hin, $hfa, $hfb);
check((count($herr) === 2) && (strpos($herr[0], '10.1.0.2/24') !== false), 'an address outside the network is refused');
$hvb = fleet_ha_vip_body($hplan['vips'][0], 100, 'pw');
$hsb = fleet_ha_sync_body($hplan, true, 'pw');
check(($hvb['mode'] === 'carp') && ($hvb['advskew'] === '100') && (strpos($hvb['descr'], FLEET_HA_MARK) === 0) &&
    ($hsb['synchronizetoip'] === '10.9.0.2') && ($hsb['synchronizerules'] === true) && ($hsb['synchronizenat'] === false) && !isset($hsb['synchronizeusers']) &&
    !isset(fleet_ha_sync_body($hplan, false)['synchronizetoip']) && ($hsb['syncpeerpin'] === str_repeat('ab', 32)), 'the CARP address and HA sync bodies (the secondary WebGUI certificate pinned); the secondary pushes nothing');
list($herr) = fleet_ha_setup_plan($hin, $hfa, array('gui_cert' => '') + $hfb);
check((count($herr) === 1) && (strpos($herr[0], 'WebGUI certificate') !== false) && empty(fleet_ha_setup_plan(array('sections' => array()) + $hin, $hfa, array('gui_cert' => '') + $hfb)[0]),
    'configuration sync needs the secondary certificate to pin; without sync sections it is not needed');

$hrb = fleet_ha_rule_bodies($hplan, 8443);
check((count($hrb) === 2) && ($hrb[0]['proto'] === 'pfsync') && ($hrb[0]['src'] === '10.9.0.0') && ($hrb[0]['srcmask'] === '30') && ($hrb[1]['src'] === '10.9.0.1') &&
    ($hrb[1]['dsttype'] === 'opt1ip') && ($hrb[1]['dstbeginport'] === '8443') && (strpos($hrb[1]['descr'], FLEET_HA_MARK) === 0),
    'the sync interface rules are the same on both and right on either (HA sync copies them): pfsync from the sync network, configuration sync from the primary');

$hsg = fleet_ha_suggest($hfa['ifaces'], $hfb['ifaces']);
check(($hsg['sync_iface'] === 'opt1') && ($hsg['vips'] === array(array('iface' => 'lan', 'address' => '10.1.0.1'))) && empty(fleet_ha_setup_plan(array('primary' => 'a', 'secondary' => 'b') + $hsg, $hfa, $hfb)[0]) &&
    (fleet_ha_suggest($hfa['ifaces'], fleet_ha_ifaces(array(array('name' => 'lan', 'ipaddr' => '10.7.0.3', 'subnet' => '255.255.255.0')))) === null),
    'HA setup suggests the sync interface and the first free address of the other shared networks; none when nothing is shared');
$hdup = fleet_ha_ifaces(array(array('name' => 'lan', 'ipaddr' => '10.9.0.1', 'subnet' => '255.255.255.248'), array('name' => 'opt1', 'description' => 'HASYNC', 'ipaddr' => '10.9.0.1', 'subnet' => '255.255.255.248')));
$hdup2 = fleet_ha_ifaces(array(array('name' => 'lan', 'ipaddr' => '10.9.0.2', 'subnet' => '255.255.255.248'), array('name' => 'opt1', 'description' => 'HASYNC', 'ipaddr' => '10.9.0.2', 'subnet' => '255.255.255.248')));
check(fleet_ha_suggest($hdup, $hdup2)['vips'] === array(array('iface' => 'opt1', 'address' => '10.9.0.3')),
    'two assignments of one port on the sync network count as one network');
$hfc = array('label' => 'C', 'ifaces' => fleet_ha_ifaces(array(array('name' => 'lan', 'ipaddr' => '10.5.0.2', 'subnet' => '255.255.255.0')))) + $hfa;
$hcand = fleet_ha_candidates(array('b' => $hfb, 'c' => $hfc, 'a' => $hfa, 'p' => array('in_pair' => true) + $hfa));
check((count($hcand) === 1) && ($hcand[0]['primary'] === 'a') && ($hcand[0]['secondary'] === 'b'),
    'pairing a group pairs managed firewalls sharing a network (lower name primary), never one already paired or alone');

/* Standby controller. */
$sbtok = random_bytes(32);
$sbkey = random_bytes(32);
$sbcode = fleet_standby_code_make('https://ctl.example.net:8443', str_repeat('ab', 32), $sbtok, $sbkey);
$sbc = fleet_standby_code_read(" {$sbcode}\n");
check(($sbc !== null) && ($sbc['url'] === 'https://ctl.example.net:8443') && ($sbc['token'] === $sbtok) && ($sbc['key'] === $sbkey) && (strpos($sbcode, 'FSB1-') === 0) &&
    (fleet_standby_code_read('FSB1-' . fleet_standby_b64u('{"u":"http://x:1","f":"' . str_repeat('ab', 32) . '"}')) === null) && (fleet_standby_code_read('hello') === null),
    'a standby pairing code carries the URL, certificate fingerprint, token and key, and nothing else reads as one');
$sbsealed = fleet_standby_seal('copy', $sbkey);
check((fleet_standby_unseal($sbsealed, $sbkey) === 'copy') && (fleet_standby_unseal($sbsealed, random_bytes(32)) === null) && (fleet_unseal($sbsealed, $sbkey) === null),
    'a standby copy opens only with the pairing key (and is not a store secret)');
check((fleet_standby_endpoints_want('a:1', 'b:1') === array('a:1', 'b:1')) && (fleet_standby_endpoints_want('a:1', '') === array('a:1')) && (fleet_standby_endpoints_want('a:1', 'a:1') === array('a:1')),
    'firewalls know this controller first, then the standby');
$sbw = array('a:1', 'b:1');
check((fleet_standby_box_action(array('api_level' => 12), $sbw, 0) === 'skip') &&
    (fleet_standby_box_action(array('api_level' => 13, 'controller_endpoints' => $sbw, 'controller_epoch' => 2), $sbw, 2) === 'ok') &&
    (fleet_standby_box_action(array('api_level' => 13, 'controller_endpoints' => array('a:1'), 'controller_epoch' => 2), $sbw, 2) === 'push') &&
    (fleet_standby_box_action(array('api_level' => 13, 'controller_endpoints' => $sbw, 'controller_epoch' => 1), $sbw, 2) === 'push') &&
    (fleet_standby_box_action(array('api_level' => 13, 'controller_endpoints' => $sbw, 'controller_epoch' => 3), $sbw, 2) === 'newer'),
    'each firewall\'s controller endpoints are kept current, and one that saw a newer controller means this one was replaced');
$sbp = array('role' => 'standby');
$sbs = array('takeover' => 'auto', 'auto_minutes' => 10, 'snapshot' => array('created' => 1), 'last_ok' => 1000);
check(!fleet_standby_takeover_due($sbp, $sbs, 1000 + 599) && fleet_standby_takeover_due($sbp, $sbs, 1000 + 600) &&
    !fleet_standby_takeover_due($sbp, array('takeover' => 'manual') + $sbs, 99999) && !fleet_standby_takeover_due($sbp, array('snapshot' => null) + $sbs, 99999) &&
    !fleet_standby_takeover_due($sbp, array('last_ok' => 0) + $sbs, 99999) && !fleet_standby_takeover_due(array('role' => 'primary'), $sbs, 99999),
    'automatic takeover only on a standby with a copy, set to automatic, after the primary answered once and was silent long enough');
check((fleet_standby_url_host('https://[2001:db8::5]:8443') === '2001:db8::5') && (fleet_standby_url_host('https://ctl.example.net:8443') === 'ctl.example.net'),
    'the primary\'s host from its URL');
$sbb = array('format' => 'freesense-fleet-self-v1', 'created' => 5, 'schema' => FLEET_DB_SCHEMA, 'db' => '', 'keys' => array(), 'settings' => array(),
    'master' => base64_encode(random_bytes(32)), 'epoch' => 4);
$sbo = fleet_standby_open(fleet_standby_seal(gzencode(json_encode($sbb)), $sbkey), $sbkey);
check(is_array($sbo) && ($sbo[1]['epoch'] === 4) && ($sbo[1]['created'] === 5) && is_string(fleet_standby_open(fleet_standby_seal(gzencode(json_encode(array('master' => '') + $sbb)), $sbkey), $sbkey)) &&
    is_string(fleet_standby_open('s1:x:y:z', $sbkey)), 'a standby copy opens to the bundle with the master key and epoch; anything else is refused');
$sbpoll = (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/sbin/freesense-fleet-poll');
$sbix = (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg/fleet/enroll/index.php');
check((strpos($sbpoll, 'fleet_standby_endpoints_tick()') !== false) && (strpos($sbpoll, 'fleet_standby_fence_tick(') !== false) && (strpos($sbix, 'fleet_standby_handle(') !== false) &&
    (strpos(fleet_enroll_nginx_conf(8443, '/fleet/tls.pem'), 'location ^~ /fleet/standby/') !== false),
    'the poll keeps the standby copy and the firewalls\' endpoints current, and the enrollment port serves the standby');
/* Controller access. */
check((fleet_access_cidr(' 203.0.113.5 ') === '203.0.113.5') && (fleet_access_cidr('203.0.113.0/24') === '203.0.113.0/24') && (fleet_access_cidr('203.0.113.5/32') === '203.0.113.5') &&
    (fleet_access_cidr('2001:db8::/48') === '2001:db8::/48') && (fleet_access_cidr('203.0.113.0/33') === null) && (fleet_access_cidr('x') === null) && (fleet_access_cidr('1.2.3.4/0') === null),
    'the allowed list takes addresses and networks, IPv4 and IPv6');
check(fleet_access_in('203.0.113.77', '203.0.113.0/24') && !fleet_access_in('203.0.114.1', '203.0.113.0/24') && fleet_access_in('203.0.113.5', '203.0.113.5') &&
    fleet_access_in('2001:db8:0:1::9', '2001:db8::/48') && !fleet_access_in('2001:db9::1', '2001:db8::/48') && fleet_access_in('10.1.2.3', '10.0.0.0/9') && !fleet_access_in('10.200.0.1', '10.0.0.0/9') &&
    !fleet_access_in('203.0.113.5', '2001:db8::/48'), 'an address is in a network only within its mask');
$acd = fleet_access_from(array());
check(($acd['enroll'] === 'any') && ($acd['tunnel'] === 'any') && $acd['firewalls'] && $acd['block'] && ($acd['block_after'] === 5) && ($acd['block_minutes'] === 60),
    'access defaults: open as before, firewalls allowed automatically, wrong keys blocked after 5 for an hour');
$acl = fleet_access_from(array('enroll' => 'list', 'entries' => array(array('cidr' => '198.51.100.0/24', 'note' => 'Office'), array('cidr' => 'bad'))));
$alw = fleet_access_allowed($acl, array('Shop' => '203.0.113.9'), array(array('ip' => '192.0.2.4', 'label' => 'New', 'expires' => 2000), array('ip' => '192.0.2.5', 'label' => 'Old', 'expires' => 500)),
    array('192.0.2.200' => 'Standby controller'), 1000);
check(($alw === array('198.51.100.0/24' => 'Office', '203.0.113.9' => 'Firewall Shop', '192.0.2.4' => 'Invitation New', '192.0.2.200' => 'Standby controller')) &&
    !isset(fleet_access_allowed(array('firewalls' => false) + $acl, array('Shop' => '203.0.113.9'), array(), array(), 1000)['203.0.113.9']),
    'the allowed list: entries, firewalls\' addresses, open invitations and the standby (an expired invitation is gone)');
$ars = array('enable' => true, 'enroll_port' => 8443, 'wg_port' => 51830);
$arl = fleet_access_rules($ars, $acl, $alw + array('2001:db8::/48' => 'v6'), array('198.18.0.9' => 5000, '198.18.0.10' => 10), 1000);
check((strpos($arl, 'block in quick proto tcp from { 198.18.0.9 } to (self) port 8443') !== false) && (strpos($arl, '198.18.0.10') === false) &&
    (strpos($arl, 'pass in quick inet proto tcp from { 198.51.100.0/24 203.0.113.9 192.0.2.4 192.0.2.200 } to (self) port 8443') !== false) &&
    (strpos($arl, 'pass in quick inet6 proto tcp from { 2001:db8::/48 } to (self) port 8443') !== false) &&
    (strpos($arl, 'pass in quick proto udp from any to (self) port 51830') !== false) &&
    (strpos(fleet_access_rules($ars, array('open_until' => 2000) + $acl, array(), array(), 1000), 'pass in quick proto tcp from any to (self) port 8443') !== false) &&
    (strpos(fleet_access_rules($ars, $acl, array(), array(), 1000), 'port 8443') === false) && (fleet_access_rules(array('enable' => false) + $ars, $acl, $alw, array(), 1000) === ''),
    'the port rules: blocked first, then anyone or only the allowed list per port (nothing when it is empty), open for joining lets anyone join for a while');
list($afl, $afn) = fleet_access_fail_add(array('198.18.0.1' => array(100, 990), '198.18.0.2' => array(10)), '198.18.0.1', 1000);
check(($afn === 2) && !isset($afl['198.18.0.2']) && (fleet_access_fail_add($afl, '198.18.0.1', 1000 + FLEET_ACCESS_WINDOW + 1)[1] === 1),
    'wrong keys count within ten minutes; old ones are forgotten');
check((fleet_access_endpoints_parse(array("k1=\t203.0.113.9:51820", "k2=\t[2001:db8::7]:4000", "k3=\t(none)")) === array('k1=' => '203.0.113.9', 'k2=' => '2001:db8::7')),
    'the addresses firewalls connect from, read from the tunnel');
check((fleet_access_reach_kind(array('203.0.113.1'), array('203.0.113.1', '10.0.0.1'))[0] === 'local') && (fleet_access_reach_kind(array('198.51.100.1'), array('10.0.0.1'))[0] === 'forward') &&
    (fleet_access_reach_kind(array(), array('10.0.0.1'))[0] === 'unresolved'), 'the public address is on this controller, or forwarded to it');
$aix = (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg/fleet/enroll/index.php');
check((substr_count($aix, 'fleet_access_failed(') === 2) && (strpos((string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/pkg/fleet.inc'), 'fleet_access_filter_rules(') !== false),
    'wrong keys at the enrollment port and the standby route count; the filter takes the access rules');
$cpb = array('method' => 'both', 'iface' => 'opt1', 'paths' => array(array('method' => 'direct', 'address' => '10.0.0.2', 'ok' => true), array('method' => 'tailscale', 'address' => '100.64.0.2', 'ok' => false)));
check((fleet_conn_paths(null) === array()) && (fleet_conn_paths(array('method' => 'wireguard')) === array()) && (count(fleet_conn_paths($cpb)) === 2) &&
    (fleet_conn_paths(array('method' => 'tailscale', 'address' => 'x'))[0]['method'] === 'tailscale') && (FLEET_CONN_PATHS['both'] === array('direct', 'tailscale')) &&
    !fleet_conn_pending(array('want' => array('both', 'opt1'), 'state' => $cpb)) && fleet_conn_pending(array('want' => array('both', 'lan'), 'state' => $cpb)) &&
    fleet_conn_pending(array('want' => array('direct', 'opt1'), 'state' => $cpb)) && (fleet_conn_cfg_from(array('conn_method' => 'both', 'conn_iface' => 'opt1'), true)['method'] === 'both') && !empty(fleet_conn_requirements('both')),
    'a firewall can use Direct and Tailscale together: both paths in order, then the tunnel');

/* Dashboard widget. */
check((fleet_widget_cfg(array()) === array('parts' => array_keys(FLEET_WIDGET_PARTS), 'group' => 0, 'rows' => 5)) &&
    (fleet_widget_cfg(array('fleet_parts' => 'problems,bogus,health', 'fleet_group' => '3', 'fleet_rows' => '10')) === array('parts' => array('health', 'problems'), 'group' => 3, 'rows' => 10)) &&
    (fleet_widget_cfg(array('fleet_parts' => '', 'fleet_rows' => '7'))['parts'] === array()) && (fleet_widget_cfg(array('fleet_rows' => '7'))['rows'] === 5),
    'widget settings: all parts by default, unknown parts and row counts are ignored, every part can be off');
$wb = function ($id, $state, $extra = array()) { return $extra + array('id' => $id, 'label' => strtoupper($id), 'state' => $state, 'problem' => '', 'policy' => 0, 'rollback' => true, 'update' => null); };
$wboxes = array($wb('a', 'online', array('update' => array('info', 'Update: 1.2.1'))), $wb('b', 'online', array('rollback' => false)), $wb('c', 'degraded'),
    $wb('d', 'offline', array('problem' => 'FLEET-E105: No route (x). Check it.')), $wb('e', 'online', array('policy' => 2)), $wb('f', 'online'));
$wp = fleet_widget_problems($wboxes, array(array('nodes' => array('a', 'f'), 'problem' => array('split', 'x')), array('nodes' => array('b', 'e'), 'problem' => null)),
    array('a' => 'A', 'f' => 'F'), 10);
check((array_column($wp, 'label') === array('D', 'A + F', 'C', 'E', 'B', 'A')) && ($wp[0]['badge'] === array('block', 'Offline')) && ($wp[0]['text'] === 'No route (x)') &&
    ($wp[1]['badge'][1] === 'Split-brain') && ($wp[3]['text'] === '2 policy rules fail') && ($wp[5]['link'] === '/fleet/fleet_updates.php') &&
    (count(fleet_widget_problems($wboxes, array(), array(), 3)) === 3) && (fleet_widget_problems(array($wb('f', 'online')), array(), array(), 5) === array()),
    'widget problem list: offline, HA problems, degraded, policy, no rollback, updates, worst first and cut to the rows; a healthy fleet lists nothing');
check((strpos(fleet_widget_html(array('ready' => false, 'standby' => null), fleet_widget_cfg(array())), 'not set up') !== false) &&
    (strpos(fleet_widget_html(array('ready' => false, 'standby' => array('last_ok' => 0)), fleet_widget_cfg(array())), 'standby') !== false) &&
    (strpos(fleet_widget_html(array('ready' => true, 'counts' => array(), 'total' => 0), fleet_widget_cfg(array('fleet_parts' => ''))), 'Every part is turned off') !== false),
    'widget on a server that is not a controller, on a standby, and with every part off');
$wpl = (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/pkg-plist') . (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/Makefile') .
    (string)file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/etc/inc/priv/fleet.priv.inc');
check((substr_count($wpl, 'widgets/widgets/fleet.widget.php') === 3) && (strpos($wpl, 'www/widgets/include/fleet.inc') !== false), 'the widget is packaged, installed and in the read-only Fleet privilege');

/* Load samples. */
check((fleet_samples_last(array(1, 2.5, null, null)) === 2.5) && (fleet_samples_last(array(null)) === null) && (fleet_samples_last(null) === null), 'the last value of an RRD series skips the unfilled end');
$smp = fleet_samples_from(array('cpu' => array('usage' => null), 'memory' => array('total_bytes' => 1000, 'used_bytes' => 250), 'states' => array('current' => 120, 'max' => 400000),
    'temperatures' => array(array('name' => 'CPU 0', 'celsius' => 41.5), array('name' => 'CPU 1', 'celsius' => 44.25))),
    array('cpu' => array(3.2, 7.04, null), 'mem' => array()), array('in_bps' => array(1000, 2500.6, null), 'out_bps' => array(null)));
check(($smp === array('cpu' => 7.0, 'mem' => 25.0, 'states' => 120, 'states_max' => 400000, 'temp' => 44.3, 'rx_bps' => 2501.0, 'tx_bps' => null)) &&
    (fleet_samples_from(array(), null, null) === array_fill_keys(FLEET_SAMPLES_COLS, null)),
    'a sample: CPU from the RRD, memory from the RRD or the live numbers, the hottest sensor, WAN traffic; missing parts stay empty');
$shr = fleet_samples_hourly(array(
    array('node_id' => 'a', 'time' => 7200, 'cpu' => 10, 'mem' => 50, 'states' => 100, 'states_max' => 1000, 'temp' => null, 'rx_bps' => 10, 'tx_bps' => 20),
    array('node_id' => 'a', 'time' => 7500, 'cpu' => 30, 'mem' => null, 'states' => 300, 'states_max' => 1000, 'temp' => null, 'rx_bps' => 30, 'tx_bps' => 40),
    array('node_id' => 'b', 'time' => 7300, 'cpu' => 5, 'mem' => 5, 'states' => 1, 'states_max' => 9, 'temp' => 40, 'rx_bps' => 0, 'tx_bps' => 0),
    array('node_id' => 'a', 'time' => 10800, 'cpu' => 99, 'mem' => 1, 'states' => 1, 'states_max' => 1, 'temp' => 1, 'rx_bps' => 1, 'tx_bps' => 1)));
check((count($shr) === 3) && ($shr[0]['node_id'] === 'a') && ($shr[0]['time'] === 7200) && ($shr[0]['n'] === 2) && ($shr[0]['cpu'] === 20.0) && ($shr[0]['cpu_max'] === 30.0) &&
    ($shr[0]['mem'] === 50.0) && ($shr[0]['temp'] === null) && ($shr[2]['time'] === 10800), 'hourly rows: averages per firewall and hour, the CPU peak, empty values stay empty');
$sdb = fleet_db();
check(((int)$sdb->query('PRAGMA user_version')->fetchColumn() === 27) && ($sdb->query("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('samples', 'samples_hourly')")->fetchColumn() == 2),
    'schema 27 has the sample tables');
$sdb->exec("INSERT INTO samples (node_id, time, cpu) VALUES ('sx', 100, 5), ('sy', 100, 9)");
$sdb->exec("INSERT INTO samples_hourly (node_id, time, n, cpu, cpu_max) VALUES ('sx', 50, 12, 4, 8)");
check((count(fleet_samples_rows(null, 0, 200)) === 3) && (count(fleet_samples_rows(array('sx'), 0, 200)) === 2) && (fleet_samples_rows(array(), 0, 200) === array()) &&
    (fleet_samples_rows(array('sx'), 0, 200)[0]['cpu_max'] == 8), 'sample rows for some or all firewalls, hourly before five-minute');
$sdb->exec("DELETE FROM samples WHERE node_id IN ('sx', 'sy'); DELETE FROM samples_hourly WHERE node_id = 'sx'");

/* Dashboard trends. */
check((fleet_trends_cells('online', array(array(150, 'offline'), array(170, 'online'), array(350, 'degraded')), 100, 100, 4) === array('offline', 'online', 'degraded', 'degraded')) &&
    (fleet_trends_cells(null, array(array(250, 'new'), array(260, 'online')), 100, 100, 3) === array(null, 'new', 'online')),
    'pulse cells: the worst state in each half hour, empty before the firewall joined');
check((fleet_trends_badness(array('online', 'offline', 'degraded', null)) === 110) && (fleet_trends_badness(array('online', 'new')) === 0), 'pulse rows sort by how bad they were');
check((fleet_trends_quantile(array(1, 2, 3, 4, null), .5) === 2.5) && (fleet_trends_quantile(array(10, 20, 30, 40, 50), .9) === 46.0) && (fleet_trends_quantile(array(null), .5) === null),
    'median and 90th percentile skip empty values');
$tdays = fleet_trends_days(mktime(12, 0, 0, 3, 10, 2026), 3);
check(($tdays === array('2026-03-08', '2026-03-09', '2026-03-10')) &&
    (fleet_trends_per_day(array(array(mktime(1, 0, 0, 3, 9, 2026), 'warning'), array(mktime(2, 0, 0, 3, 9, 2026), 'warning'), array(mktime(3, 0, 0, 3, 10, 2026), 'critical'),
    array(mktime(3, 0, 0, 3, 1, 2026), 'critical'), array(mktime(3, 0, 0, 3, 10, 2026), 'bogus')), $tdays, array('critical', 'warning')) ===
    array('critical' => array(0, 0, 1), 'warning' => array(0, 2, 0))), 'counts per day and kind; other days and kinds are left out');
$tb = fleet_trends_buckets(array(
    array('node_id' => 'a', 'time' => 0, 'cpu' => 10, 'cpu_max' => 10, 'mem' => 40, 'states' => 50, 'states_max' => 100, 'temp' => null, 'rx_bps' => 100, 'tx_bps' => 10),
    array('node_id' => 'a', 'time' => 50, 'cpu' => 30, 'cpu_max' => 60, 'mem' => 60, 'states' => 70, 'states_max' => 100, 'temp' => null, 'rx_bps' => 300, 'tx_bps' => 30),
    array('node_id' => 'b', 'time' => 120, 'cpu' => 90, 'cpu_max' => 90, 'mem' => 10, 'states' => 1, 'states_max' => 10, 'temp' => 70, 'rx_bps' => 1000, 'tx_bps' => null),
    array('node_id' => 'b', 'time' => 999, 'cpu' => 1, 'cpu_max' => 1, 'mem' => 1, 'states' => 1, 'states_max' => 1, 'temp' => 1, 'rx_bps' => 1, 'tx_bps' => 1)), 0, 100, 2);
check(($tb['a']['cpu'] === array(20.0, null)) && ($tb['a']['cpu_max'] === array(60.0, null)) && ($tb['b']['temp'] === array(null, 70.0)) && !isset($tb['a']['temp']),
    'sample buckets: the average per firewall and bucket, the CPU peak, samples outside the range left out');
$tl = fleet_trends_load($tb, 2);
check(($tl['cpu_med'] === array(20.0, 90.0)) && ($tl['rx'] === array(200.0, 1000.0)) && ($tl['tx'] === array(20.0, null)), 'fleet load: median CPU across firewalls, WAN traffic summed');
$tt = fleet_trends_top($tb, array('a' => 'Alpha', 'b' => 'Beta'), function ($x) { return $x['cpu']; }, 1);
check((count($tt) === 1) && ($tt[0]['label'] === 'Beta') && ($tt[0]['peak'] === 90.0) && ($tt[0]['data'] === array(null, 90.0)), 'top firewalls by their peak');
check(fleet_trends_versions(array(array('version' => '1.2.0'), array('version' => '1.1.5'), array('version' => '1.2.0'), array())) ===
    array(array('label' => '1.2.0', 'value' => 2), array('label' => '1.1.5', 'value' => 1), array('label' => 'Unknown', 'value' => 1)), 'firewalls per version, most first');

echo "Fleet controller tests: OK\n";
