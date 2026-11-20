<?php
/* Fleet controller tests: alerts. Loaded by ../run.php (shares its variables). */

check(fleet_alert_classify('state', 'n-abc123 (Shop): online -> offline (FLEET-E105)')[0] === 'offline' && fleet_alert_classify('state', 'n-abc123 (Shop): online -> offline')[1] === 'n-abc123' &&
    fleet_alert_classify('state', 'n-abc123 (Shop): offline -> online')[0] === 'online' && fleet_alert_classify('state', 'n-abc123 (Shop): new -> online') === null &&
    fleet_alert_classify('state', 'n-abc123 (Shop): online -> degraded') === null && fleet_alert_classify('state', 'n-abc123 (Shop): degraded -> online') === null,
    'alerts from state changes: offline and back, not first contact or degraded (no "back online" without an "offline" first)');
check((fleet_alert_pin_normalize('AB:' . str_repeat('cd', 31)) === 'ab' . str_repeat('cd', 31)) && (fleet_alert_pin_normalize('') === '') &&
    (fleet_alert_pin_normalize('sha256 Fingerprint=' . implode(':', str_split(str_repeat('0F', 32), 2))) === str_repeat('0f', 32)) && (fleet_alert_pin_normalize('xyz') === null),
    'a trusted webhook certificate: SHA-256 with or without colons or the openssl prefix; anything else is refused');
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
/* Day labels are calendar days, also across a clock change (Europe/Copenhagen, 2026-03-29: a 23-hour day). */
date_default_timezone_set('Europe/Copenhagen');
check(fleet_trends_days(strtotime('2026-03-30 12:00:00'), 4) === array('2026-03-27', '2026-03-28', '2026-03-29', '2026-03-30'), 'day labels survive a 23-hour day');
date_default_timezone_set('UTC');
check(fleet_alert_link_base('fw.example.net', array()) === 'https://fw.example.net' && fleet_alert_link_base('fw.example.net', array('protocol' => 'https', 'port' => '8443')) === 'https://fw.example.net:8443' &&
    fleet_alert_link_base('10.0.0.1', array('protocol' => 'http', 'port' => '80')) === 'http://10.0.0.1' && fleet_alert_link_base('fd00::1', array('port' => '443')) === 'https://[fd00::1]',
    'alert links use the WebGUI protocol and port');
check(fleet_alert_url_ok('https://192.168.1.50:8443/hook') && fleet_alert_url_ok('https://hooks.example.net/x') && fleet_alert_host_blocked('127.0.0.1') && fleet_alert_host_blocked('localhost') &&
    fleet_alert_host_blocked('169.254.169.254') && fleet_alert_host_blocked('[::1]') && fleet_alert_host_blocked('fe80::1') && fleet_alert_host_blocked('::ffff:127.0.0.1') && fleet_alert_host_blocked('0.0.0.0') &&
    !fleet_alert_host_blocked('192.168.1.50') && !fleet_alert_host_blocked('hooks.example.net'),
    'a webhook cannot call the controller itself or a link-local address (cloud metadata)');
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

/* The audit log keeps the firewall and the FLEET-E code of an entry as columns; alerts read them from there. */
check(fleet_audit_subject('n-abc123 (Shop): online -> offline (FLEET-E105)') === array('n-abc123', 'FLEET-E105') && fleet_audit_subject('Shop: nothing') === array('', '') &&
    fleet_audit_subject('FLEET-E321: Lock suspended on Shop', 'n-abc123') === array('n-abc123', 'FLEET-E321') && fleet_audit_subject('x', 'n-1', 'FLEET-E999') === array('n-1', 'FLEET-E999'),
    'the firewall and the code of an audit entry: given by the caller, or read from the start of the detail');
fleet_audit('poll', 'state', 'n-col123 (Col): online -> degraded');
fleet_audit('poll', 'policy', 'FLEET-E321: Lock suspended on Col until later by x: y', 'n-col123');
$arow = fleet_db()->query("SELECT node_id, code FROM audit WHERE detail LIKE 'FLEET-E321: Lock suspended on Col%'")->fetch();
check(($arow === array('node_id' => 'n-col123', 'code' => 'FLEET-E321')) && (fleet_db()->query("SELECT node_id FROM audit WHERE detail LIKE 'n-col123 (Col)%'")->fetchColumn() === 'n-col123'),
    'fleet_audit stores the node id and the code');
check((fleet_alert_classify('policy', 'FLEET-E321: Lock suspended on Shop', 'n-abc123')[1] === 'n-abc123') && (fleet_alert_classify('policy', 'x', 'n-abc123', 'FLEET-E320')[0] === 'policy') &&
    (fleet_alert_classify('backup_verify', 'a backup is damaged FLEET-E806', 'n-abc123')[1] === 'n-abc123'),
    'break-glass and policy alerts carry their firewall');
/* Alerts about no firewall merge only with the same text: two different pending enrollments are both sent. */
$a1 = fleet_alert('approval', '', 'e-1 waits for approval');
$a2 = fleet_alert('approval', '', 'e-2 waits for approval');
$a3 = fleet_alert('approval', '', 'e-1 waits for approval');
$b1 = fleet_alert('breakglass', 'n-bg-one1', 'Lock suspended on One');
$b2 = fleet_alert('breakglass', 'n-bg-two2', 'Lock suspended on Two');
$b3 = fleet_alert('breakglass', 'n-bg-one1', 'Lock suspended on One again');
check(($a1 !== null) && ($a2 !== null) && ($a3 === null) && ($b1 !== null) && ($b2 !== null) && ($b3 === null),
    'an alert merges with the same event for the same firewall (or, for none, the same text), never with another firewall\'s');
