<?php
/* Fleet controller tests: retention. Loaded by ../run.php (shares its variables). */

$rd = fleet_db();
$rnow = 2000 * 86400;
$old = $rnow - 400 * 86400;
$mid = $rnow - 60 * 86400;
$fresh = $rnow - 3600;
$rd->exec('DELETE FROM audit');
foreach (array($old, $mid, $fresh) as $t) {
	$rd->prepare("INSERT INTO audit (time, who, action, detail) VALUES (?, 'x', 'y', 'z')")->execute(array($t));
}
/* Operations: a finished group with tasks, a finished single one, a running old one, a fresh one. */
$rd->exec('DELETE FROM ops; DELETE FROM rollouts');
$insop = $rd->prepare("INSERT INTO ops (id, node_id, kind, state, text, who, started, updated, finished, parent) VALUES (?, 'n', 'reboot', ?, 't', 'w', ?, ?, ?, ?)");
$insop->execute(array(1, 'done', $old, $old, $old, null));
$insop->execute(array(2, 'done', $old, $old, $old, 1));
$insop->execute(array(3, 'failed', $old, $old, $old, null));
$insop->execute(array(4, 'running', $old, $old, null, null));
$insop->execute(array(5, 'done', $fresh, $fresh, $fresh, null));
$rd->exec("INSERT INTO rollouts (op_id, target, rings, state, gap, who, created) VALUES (1, 'a', '[]', 'done', 0, 'w', {$old}), (4, 'b', '[]', 'running', 0, 'w', {$old})");
/* Alerts, enrollments, invitations. */
$rd->exec('DELETE FROM alerts');
$rd->exec("INSERT INTO alerts (time, event, severity, node_id, text, sent) VALUES ({$old}, 'test', 'info', '', 'old', '{}'), ({$fresh}, 'test', 'info', '', 'new', '{}')");
$rd->exec('DELETE FROM enrollments; DELETE FROM invitations; DELETE FROM batch_rows');
$insinv = $rd->prepare("INSERT INTO invitations (token_id, secret_hash, okm, role, label, created, expires, state) VALUES (?, 'h', ?, 'managed', 'l', ?, ?, ?)");
$insinv->execute(array('i-old-used', '', $old, $old + 3600, 'used'));
$insinv->execute(array('i-old-burn', 'sealed', $old, $old + 3600, 'burned'));
$insinv->execute(array('i-old-batch', '', $old, $old + 3600, 'used'));
$insinv->execute(array('i-old-enr', '', $old, $old + 3600, 'used'));
$insinv->execute(array('i-open-exp', 'sealed', $old, $old + 3600, 'open'));
$insinv->execute(array('i-open-now', 'sealed', $fresh, $rnow + 3600, 'open'));
$insinv->execute(array('i-new-used', 'sealed', $fresh, $fresh + 100, 'used'));
$rd->exec("INSERT INTO batch_rows (batch_id, n, site, label, hostname, domain, serial, instance_id, token_id) VALUES (1, 1, 's', 'l', 'h', 'd', '', '', 'i-old-batch')");
$rd->exec("INSERT INTO enrollments (id, token_id, node_wg_pub, inventory, code, state, created) VALUES ('e1', 'i-old-enr', 'k', '{}', '1', 'approved', {$old}), ('e2', 'i-open-now', 'k2', '{}', '2', 'pending', {$old})");
$rd->exec('DELETE FROM policy_exceptions');
$rd->exec("INSERT INTO policy_exceptions (node_id, rule_id, reason, who, created, expires) VALUES ('n', 'r', 'x', 'w', {$old}, {$old}), ('n', 'r2', 'x', 'w', {$old}, {$rnow})");
$gone = fleet_retention_prune($rnow);
check(($rd->query('SELECT COUNT(*) FROM audit')->fetchColumn() == 2) && ($rd->query('SELECT group_concat(id) FROM (SELECT id FROM ops ORDER BY id)')->fetchColumn() === '4,5') &&
    ($rd->query('SELECT COUNT(*) FROM rollouts')->fetchColumn() == 1) && ($rd->query('SELECT group_concat(text) FROM alerts')->fetchColumn() === 'new'),
    'retention removes old audit entries, finished actions with their tasks and rollouts, and old alerts; running ones stay');
check(($rd->query("SELECT group_concat(token_id) FROM (SELECT token_id FROM invitations ORDER BY token_id)")->fetchColumn() === 'i-new-used,i-old-batch,i-open-now') &&
    ($rd->query('SELECT group_concat(id) FROM enrollments')->fetchColumn() === 'e2') &&
    ($rd->query("SELECT group_concat(okm) FROM invitations WHERE okm != ''")->fetchColumn() === 'sealed') && ($rd->query("SELECT COUNT(*) FROM policy_exceptions")->fetchColumn() == 1),
    'retention: old decided enrollments and the invitations that are over go (not those a batch row points at), pending enrollments stay, join keys of invitations that are over are cleared');
check(($gone['audit'] === 1) && ($gone['ops'] === 2) && ($gone['ops_tasks'] === 1) && ($gone['alerts'] === 1), 'retention reports what it removed');
foreach (array('audit', 'ops', 'rollouts', 'alerts', 'enrollments', 'invitations', 'batch_rows', 'policy_exceptions') as $t) {
	$rd->exec("DELETE FROM {$t}");
}
