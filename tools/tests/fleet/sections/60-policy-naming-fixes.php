<?php
/* Fleet controller tests: exceptions, fix loops and naming. Loaded by ../run.php (shares its variables). */

/* A rule with an exception is not locked or fixed on that firewall. */
$eff = array('SEC-002' => array(array(), 'lock', 1, 'P', null), 'SEC-012' => array(array(), 'lock', 1, 'P', null));
$exs = array(array('node_id' => 'n-x-0001', 'rule_id' => 'SEC-002', 'expires' => 5000), array('node_id' => 'n-other', 'rule_id' => 'SEC-012', 'expires' => 5000));
check((array_keys(fleet_policy_without_exceptions($eff, $exs, 'n-x-0001', 1000)) === array('SEC-012')) && (array_keys(fleet_policy_without_exceptions($eff, $exs, 'n-x-0001', 6000)) === array('SEC-002', 'SEC-012')) &&
    (array_keys(fleet_policy_without_exceptions($eff, $exs, 'n-nobody', 1000)) === array('SEC-002', 'SEC-012')), 'an exception takes the rule out of that firewall\'s bundle until it ends');

/* A fix that is undone again and again stops after three in a day. */
$failing = array('SEC-002' => array('x' => 1));
$h = hash('sha256', json_encode($failing['SEC-002']));
$last = array('SEC-002' => array('time' => 1000, 'hash' => $h, 'result' => 'fixed', 'detail' => '', 'fixed_count' => 3, 'fixed_since' => 500));
check((fleet_remediate_due($failing, $last, 1000 + 4000, false) === array()) && (array_keys(fleet_remediate_due($failing, $last, 1000 + 4000, true)) === array('SEC-002')) &&
    (array_keys(fleet_remediate_due($failing, $last, 500 + FLEET_AUTOFIX_WINDOW + 1, false)) === array('SEC-002')) &&
    (array_keys(fleet_remediate_due($failing, array('SEC-002' => array('fixed_count' => 2) + $last['SEC-002']), 1000 + 4000, false)) === array('SEC-002')),
    'after three fixes in a day an automatic fix of the same rule waits for a person; Fix now still works; a new day starts again');
$rn = 'n-rm-0001';
$c1 = fleet_remediation_record($rn, 'SEC-002', 'h', 'fixed', 'a');
$c2 = fleet_remediation_record($rn, 'SEC-002', 'h', 'fixed', 'b');
$cf = fleet_remediation_record($rn, 'SEC-002', 'h', 'failed', 'c');
$c3 = fleet_remediation_record($rn, 'SEC-002', 'h', 'fixed', 'd');
fleet_db()->prepare('UPDATE remediation_state SET fixed_since = ? WHERE node_id = ?')->execute(array(time() - FLEET_AUTOFIX_WINDOW - 5, $rn));
$c4 = fleet_remediation_record($rn, 'SEC-002', 'h', 'fixed', 'e');
check(array($c1, $c2, $cf, $c3, $c4) === array(1, 2, 2, 3, 1), 'fixes are counted per rule in a day; a failure does not count; the day restarts the count');
fleet_db()->exec('DELETE FROM remediation_state');

/* Naming: each attribute is decided on its own. */
$ga = array('id' => 1, 'name' => 'A', 'naming_pattern' => '', 'naming_domain' => 'a.example');
$gb = array('id' => 2, 'name' => 'B', 'naming_pattern' => 'fw-{nn}', 'naming_domain' => '');
$gc = array('id' => 3, 'name' => 'C', 'naming_pattern' => 'shop-{nn}', 'naming_domain' => 'c.example');
check((fleet_naming_pick(array($ga, $gb), 'pattern')[0]['name'] === 'B') && (fleet_naming_pick(array($ga, $gb), 'domain')[0]['name'] === 'A') && (fleet_naming_pick(array($ga, $gb))[0]['name'] === 'A') &&
    (fleet_naming_pick(array($ga, $gb), 'pattern')[1] === array()) && (fleet_naming_pick(array($ga), 'pattern') === array(null, array())) && (fleet_naming_pick(array(), '') === array(null, array())) &&
    (fleet_naming_pick(array($ga, $gb, $gc), 'pattern') === array($gb, array('C'))) && (fleet_naming_pick(array($ga, $gb, $gc), 'domain') === array($ga, array('C'))),
    'a group with only a domain no longer hides another group\'s pattern; groups that set an attribute differently are named as conflicts');
fleet_naming_counter_raise('t-scope', 10);
fleet_naming_counter_raise('t-scope', 5);
fleet_naming_counter_raise('t-scope', 12);
check((int)fleet_db()->query("SELECT next FROM name_counters WHERE scope = 't-scope'")->fetchColumn() === 12, 'a naming counter only goes up');
fleet_db()->exec("DELETE FROM name_counters WHERE scope = 't-scope'");

/* An open invitation holds its name alone. */
$ni = fleet_db();
$gid = fleet_group_save(null, 'Naming test', '', '1', 'tester');
fleet_naming_set($gid, 'nt-{nn}', '', 'tester');
$mk = function (string $id) use ($ni) {
	$ni->prepare("INSERT INTO invitations (token_id, secret_hash, okm, role, label, created, expires, state) VALUES (?, 'h', 'x', 'managed', 'l', ?, ?, 'open')")->execute(array($id, time(), time() + 3600));
};
$mk('nm-tok-1');
$mk('nm-tok-2');
$mk('nm-tok-3');
list($n1) = fleet_invite_set_name('nm-tok-1', $gid, 's', 'managed', '', 'tester');
list($n2) = fleet_invite_set_name('nm-tok-2', $gid, 's', 'managed', '', 'tester');
$dup = null;
try {
	fleet_invite_set_name('nm-tok-3', $gid, 's', 'managed', $n1, 'tester');
} catch (InvalidArgumentException $e) {
	$dup = $e->getMessage();
}
$sql = null;
try {
	$ni->exec("UPDATE invitations SET hostname = '{$n1}' WHERE token_id = 'nm-tok-3'");
} catch (PDOException $e) {
	$sql = $e->getMessage();
}
check(($n1 !== '') && ($n2 !== '') && ($n1 !== $n2) && ($dup !== null) && (strpos((string)$sql, 'UNIQUE') !== false) && (fleet_naming_taken() !== array()) &&
    ($ni->query("SELECT hostname FROM invitations WHERE token_id = 'nm-tok-3'")->fetchColumn() === ''),
    'two invitations never get the same name (the second is refused, and the database refuses it too); a refused name is not kept');
$ni->exec("DELETE FROM invitations WHERE token_id LIKE 'nm-tok-%'");
$ni->exec('DELETE FROM name_counters');
fleet_group_delete($gid, 'tester');
