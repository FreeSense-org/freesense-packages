<?php
/* Fleet controller tests: user accounts that go to every firewall. Loaded by ../run.php (shares its variables). */

check(!fleet_users_valid_name('proxy') && !fleet_users_valid_name('man') && !fleet_users_valid_name('_dhcp') && !fleet_users_valid_name('Fleet-Controller') && fleet_users_valid_name('anna.b') &&
    fleet_users_valid_name('x') && !fleet_users_valid_name(str_repeat('a', 33)) && !fleet_users_valid_name(''), 'a user never takes a name FreeBSD or FreeSense uses itself, or one that starts with an underscore');
$key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoodKeyGoodKeyGoodKeyGoodKey1234 anna@pc';
check(fleet_users_ssh_keys_valid('') && fleet_users_ssh_keys_valid($key . "\n" . $key) && !fleet_users_ssh_keys_valid('command="curl x|sh" ' . $key) && !fleet_users_ssh_keys_valid($key . "\nno-pty " . $key) &&
    !fleet_users_ssh_keys_valid("ssh-ed25519 short"), 'public keys only: options such as command="..." are refused');
$bad = null;
try {
	fleet_fuser_save(null, array('name' => 'longpw', 'password' => str_repeat('x', 73), 'password_again' => str_repeat('x', 73)), 'tester');
} catch (InvalidArgumentException $e) {
	$bad = $e->getMessage();
}
check($bad === 'A password has at most 72 characters.', 'a password longer than bcrypt reads is refused instead of being cut silently');

/* A user and its groups are saved together. */
fleet_db()->prepare('INSERT INTO ugroups (name, privs, targets, created, updated) VALUES (?, ?, ?, ?, ?)')->execute(array('ug-safety', '["page-dashboard-all"]', '["all"]', time(), time()));
$gid = (int)fleet_db()->lastInsertId();
$uid = fleet_fuser_save(null, array('name' => 'safe.user', 'groups' => array($gid), 'password' => 'a-long-enough-pass', 'password_again' => 'a-long-enough-pass'), 'tester');
$sd2 = fleet_db();
$sd2->exec("CREATE TEMP TRIGGER fleet_test_boom BEFORE INSERT ON ugroup_members BEGIN SELECT RAISE(ABORT, 'boom'); END");
$boom = null;
try {
	fleet_fuser_save($uid, array('name' => 'renamed.user', 'groups' => array($gid)), 'tester');
} catch (Throwable $e) {
	$boom = $e->getMessage();
}
$sd2->exec('DROP TRIGGER fleet_test_boom');
check(($boom !== null) && ($sd2->query("SELECT name FROM fusers WHERE id = {$uid}")->fetchColumn() === 'safe.user') && ((int)$sd2->query("SELECT COUNT(*) FROM ugroup_members WHERE user_id = {$uid}")->fetchColumn() === 1) && !$sd2->inTransaction(),
    'a failure between saving a user and its groups changes nothing: the user keeps its name and its groups');
fleet_fuser_delete($uid, 'tester');
fleet_ugroup_delete($gid, 'tester');
check(((int)$sd2->query("SELECT COUNT(*) FROM fusers WHERE name = 'safe.user'")->fetchColumn() === 0) && ((int)$sd2->query("SELECT COUNT(*) FROM ugroup_members")->fetchColumn() === 0), 'deleting a user or a group removes its memberships with it');
/* fleet_transaction: all or nothing, and nested calls join the outer one. */
$tx = null;
try {
	fleet_transaction(function () use ($sd2) {
		$sd2->exec("INSERT INTO settings (name, value) VALUES ('tx-test', '1')");
		fleet_transaction(function () use ($sd2) {
			$sd2->exec("INSERT INTO settings (name, value) VALUES ('tx-test2', '1')");
			throw new RuntimeException('stop');
		});
	});
} catch (RuntimeException $e) {
	$tx = $e->getMessage();
}
check(($tx === 'stop') && ((int)$sd2->query("SELECT COUNT(*) FROM settings WHERE name LIKE 'tx-test%'")->fetchColumn() === 0) && !$sd2->inTransaction() && (fleet_transaction(function () { return 7; }) === 7),
    'a transaction rolls back everything on an error, also across nested calls');
