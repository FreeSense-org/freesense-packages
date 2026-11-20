<?php
/* Fleet controller tests: what was reviewed is what runs. Loaded by ../run.php (shares its variables). */

$parts = array('template', 'hash1', 'all', array('n-1', 'n-2'));
$tok = fleet_review_token($parts);
check((strlen($tok) === 32) && ($tok === fleet_review_token($parts)) && ($tok !== fleet_review_token(array('template', 'hash2', 'all', array('n-1', 'n-2')))) && ($tok !== fleet_review_token(array('template', 'hash1', 'all', array('n-1')))) &&
    fleet_review_ok($parts, $tok) && !fleet_review_ok($parts, '') && !fleet_review_ok(array('template', 'hash1', 'n-1'), $tok) && !fleet_review_ok($parts, strtoupper($tok)) &&
    (strpos(fleet_review_field($parts), $tok) !== false) && (strpos(fleet_review_field(array('x"y')), '"y') === false),
    'the review token follows the targets and settings: any change makes it no longer match; it is keyed');
$u1 = fleet_users_review_state();
fleet_db()->prepare('INSERT INTO fusers (name, hash, created, updated) VALUES (?, ?, ?, ?)')->execute(array('rev.user', 'h', 1, 1));
$u2 = fleet_users_review_state();
fleet_db()->exec("DELETE FROM fusers WHERE name = 'rev.user'");
check(($u1 !== $u2) && (fleet_users_review_state() === $u1) && (strlen($u1) === 64), 'the users review state changes with the users and groups');
/* Every button that changes many firewalls carries the token, and its handler checks it. */
$www = $repo . '/sysutils/FreeSense-pkg-Fleet/files/usr/local/www/fleet/';
$miss = array();
foreach (array('fleet_templates.php' => 2, 'fleet_users.php' => 2, 'fleet_connections.php' => 2) as $f => $fields) {
	$t = (string)file_get_contents($www . $f);
	if ((substr_count($t, 'fleet_review_field(') !== $fields) || (substr_count($t, 'fleet_review_ok(') !== 1)) {
		$miss[] = $f;
	}
}
check(empty($miss), 'the template, user sync and connection apply buttons carry the review token and their handlers check it: ' . implode(', ', $miss));
