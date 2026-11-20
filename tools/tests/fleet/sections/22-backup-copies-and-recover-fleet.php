<?php
/* Fleet controller tests: backup copies and Recover fleet. Loaded by ../run.php (shares its variables). */

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

/* Recover vouches for backups: a label the sealed database does not know, or content that does not match, is left out. */
$vm = random_bytes(32);
$plain_ok = '<xml>one</xml>';
list($kept, $left) = fleet_recover_vouched(array('n1/a.xml.enc' => fleet_seal($plain_ok, $vm), 'n1/swapped.xml.enc' => fleet_seal('<xml>other</xml>', $vm),
    'n9/unknown.xml.enc' => fleet_seal($plain_ok, $vm), 'n1/foreign.xml.enc' => fleet_seal($plain_ok, random_bytes(32))),
    array('n1/a.xml.enc' => hash('sha256', $plain_ok), 'n1/swapped.xml.enc' => hash('sha256', $plain_ok), 'n1/foreign.xml.enc' => hash('sha256', $plain_ok)), $vm);
check(array_keys($kept) === array('n1/a.xml.enc') && $left === 3, 'Recover keeps only backups the copy\'s own database vouches for');
check(!is_dir(FLEET_DATA . '/.recover-' . getmypid()), 'Recover leaves no staging directory behind');
