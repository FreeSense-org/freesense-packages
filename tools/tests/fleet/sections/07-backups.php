<?php
/* Fleet controller tests: backups. Loaded by ../run.php (shares its variables). */

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
