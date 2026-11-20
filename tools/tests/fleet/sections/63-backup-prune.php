<?php
/* Fleet controller tests: backups of firewalls that left the fleet. Loaded by ../run.php (shares its variables). */

$bp = fleet_db();
if (!is_dir(FLEET_BACKUP_DIR)) {
	mkdir(FLEET_BACKUP_DIR, 0700, true);
}
$pnow = 400 * 86400;
$bp->exec('DELETE FROM backups');
$bp->exec("INSERT OR IGNORE INTO boxes (node_id, name, label, host_no, overlay, wg_pub, api_key, cert_sha256, role, joined) VALUES ('n-bp-live', 'live', 'Live', 903, 'x', 'wgbp1', 'k', 'c', 'managed', 1)");
$bpi = $bp->prepare("INSERT INTO backups (node_id, time, reason, who, sha256, size, file, pinned) VALUES (?, ?, 'change', 'w', ?, 10, ?, ?)");
$rows = array(array('n-bp-gone', $pnow - 200 * 86400, 'old-gone', 0), array('n-bp-gone', $pnow - 200 * 86400, 'old-pinned', 1), array('n-bp-gone', $pnow - 10 * 86400, 'new-gone', 0), array('n-bp-live', $pnow - 200 * 86400, 'old-live', 0));
foreach ($rows as list($n, $t, $f, $pin)) {
	file_put_contents(FLEET_BACKUP_DIR . '/' . $f, 'x');
	$bpi->execute(array($n, $t, hash('sha256', $f), $f, $pin));
}
list($removed, $freed) = fleet_backup_prune('tester', $pnow);
$left = $bp->query('SELECT group_concat(file) FROM (SELECT file FROM backups ORDER BY file)')->fetchColumn();
check(($removed === 1) && ($freed === 10) && ($left === 'new-gone,old-live,old-pinned') && !is_file(FLEET_BACKUP_DIR . '/old-gone') && is_file(FLEET_BACKUP_DIR . '/old-pinned') && is_file(FLEET_BACKUP_DIR . '/old-live'),
    'backups of a firewall that left the fleet are removed after the keep_removed time (row and file); pinned, recent and live firewalls\' backups stay');
foreach (array('new-gone', 'old-live', 'old-pinned') as $f) {
	@unlink(FLEET_BACKUP_DIR . '/' . $f);
}
$bp->exec("DELETE FROM backups; DELETE FROM boxes WHERE node_id = 'n-bp-live'");
