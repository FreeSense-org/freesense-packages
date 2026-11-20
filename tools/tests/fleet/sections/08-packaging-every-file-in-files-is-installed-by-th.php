<?php
/* Fleet controller tests: packaging: every file in files/ is installed by the Makefile. Loaded by ../run.php (shares its variables). */

$port = $repo . '/sysutils/FreeSense-pkg-Fleet';
$make = str_replace('${PORTNAME}', 'FreeSense-pkg-Fleet', (string)file_get_contents("{$port}/Makefile"));
$plist = str_replace("\r", "", (string)file_get_contents("{$port}/pkg-plist"));
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
	/* ... and the package list names it, or the built package leaves it out. */
	check(preg_match('#^' . preg_quote((strpos($rel, '/usr/local/') === 0) ? substr($rel, strlen('/usr/local/')) : $rel, '#') . '$#m', $plist) === 1, "pkg-plist lists {$rel}");
}

check(fleet_box_error(422, array('error' => array('message' => 'The request failed validation.', 'details' => array('fields' => array('config' => 'The configuration is from a newer FreeSense.'))))) === 'The configuration is from a newer FreeSense.' &&
    fleet_box_error(500, array('error' => array('message' => 'Disk full.'))) === 'Disk full.' &&
    fleet_box_error(502, array()) === 'The box answered HTTP 502.' && fleet_backup_reason_text('safety') === 'Before a restore', 'restore messages');
check(fleet_event_text('node-1', 'restore', 'node-1 (Lab): backup of 2026-10-15 20:28') === array('Restored a backup', 'from 2026-10-15 20:28'), 'restore events in words');
