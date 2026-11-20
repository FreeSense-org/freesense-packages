<?php
/* Fleet controller tests: Fleet is 1.2 only. Loaded by ../run.php (shares its variables). */

$gpkg = $repo . '/sysutils/FreeSense-pkg-Fleet/files/pkg-install.in';
$gmk = (string)@file_get_contents($repo . '/Mk/bsd.freesense-package.mk');
$gsrc = (string)@file_get_contents($gpkg);
check((strpos($gmk, 'RUN_DEPENDS+=	FreeSense-platform-abi=${FREESENSE_PACKAGE_TRAIN}.0') !== false) &&
    (strpos($gsrc, '"PRE-INSTALL"') !== false) && (strpos($gsrc, '-lt 11') !== false) && (strpos($gsrc, 'fleet_agent.inc') !== false) && (strpos($gsrc, 'exit 1') !== false),
    'Fleet installs only on FreeSense 1.2: the package pins its release train, and its install script refuses a System without the agent and API level 11');
