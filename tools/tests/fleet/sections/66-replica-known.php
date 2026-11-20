<?php
/* Fleet controller tests: peers keep copies of backups whose file is missing here. Loaded by ../run.php (shares its variables). */

$w = array('cfg.n1.7' => array('sha256' => 'aa'));
check(fleet_replica_plan($w, array('cfg.n1.7' => 'aa', 'cfg.n1.3' => 'bb', 'cfg.n1.4' => 'cc'), array('cfg.n1.3' => true)) === array(array(), array('cfg.n1.4')),
    'a peer\'s copy of a backup that still has a row here is never removed, even when its file is missing on this controller');
