<?php
/* Fleet controller tests: a firewall's System view data. Loaded by ../run.php (shares its variables). */

/* A managed firewall's answer is cut down to numbers and short plain texts before it reaches the admin's browser. */
$hostile = array('cpu' => array('model' => "Xeon\x07 <img src=x onerror=alert(1)>" . str_repeat('y', 200), 'count' => '<svg onload=x>', 'load' => array(0.5, '1.25', 'x', 9, 10)),
    'memory' => array('total_bytes' => '<img src=x onerror=alert(1)>', 'used_bytes' => '2048'), 'swap' => 'junk', 'states' => array('current' => 5, 'max' => INF),
    'mbuf' => null, 'uptime_seconds' => array('x'), 'temperatures' => array(array('celsius' => '55.5'), 'x', array('celsius' => '<b>')),
    'disks' => array(array('mount' => "/\n<script>", 'type' => 'zfs', 'used_bytes' => 1, 'total_bytes' => '2'), 'bad'), 'extra' => '<script>alert(1)</script>');
$clean = fleet_metrics_system($hostile);
check(fleet_metrics_system('x') === null && fleet_metrics_system(null) === null, 'no System data: null');
check(($clean['memory'] === array('used_bytes' => 2048, 'total_bytes' => 0)) && ($clean['cpu']['count'] === 0) && ($clean['cpu']['load'] === array(0.5, 1.25, 0.0)) &&
    ($clean['swap'] === array('used_bytes' => 0, 'total_bytes' => 0)) && ($clean['states'] === array('current' => 5, 'max' => 0)) && ($clean['mbuf'] === array('used' => 0, 'max' => 0)) &&
    ($clean['uptime_seconds'] === 0) && (array_column($clean['temperatures'], 'celsius') === array(55.5, 0, 0)) && !isset($clean['extra']),
    'System metrics: every number is cast, bad values become 0, unknown keys are dropped');
check((strlen($clean['cpu']['model']) <= 80 + 8) && (strpos($clean['cpu']['model'], "\x07") === false) && ($clean['disks'][0] === array('mount' => '/<script>', 'type' => 'zfs', 'used_bytes' => 1, 'total_bytes' => 2)) &&
    (count($clean['disks']) === 2) && (json_encode($clean) !== false),
    'System metrics: texts lose control characters and are capped, the result always encodes as JSON');
