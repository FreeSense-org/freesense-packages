<?php
/* Fleet controller tests: deployment factory. Loaded by ../run.php (shares its variables). */

$frows = fleet_factory_rows("site,label,serial,instance_id,hostname\ncph,Copenhagen 1,PT-1,,\n\ncph;Copenhagen 2;PT-2;;\naar,Aarhus,,i-9,AAR-EDGE\n");
check(count($frows) === 3 && $frows[1]['label'] === 'Copenhagen 2' && $frows[1]['serial'] === 'PT-2' && $frows[2]['hostname'] === 'aar-edge' && $frows[0]['line'] === 2,
    'rows from pasted CSV (header skipped, comma or semicolon)');
$fnaming = array('gid' => 3, 'group' => 'Retail', 'pattern' => '{site}-fw{nn}', 'domain' => 'shops.example.local');
list($fplan, $fcount) = fleet_factory_plan($frows, array('mode' => 'attended'), $fnaming, array('3:cph-fw#' => 4), array('cph-fw05'));
check($fplan[0]['hostname'] === 'cph-fw04' && $fplan[1]['hostname'] === 'cph-fw06' && $fplan[2]['hostname'] === 'aar-edge' && $fplan[0]['domain'] === 'shops.example.local' &&
    $fcount['3:cph-fw#'] === 7 && empty($fplan[0]['problems']), 'rows are named from the group: counters go on, taken names are skipped, a typed name wins');
list($fbad) = fleet_factory_plan(fleet_factory_rows("cph,Shop,,,\ncph,shop,,,\n,Pop-up,,,\nx,Bad,a b,,\nosl,Taken,,,aar-edge"), array('mode' => 'unattended'), $fnaming, array(), array('aar-edge'));
check(strpos(implode(' ', $fbad[1]['problems']), 'same label') !== false && strpos(implode(' ', $fbad[2]['problems']), 'site') !== false &&
    strpos(implode(' ', $fbad[3]['problems']), 'serial') !== false && strpos(implode(' ', $fbad[4]['problems']), 'already') !== false &&
    strpos(implode(' ', $fbad[0]['problems']), 'Unattended needs') !== false, 'E120 problems: duplicate label, no site for the pattern, bad serial, taken name, unattended without binding');
check(fleet_enroll_binding_ok('', '', array()) && fleet_enroll_binding_ok('PT-1', '', array('serial' => 'PT-1')) && !fleet_enroll_binding_ok('PT-1', '', array('serial' => 'PT-2')) &&
    fleet_enroll_binding_ok('PT-1', 'i-9', array('serial' => '', 'instance_id' => 'i-9')) && !fleet_enroll_binding_ok('', 'i-9', array()), 'binding to a serial or instance id (E121 otherwise)');
$fenc = fleet_factory_encrypt('bundle bytes', 'correct horse battery', 1000);
check(fleet_factory_decrypt($fenc, 'correct horse battery', 1000) === 'bundle bytes' && fleet_factory_decrypt($fenc, 'wrong', 1000) !== 'bundle bytes' && strncmp($fenc, 'Salted__', 8) === 0,
    'the bundle encryption (OpenSSL salted format)');
if (trim((string)@shell_exec('command -v openssl')) !== '') {
	$ftmp = tempnam(sys_get_temp_dir(), 'fenc');
	file_put_contents($ftmp, fleet_factory_encrypt('opens anywhere', 'correct horse battery', 1000));
	check(trim((string)shell_exec('openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000 -pass pass:"correct horse battery" -in ' . escapeshellarg($ftmp))) === 'opens anywhere',
	    'the openssl command opens the bundle');
	@unlink($ftmp);
}
check(fleet_factory_passphrase_problem('short') !== null && fleet_factory_passphrase_problem('aaaaaaaaaaaaaaa') !== null && fleet_factory_passphrase_problem('Spring rollout 2026') === null, 'bundle passphrases');
$fseed = fleet_factory_seed(fleet_invite_link_build('fw.example.net:8443', 'aabbccddeeff', str_repeat('A', 43), str_repeat('ab', 32), 'tunnel'), 'pin', 'FLT-AAAA-BBBB', '123456');
check(!isset($fseed['key']) && isset($fseed['sealed_key']['data']) && !isset(fleet_factory_seed('l', 'attended', 'FLT-X', null)['sealed_key']) &&
    fleet_factory_seed('l', 'unattended', 'FLT-X', null)['key'] === 'FLT-X', 'seeds: attended without key, PIN sealed, unattended with key');
if (is_file($src . '/src/etc/inc/fleet_seed.inc')) {
	require_once($src . '/src/etc/inc/fleet_seed.inc');
	check(fleet_seed_open_key($fseed['sealed_key'], '123456') === 'FLT-AAAA-BBBB' && fleet_seed_open_key($fseed['sealed_key'], '654321') === null,
	    'the firewall opens a Factory PIN seed with the right PIN only');
	check(fleet_seed_parse(json_encode($fseed))['mode'] === 'pin', 'the firewall accepts the Factory seed');
}
check(fleet_batch_row_state(array('box' => null, 'inv_state' => 'open', 'expires' => 10), 20) === 'expired' && fleet_batch_row_state(array('box' => 'n1', 'inv_state' => 'used', 'expires' => 0), 20) === 'joined' &&
    fleet_batch_row_state(array('box' => null, 'inv_state' => 'open', 'expires' => 99), 20) === 'waiting', 'batch row states');

fleet_db()->prepare('INSERT INTO batches (name, settings, created, who) VALUES (?, ?, ?, ?)')->execute(array('t', '{}', 1, 't'));
check(is_array(fleet_batch_rows((int)fleet_db()->lastInsertId())), 'batch rows can be read (the query matches the schema)');

/* An unattended seed is kept short: 3 days by default, 7 at most; the other modes keep their 14 and 30. */
check(fleet_factory_settings(array('name' => 'x', 'mode' => 'unattended'))['days'] === 3 && fleet_factory_settings(array('name' => 'x', 'mode' => 'unattended', 'days' => 30))['days'] === 7 &&
    fleet_factory_settings(array('name' => 'x', 'mode' => 'attended'))['days'] === 14 && fleet_factory_settings(array('name' => 'x', 'mode' => 'pin', 'days' => 30))['days'] === 30,
    'an unattended seed lives 3 days by default and 7 at most');
