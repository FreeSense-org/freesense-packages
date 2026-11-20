<?php
/* Fleet controller tests: NOC looks and the live view. Loaded by ../run.php (shares its variables). */

check((fleet_kiosk_look('hacker', 'light') === array('hacker', 'light')) && (fleet_kiosk_look('<x>', 'neon') === array('freesense', 'auto')) && (count(FLEET_KIOSK_STYLES) === 5),
    'five NOC styles in light, dark or the screen\'s own setting; anything else is the default');
$nocp = fleet_kiosk_page(true, 'blueprint', 'dark', true, array('css' => 1, 'js' => 2));
$nock = fleet_kiosk_page(false, 'pro', 'auto', false, array());
check((strpos($nocp, 'class="k--blueprint" data-theme="dark"') !== false) && (strpos($nocp, 'id="k-style"') !== false) && (strpos($nocp, 'data-mode="live"') !== false) &&
    (strpos($nock, 'id="k-style"') === false) && (strpos($nock, 'data-theme=') === false || strpos($nock, ' data-theme="') === false) && (stripos($nocp . $nock, '<script>') === false) && (stripos($nocp . $nock, 'style="') === false),
    'the live view has a style picker, a wall screen does not, and neither page has inline script or style (the CSP)');
$nocv = fleet_kiosk_view(array('boxes' => array(array('node_id' => 'n1', 'state' => 'online', 'groups' => array(), 'version' => '', 'seen' => 0, 'policy' => 0, 'breakglass' => false,
    'update' => null, 'op' => null, 'label' => 'A', 'host' => 'a', 'problem' => '')), 'headline' => '', 'total' => 1, 'counts' => array(), 'checked' => 0, 'now' => 0), array(), true, 'T', array('control', 'dark'));
check(!isset($nocv['boxes'][0]['id']) && ($nocv['style'] === 'control') && ($nocv['theme'] === 'dark'), 'a screen that hides names gets no firewall ids, and every screen gets its saved look');
$kc = fleet_kiosk_config_parse(array());
check(($kc === fleet_kiosk_config_defaults()) && (count(FLEET_KIOSK_PANELS) === 22) && in_array('inet', $kc['panels'], true) && in_array('inet', $kc['columns'], true) && in_array('ha', $kc['panels'], true) && in_array('controller', $kc['panels'], true),
    'a screen without settings gets the defaults: split view, every panel, list fitted to the screen');
$kc = fleet_kiosk_config_parse(array('layout' => 'panels', 'left' => '93', 'side' => 'right', 'view' => 'tiles', 'columns' => array('cpu', 'bogus', 'ha'), 'sort' => 'up',
    'groups' => array('3', '0', 'x', '3'), 'rows' => '1', 'flip' => '2', 'panel_flip' => '9999', 'range' => '1y', 'panels' => array('alerts', 'ha', 'nope', 'health'),
    'order' => array('health' => 1, 'ha' => 2, 'alerts' => 3), 'beep' => array('ha', 'boom')), true);
check(($kc['layout'] === 'panels') && ($kc['left'] === 75) && ($kc['side'] === 'right') && ($kc['view'] === 'tiles') && ($kc['columns'] === array('state', 'name', 'cpu', 'ha')) &&
    ($kc['sort'] === 'problems') && ($kc['groups'] === array(3)) && ($kc['rows'] === 3) && ($kc['flip'] === 5) && ($kc['panel_flip'] === 300) && ($kc['range'] === '24h') &&
    ($kc['panels'] === array('health', 'ha', 'alerts')) && ($kc['beep'] === array('ha')) && ($kc['hold'] === false) && ($kc['sound'] === false),
    'screen settings: clamped, unknown values dropped, state and name always shown, panels in the order asked for, unticked boxes off');
check(fleet_kiosk_config_parse(array('layout' => 'panels', 'panels' => array()), true)['layout'] === 'list' && fleet_kiosk_config_json('not json') === fleet_kiosk_config_defaults() &&
    (fleet_kiosk_config_json(json_encode($kc)) === $kc), 'panels only with no panel shows the list; stored settings read back the same');
$kpan = array('pulse' => array('rows' => array(array('label' => 'Copenhagen HQ', 'node' => 'n1', 'link' => '/fleet/fleet_box.php?id=n1', 'cells' => array()))),
    'alerts' => array('latest' => array(array('time' => 1, 'severity' => 'critical', 'title' => 'Firewall offline', 'node' => 'n1', 'box' => 'Copenhagen HQ', 'text' => 'x'))),
    'ha' => array('pairs' => array(array('name' => 'Copenhagen HQ + Oslo', 'members' => array(array('node' => 'n1', 'label' => 'Copenhagen HQ', 'role' => 'MASTER'), array('node' => 'n2', 'label' => 'Oslo', 'role' => 'BACKUP')))) ),
    'busiest' => array('busiest' => array(array('label' => 'Oslo', 'node' => 'n2', 'cpu' => 4))),
    'controller' => array('host' => 'hq-fleet.example', 'standby_addr' => '198.51.100.7', 'load' => array(0.1)));
$kh = fleet_kiosk_panels_hide($kpan, array('n1' => 'Firewall 1', 'n2' => 'Firewall 2'));
$khj = json_encode($kh);
check((strpos($khj, 'Copenhagen') === false) && (strpos($khj, 'Oslo') === false) && (strpos($khj, 'hq-fleet') === false) && (strpos($khj, '198.51') === false) && (strpos($khj, 'fleet_box') === false) &&
    ($kh['ha']['pairs'][0]['name'] === 'Pair 1') && ($kh['ha']['pairs'][0]['members'][1]['label'] === 'Firewall 2') && ($kh['alerts']['latest'][0]['box'] === 'Firewall 1') &&
    ($kh['busiest']['busiest'][0]['label'] === 'Firewall 2'), 'hidden names in the panels: firewalls numbered as in the list, no links, server name or addresses');
$kv = fleet_kiosk_view($kdata, array(), false, 'NOC', array('freesense', 'auto'), fleet_kiosk_config_parse(array('sort' => 'name')),
    array('n9' => array('cpu' => 12.5, 'mem' => 40.0, 'rx' => 1000, 'tx' => 2000, 'up' => 99.5, 'ha' => 'MASTER')), $kpan);
check(($kv['boxes'][0]['name'] === 'Copenhagen HQ') && array_key_exists('cpu', $kv['boxes'][1]) && array_key_exists('ha', $kv['boxes'][1]) && isset($kv['layout']['columns']) &&
    !isset($kv['layout']['groups']) && isset($kv['panels']['ha']), 'the list carries load, traffic, availability and HA role; a problem stays first in any order; panels and layout are sent');
$kg = fleet_kiosk_view($kdata, array(), false, 'NOC', array('freesense', 'auto'), fleet_kiosk_config_parse(array('groups' => array(1))));
check((count($kg['boxes']) === 1) && ($kg['total'] === 1) && ($kg['counts']['offline'] === 1) && ($kg['headline'] === '1 of 1 firewall needs attention'),
    'a screen for some groups shows, counts and heads only their firewalls');
$kx = fleet_kiosk_view(array('boxes' => array(array('id' => 'n7', 'state' => 'online', 'groups' => array(), 'version' => '', 'seen' => 0, 'policy' => 0, 'breakglass' => false,
    'update' => null, 'op' => null, 'label' => 'A', 'host' => 'a', 'problem' => '')), 'headline' => '', 'total' => 1, 'counts' => array(), 'checked' => 0, 'now' => 0), array(), false, 'T',
    array('freesense', 'auto'), null, array('n7' => array('cpu' => 5.0)));
check(($kx['boxes'][0]['id'] === 'n7') && ($kx['boxes'][0]['cpu'] === 5.0), 'the live view links each firewall (the dashboard rows carry id, not node_id)');
