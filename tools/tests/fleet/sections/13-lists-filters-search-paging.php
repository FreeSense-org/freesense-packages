<?php
/* Fleet controller tests: lists: filters, search, paging. Loaded by ../run.php (shares its variables). */

check(fleet_list_filters(array('state' => 'failed', 'kind' => 'evil', 'q' => "  cph\x01 ", 'since' => '7', 'x' => 'y'),
    array('q' => null, 'state' => FLEET_OPS_STATES, 'kind' => FLEET_OPS_KINDS, 'since' => FLEET_OPS_SINCE)) === array('q' => 'cph', 'state' => 'failed', 'since' => '7'),
    'only known filter values survive; search is trimmed and cleaned');
check(fleet_list_page(0, 3) === array('page' => 1, 'pages' => 1, 'per' => 25, 'offset' => 0, 'total' => 0, 'first' => 0, 'last' => 0) &&
    fleet_list_page(340, 2)['first'] === 26 && fleet_list_page(340, 2)['last'] === 50 && fleet_list_page(340, 99)['page'] === 14, 'paging, past the end shows the last page');
check(fleet_list_page_links(1, 1) === array(1) && fleet_list_page_links(7, 14) === array(1, 0, 6, 7, 8, 0, 14) && fleet_list_page_links(2, 4) === array(1, 2, 3, 4),
    'page links with gaps');
check(fleet_list_like('50%_off') === '%50\%\_off%', 'a search for % or _ is literal');
check(strpos(fleet_list_url(array('op' => 3), array('state' => 'failed', 'page' => 4), array('q' => 'x')), 'page') === false &&
    fleet_list_url(array(), array('state' => 'failed'), array('page' => 2)) === '?state=failed&page=2', 'changing a filter goes back to page 1');
for ($i = 0; $i < 30; $i++) {
	fleet_op_set(fleet_op_start('node-list', 'reboot', 'Rebooting', ($i % 2) ? 'alice' : 'bob'), ($i % 3) ? 'done' : 'failed', '50%_done');
}
list($rows, $pg) = fleet_ops_find(array('kind' => 'reboot', 'q' => 'alice'), 1, time());
check($pg['total'] === 15 && count($rows) === 15, 'filter by action and search by person');
list($rows, $pg) = fleet_ops_find(array('kind' => 'reboot'), 2, time());
check($pg['page'] === 2 && count($rows) === min(25, $pg['total'] - 25), 'the second page holds the rest');
list(, $pg) = fleet_ops_find(array('state' => 'failed', 'q' => '50%_'), 1, time());
check($pg['total'] === 10, 'state filter plus a literal % search');
list(, $pg2) = fleet_ops_find(array('q' => 'no such thing'), 1, time());
check($pg2['total'] === 0, 'no match is zero, not everything');
list(, $pg) = fleet_ops_find(array('q' => 'node-gb'), 1, time());
check($pg['total'] === 1, 'a group operation is found by one of its firewalls');
fleet_audit('poll', 'state', 'node-ev (Ev): online -> offline');
fleet_audit('admin', 'reboot', 'node-ev (Ev): reboot started');
fleet_audit('admin', 'backup', 'node-ev (Ev): stored');
list($evs, $epg) = fleet_events_find('node-ev', array('type' => 'manage'), 1, time());
check($epg['total'] === 1 && $evs[0]['action'] === 'reboot', 'events filtered by type');
list(, $epg) = fleet_events_find('node-ev', array('q' => 'offline'), 1, time());
check($epg['total'] === 1, 'events searched');
