<?php
/* Fleet controller tests: Open WebUI. Loaded by ../run.php (shares its variables). */

$tok = str_repeat('a', 43);
$st = array('webgui' => array(array('name' => 'LAN', 'url' => 'https://192.168.1.1')));
check(fleet_handoff_url($st, 'https://192.168.1.1', "/?fleet_handoff={$tok}") === "https://192.168.1.1/?fleet_handoff={$tok}", 'a reported address and a handoff path');
check(fleet_handoff_url($st, 'https://evil.example', "/?fleet_handoff={$tok}") === null && fleet_handoff_url(array(), 'https://192.168.1.1', "/?fleet_handoff={$tok}") === null,
    'never an address the box did not report (no open redirect)');
check(fleet_handoff_url($st, 'https://192.168.1.1', '//evil.example/') === null && fleet_handoff_url($st, 'https://192.168.1.1', "/?fleet_handoff={$tok}&x=1") === null,
    'only a handoff path');
check(fleet_box_target(array('overlay' => 'fd00::10', 'cert_sha256' => 'ab'))['authority'] === '[fd00::10]:8444', 'the box API over the tunnel');
$privs = file_get_contents($repo . '/sysutils/FreeSense-pkg-Fleet/files/etc/inc/priv/fleet.priv.inc');
check(strpos($privs, "'page-status-fleet-dashboard'") !== false && strpos($privs, 'fleet/fleet_box.php*') !== false, 'a read-only privilege for the dashboard and box pages');

check(fleet_event_text('node-1', 'joined', 'node-1 (Lab) at fd00::10') === array('Joined the fleet', 'tunnel address fd00::10') &&
    fleet_event_text('node-1', 'state', 'node-1 (Lab): online -> degraded (FLEET-E105: x)') === array('Online to degraded', 'FLEET-E105: x') &&
    fleet_event_text('node-1', 'state', 'node-1 (Lab): degraded -> online') === array('Degraded to online', '') &&
    fleet_event_text('node-1', 'handoff', 'node-1 (Lab): WebUI as admin via https://192.0.2.1') === array('Opened the WebUI', 'as admin via https://192.0.2.1'),
    'event lines without the box\'s own ID');
check(fleet_event_text('node-1', 'backup', 'node-1 (Lab): Nightly, 0123456789ab') === array('Backed up', 'Nightly') &&
    fleet_event_text('node-1', 'backup', 'node-1 (Lab): Backed up by hand, 0123456789ab') === array('Backed up', 'by hand') &&
    fleet_event_text('node-1', 'backup_failed', 'node-1 (Lab): FLEET-E105: x') === array('Backup failed', 'FLEET-E105: x') &&
    fleet_event_text('node-1', 'backup_download', 'node-1 (Lab): backup of 2026-10-15 20:28') === array('Downloaded a backup', 'from 2026-10-15 20:28'),
    'backup events in words');

/* The token is only sent over https, to a plain host. */
$hst = array('webgui' => array(array('url' => 'http://192.168.1.1'), array('url' => 'https://u@evil.example'), array('url' => 'https://192.168.1.2:8443')));
check((fleet_handoff_url($hst, 'http://192.168.1.1', "/?fleet_handoff={$tok}") === null) && (fleet_handoff_url($hst, 'https://u@evil.example', "/?fleet_handoff={$tok}") === null) &&
    (fleet_handoff_url($hst, 'https://192.168.1.2:8443', "/?fleet_handoff={$tok}") === "https://192.168.1.2:8443/?fleet_handoff={$tok}"), 'Open WebUI refuses http and addresses with a user part');
