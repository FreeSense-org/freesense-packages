<?php
/*
 * threatshield_ajax.php
 * FreeSense Threat Shield - fragments loaded after the page (health checks, list download progress)
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield
##|*DESCR=Threat Shield status data for the WebUI
##|*MATCH=threatshield/threatshield_ajax.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/threatshield.inc');
require_once('/usr/local/pkg/threatshield/threatshield_ui.inc');

header('Cache-Control: no-store');
switch ($_GET['what'] ?? '') {
	case 'health':
		$checks = threatshield_health(!empty($_GET['deep']));
		if (($_GET['format'] ?? '') === 'json') {
			$counts = ['ok' => 0, 'warn' => 0, 'fail' => 0, 'skip' => 0];
			foreach ($checks as $c) $counts[$c['state']] = ($counts[$c['state']] ?? 0) + 1;
			header('Content-Type: application/json');
			echo json_encode(['worst' => threatshield_health_worst($checks), 'counts' => $counts, 'total' => count($checks),
			    'html' => threatshield_health_html($checks)]);
			break;
		}
		header('Content-Type: text/html; charset=utf-8');
		echo threatshield_health_html($checks);
		break;
	case 'progress':
		header('Content-Type: application/json');
		echo json_encode(threatshield_progress_view(threatshield_progress_state()));
		break;
	default:
		http_response_code(404);
}
