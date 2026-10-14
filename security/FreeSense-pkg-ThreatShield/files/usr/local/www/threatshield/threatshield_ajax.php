<?php
/*
 * threatshield_ajax.php
 * FreeSense Threat Shield - fragments loaded after the page (health checks)
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
		header('Content-Type: text/html; charset=utf-8');
		echo threatshield_health_html(threatshield_health(!empty($_GET['deep'])));
		break;
	default:
		http_response_code(404);
}
