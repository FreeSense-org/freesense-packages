<?php
/* Download the generated explicit-proxy PAC file. */
require_once('guiconfig.inc');
require_once('webgateway.inc');
$wg_config = webgateway_config();
$host = (string)($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_ADDR'] ?? '');
header('Content-Type: application/x-ns-proxy-autoconfig');
header('Content-Disposition: attachment; filename="freesense-web-gateway.pac"');
header('X-Content-Type-Options: nosniff');
echo webgateway_pac_script($wg_config, $host);
