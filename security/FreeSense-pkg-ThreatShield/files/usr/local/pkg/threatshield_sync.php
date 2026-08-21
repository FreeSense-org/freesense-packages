<?php
/*
 * threatshield_sync.php
 * High Availability (CARP / XMLRPC) Synchronization for FreeSense Threat Shield
 */

require_once('threatshield.inc');
require_once('xmlrpc_client.inc');

function threatshield_sync_xmlrpc(): void {
	$hasync = config_get_path('hasync', []);
	if (empty($hasync['synchronizetoip'])) {
		return;
	}

	$synctoip = $hasync['synchronizetoip'];
	$username = empty($hasync['username']) ? 'admin' : $hasync['username'];
	$password = $hasync['password'];
	$protocol = empty($hasync['synchronizetoip_proto']) ? 'https' : $hasync['synchronizetoip_proto'];
	$port = empty($hasync['synchronizetoip_port']) ? 443 : $hasync['synchronizetoip_port'];

	$url = "{$protocol}://{$synctoip}:{$port}/xmlrpc.php";
	$cli = new XMLRPCClient($url, $username, $password);

	$cfg = threatshield_config();
	$cli->send('threatshield_xmlrpc_receive', [threatshield_config_for_storage($cfg)]);
}

function threatshield_xmlrpc_receive(array $remote_config): bool {
	$clean = threatshield_config_for_storage($remote_config);
	$errors = threatshield_validate_config(array_replace_recursive(threatshield_default_config(), $clean));
	if (!empty($errors)) {
		return false;
	}
	config_set_path(THREATSHIELD_CONFIG_PATH, $clean);
	write_config(gettext('Synchronized Threat Shield configuration from the HA primary.'));
	return threatshield_sync_config();
}

if (php_sapi_name() === 'cli' && ($argv[1] ?? '') === 'sync') {
	threatshield_sync_xmlrpc();
}
