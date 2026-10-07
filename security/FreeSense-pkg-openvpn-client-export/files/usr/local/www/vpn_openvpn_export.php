<?php
/*
 * vpn_openvpn_export.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2004-2026 The FreeSense Project
 * Copyright (C) 2008 Shrew Soft Inc
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once("globals.inc");
require_once("guiconfig.inc");
require_once("openvpn-client-export.inc");
require_once("freesense-utils.inc");
require_once("pkg-utils.inc");
require_once("certs.inc");
require_once("classes/Form.class.php");

global $current_openvpn_version, $current_openvpn_version_rev;
global $legacy_openvpn_version, $legacy_openvpn_version_rev;
global $dyndns_split_domain_types, $p12_encryption_levels;

$a_server = config_get_path('openvpn/openvpn-server', []);
$a_user = config_get_path('system/user', []);
$a_cert = config_get_path('cert', []);

$ras_server = array();
foreach ($a_server as $srvidx => $server) {
	if (isset($server['disable'])) {
		continue;
	}
	$vpnid = $server['vpnid'];
	$ras_user = array();
	$ras_certs = array();
	if (stripos($server['mode'], "server") === false) {
		continue;
	}
	$ecdsagood = array();
	foreach (config_get_path('cert', []) as $cert) {
		if (!empty($cert['prv']) &&
		    !cert_check_pkey_compatibility($cert['prv'], 'OpenVPN')) {
			continue;
		} else {
			$ecdsagood[] = $cert['refid'];
		}
	}

	if (($server['mode'] == "server_tls_user") && ($server['authmode'] == "Local Database")) {
		foreach ($a_user as $uindex => $user) {
			if (!is_array($user['cert'])) {
				continue;
			}
			foreach ($user['cert'] as $cindex => $cert) {
				// If $cert is not an array, it's a certref not a cert.
				if (!is_array($cert)) {
					$cert = lookup_cert($cert);
					$cert = $cert['item'];
				}

				$purpose = cert_get_purpose($cert['crt']);
				if (($cert['caref'] != $server['caref']) ||
				    !in_array($cert['refid'], $ecdsagood) ||
				    ($purpose['server'] == 'Yes')) {
					continue;
				}
				$ras_userent = array();
				$ras_userent['uindex'] = $uindex;
				$ras_userent['cindex'] = $cindex;
				$ras_userent['name'] = $user['name'];
				$ras_userent['certname'] = $cert['descr'];
				$ras_userent['cert'] = $cert;
				$ras_user[] = $ras_userent;
			}
		}
	} elseif (($server['mode'] == "server_tls") ||
			(($server['mode'] == "server_tls_user") && ($server['authmode'] != "Local Database"))) {
		foreach ($a_cert as $cindex => $cert) {

			$purpose = cert_get_purpose($cert['crt']);
			if (($cert['caref'] != $server['caref']) ||
			    ($cert['refid'] == $server['certref']) ||
			    !in_array($cert['refid'], $ecdsagood) ||
			    ($purpose['server'] == 'Yes')) {
				continue;
			}
			$ras_cert_entry['cindex'] = $cindex;
			$ras_cert_entry['certname'] = $cert['descr'];
			$ras_cert_entry['certref'] = $cert['refid'];
			$ras_certs[] = $ras_cert_entry;
		}
	}

	$ras_serverent = array();
	$prot = $server['protocol'];
	$port = $server['local_port'];
	if ($server['description']) {
		$name = "{$server['description']} {$prot}:{$port}";
	} else {
		$name = "Server {$prot}:{$port}";
	}
	$ras_serverent['index'] = $vpnid;
	$ras_serverent['name'] = $name;
	$ras_serverent['users'] = $ras_user;
	$ras_serverent['certs'] = $ras_certs;
	$ras_serverent['mode'] = $server['mode'];
	$ras_serverent['crlref'] = $server['crlref'];
	$ras_serverent['authmode'] = $server['authmode'] != "Local Database" ? 'other' : 'local';
	$ras_serverent['cfg'] = $server;
	$ras_serverent['cfgindex'] = $srvidx;
	$ras_server[$vpnid] = $ras_serverent;
}

$id = $_POST['id'];
$act = $_POST['act'];

global $simplefields;
$simplefields = array('server','useaddr','useaddr_hostname','verifyservercn','blockoutsidedns','legacy','bindmode',
	'usepkcs11','pkcs11providers',
	'usetoken','usepass',
	'useproxy','useproxytype','proxyaddr','proxyport', 'silent','useproxypass','proxyuser');
	//'pass','proxypass','advancedoptions'

$package_config = config_get_path('installedpackages/vpn_openvpn_export', []);
array_init_path($package_config, 'defaultsettings');

// Use default settings; may be overriden below by server-specific settings.
$pconfig = &$package_config['defaultsettings'];

if (isset($_POST['save'])) {
	// Check for existing server-specific settings.
	foreach(array_get_path($package_config, 'serverconfig/item', []) as $i => $item) {
		if ($item['server'] == $_POST['server']) {
			$pconfig = &$package_config['serverconfig']["item"][$i];
			break;
		}
	}
	if (!isset($pconfig)) {
		// Add new servcer-specific settings.
		array_set_path($package_config, 'serverconfig/item/', []);
		$pconfig = &$package_config['serverconfig']["item"][array_key_last($package_config['serverconfig']["item"])];
	}

	if ($_POST['pass'] <> DMYPWD) {
		if ($_POST['pass'] <> $_POST['pass_confirm']) {
			$input_errors[] = "Different certificate passwords entered.";
		} else {
			$pconfig['pass'] = $_POST['pass'];
		}
	}
	if ($_POST['proxypass'] <> DMYPWD) {
		if ($_POST['proxypass'] <> $_POST['proxypass_confirm']) {
			$input_errors[] = "Different Proxy passwords entered.";
		} else {
			$pconfig['proxypass'] = $_POST['proxypass'];
		}
	}

	foreach ($simplefields as $value) {
		$pconfig[$value] = $_POST[$value];
	}

	if (isset($_POST['advancedoptions']) && (strlen(strval($_POST['advancedoptions'])) > 0)) {
		$pconfig['advancedoptions'] = base64_encode($_POST['advancedoptions']);
	} else {
		$pconfig['advancedoptions'] = '';
	}

	if (empty($input_errors)) {
		config_set_path('installedpackages/vpn_openvpn_export', $package_config);
		write_config("Save openvpn client export defaults");
	}
}

if (!empty($act)) {

	$srvid = $_POST['srvid'];
	$usrid = $_POST['usrid'];
	$crtid = $_POST['crtid'];
	$srvcfg = get_openvpnserver_by_id($srvid);
	if ($srvid === false) {
		pfSenseHeader("vpn_openvpn_export.php");
		exit;
	} else if (($srvcfg['mode'] != "server_user") &&
		(($usrid === false) || ($crtid === false))) {
		pfSenseHeader("vpn_openvpn_export.php");
		exit;
	}

	if ($srvcfg['mode'] == "server_user") {
		$nokeys = true;
	} else {
		$nokeys = false;
	}

	$useaddr = '';
	if (isset($_POST['useaddr']) && !empty($_POST['useaddr'])) {
		$useaddr = trim($_POST['useaddr']);
	}

	if (!(is_ipaddr($useaddr) || is_hostname($useaddr) ||
		in_array($useaddr, array("serveraddr", "servermagic", "servermagichost", "serverhostname")))) {
		$input_errors[] = "An IP address or hostname must be specified.";
	}

	$advancedoptions = $_POST['advancedoptions'];

	$verifyservercn = $_POST['verifyservercn'];
	$blockoutsidedns = $_POST['blockoutsidedns'];
	$legacy = $_POST['legacy'];
	$silent = $_POST['silent'];
	$bindmode = $_POST['bindmode'];
	$usetoken = $_POST['usetoken'];
	if ($usetoken && (substr($act, 0, 10) == "confinline")) {
		$input_errors[] = "Microsoft Certificate Storage cannot be used with an Inline configuration.";
	}
	if ($usetoken && (($act == "conf_yealink_t28") || ($act == "conf_yealink_t38g") || ($act == "conf_yealink_t38g2") || ($act == "conf_snom"))) {
		$input_errors[] = "Microsoft Certificate Storage cannot be used with a Yealink or SNOM configuration.";
	}
	$usepkcs11 = $_POST['usepkcs11'];
	$pkcs11providers = $_POST['pkcs11providers'];
	if ($usepkcs11 && !$pkcs11providers) {
		$input_errors[] = "You must provide the PKCS#11 providers.";
	}
	$pkcs11id = $_POST['pkcs11id'];
	if ($usepkcs11 && !$pkcs11id) {
		$input_errors[] = "You must provide the PKCS#11 ID.";
	}
	$password = "";
	if ($_POST['password']) {
		if ($_POST['password'] != DMYPWD) {
			$password = $_POST['password'];
		} else {
			$password = $pconfig['pass'];
		}
	}
	if (isset($_POST['p12encryption']) &&
	    array_key_exists($_POST['p12encryption'], $p12_encryption_levels)) {
		$p12encryption = $_POST['p12encryption'];
	} else {
		$p12encryption = 'high';
	}

	$want_cert = false;
	if (($srvcfg['mode'] == "server_tls_user") && ($srvcfg['authmode'] == "Local Database")) {
		if (array_key_exists($usrid, $a_user) &&
		    array_key_exists('cert', $a_user[$usrid]) &&
		    array_key_exists($crtid, $a_user[$usrid]['cert'])) {
			$want_cert = true;
			$cert = lookup_cert($a_user[$usrid]['cert'][$crtid]);
			$cert = $cert['item'];
		} else {
			$input_errors[] = "Invalid user/certificate index value.";
		}
	} elseif ($srvcfg['mode'] != "server_user") {
		$want_cert = true;
		$cert = config_get_path("cert/{$crtid}");
	}

	if ($want_cert) {
		if (empty($cert)) {
			$input_errors[] = "Unable to locate the requested certificate.";
		} elseif (($srvcfg['mode'] != "server_user") &&
			  !$usepkcs11 &&
			  !$usetoken &&
			  empty($cert['prv'])) {
			$input_errors[] = "A private key cannot be empty if PKCS#11 or Microsoft Certificate Storage is not used.";
		}
	}

	$proxy = "";
	if (!empty($_POST['proxy_addr']) || !empty($_POST['proxy_port'])) {
		$proxy = array();
		if (empty($_POST['proxy_addr'])) {
			$input_errors[] = "An address for the proxy must be specified.";
		} else {
			$proxy['ip'] = $_POST['proxy_addr'];
		}
		if (empty($_POST['proxy_port'])) {
			$input_errors[] = "A port for the proxy must be specified.";
		} else {
			$proxy['port'] = $_POST['proxy_port'];
		}
		$proxy['proxy_type'] = $_POST['proxy_type'];
		$proxy['proxy_authtype'] = $_POST['proxy_authtype'];
		if ($_POST['proxy_authtype'] != "none") {
			if (empty($_POST['proxy_user'])) {
				$input_errors[] = "A username for the proxy configuration must be specified.";
			} else {
				$proxy['user'] = $_POST['proxy_user'];
			}
			if (!empty($_POST['proxy_user']) && empty($_POST['proxy_password'])) {
				$input_errors[] = "A password for the proxy user must be specified.";
			} else {
				if ($_POST['proxy_password'] != DMYPWD) {
					$proxy['password'] = $_POST['proxy_password'];
				} else {
					$proxy['password'] = $pconfig['proxypass'];
				}
			}
		}
	}

	$exp_name = openvpn_client_export_prefix($srvid, $usrid, $crtid);

	if (substr($act, 0, 4) == "conf") {
		switch ($act) {
			case "confzip":
				$exp_name = urlencode($exp_name . "-config.zip");
				$expformat = "zip";
				break;
			case "conf_yealink_t28":
				$exp_name = urlencode("client.tar");
				$expformat = "yealink_t28";
				break;
			case "conf_yealink_t38g":
				$exp_name = urlencode("client.tar");
				$expformat = "yealink_t38g";
				break;
			case "conf_yealink_t38g2":
				$exp_name = urlencode("client.tar");
				$expformat = "yealink_t38g2";
				break;
			case "conf_snom":
				$exp_name = urlencode("vpnclient.tar");
				$expformat = "snom";
				break;
			case "confinline":
				$exp_name = urlencode($exp_name . "-config.ovpn");
				$expformat = "inline";
				break;
			case "confinlinedroid":
				$exp_name = urlencode($exp_name . "-android-config.ovpn");
				$expformat = "inlinedroid";
				break;
			case "confinlineconnect":
				$exp_name = urlencode($exp_name . "-connect-config.ovpn");
				$expformat = "inlineconnect";
				break;
			case "confinlinevisc":
				$exp_name = urlencode($exp_name . "-viscosity-config.ovpn");
				$expformat = "inlinevisc";
				break;
			default:
				$exp_name = urlencode($exp_name . "-config.ovpn");
				$expformat = "baseconf";
		}
		$exp_path = openvpn_client_export_config($srvid, $usrid, $crtid, $useaddr, $verifyservercn, $blockoutsidedns, $legacy, $bindmode, $usetoken, $nokeys, $proxy, $expformat, $password, $p12encryption, false, false, $advancedoptions, $usepkcs11, $pkcs11providers, $pkcs11id);
	}

	if ($act == "visc") {
		$exp_name = urlencode($exp_name . "-Viscosity.visc.zip");
		$exp_path = viscosity_openvpn_client_config_exporter($srvid, $usrid, $crtid, $useaddr, $verifyservercn, $blockoutsidedns, $legacy, $bindmode, $usetoken, $password, $p12encryption, $proxy, $advancedoptions, $usepkcs11, $pkcs11providers, $pkcs11id);
	}

	if (substr($act, 0, 4) == "inst") {
		$openvpn_version = substr($act, 5);
		$exp_name = "openvpn-{$exp_name}-install-";
		switch ($openvpn_version) {
			case "Win7":
				$legacy = true;
				$exp_name .= "{$legacy_openvpn_version}-I{$legacy_openvpn_version_rev}-Win7.exe";
				break;
			case "Win10":
				$legacy = true;
				$exp_name .= "{$legacy_openvpn_version}-I{$legacy_openvpn_version_rev}-Win10.exe";
				break;
			case "x86-current":
				$exp_name .= "{$current_openvpn_version}-I{$current_openvpn_version_rev}-x86.exe";
				break;
			case "x64-current":
			default:
				$exp_name .= "{$current_openvpn_version}-I{$current_openvpn_version_rev}-amd64.exe";
				break;
		}

		$exp_name = urlencode($exp_name);
		$exp_path = openvpn_client_export_installer($srvid, $usrid, $crtid, $useaddr, $verifyservercn, $blockoutsidedns, $legacy, $bindmode, $usetoken, $password, $p12encryption, $proxy, $advancedoptions, substr($act, 5), $usepkcs11, $pkcs11providers, $pkcs11id, $silent);
	}

	/* FreeSense >= 2.5.0 with OpenVPN >= 2.5.0 has ciphers not compatible with
	 * legacy clients, check for those and warn */
	if ($legacy) {
		global $legacy_incompatible_ciphers;
		$settings = get_openvpnserver_by_id($srvid);
		if (in_array($settings['data_ciphers_fallback'], $legacy_incompatible_ciphers)) {
			$input_errors[] = gettext("The Fallback Data Encryption Algorithm for the selected server is not compatible with Legacy clients.");
		}
	}

	if (!$exp_path) {
		$input_errors[] = "Failed to export config files!";
	}

	if (empty($input_errors)) {
		if (($act == "conf") || (substr($act, 0, 10) == "confinline")) {
			$exp_size = strlen($exp_path);
		} else {
			$exp_size = filesize($exp_path);
		}
		header('Pragma: ');
		header('Cache-Control: ');
		header("Content-Type: application/octet-stream");
		header("Content-Disposition: attachment; filename={$exp_name}");
		header("Content-Length: $exp_size");
		if (($act == "conf") || (substr($act, 0, 10) == "confinline")) {
			echo $exp_path;
		} else {
			readfile($exp_path);
			@unlink($exp_path);
		}
		exit;
	}
}

$pgtitle = array(gettext("VPN"), gettext("OpenVPN"), gettext("Client Export"));
$pglinks = array("", "vpn_openvpn_server.php", "@self");
$shortcut_section = "openvpn";

if (isAllowedPage('status_openvpn.php')) {
	fs_page_action(gettext('OpenVPN status'), 'status_openvpn.php', 'fa-chart-line', 'secondary');
}

include("head.inc");

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

/* Core OpenVPN tabs plus the package tabs; add_package_tabs() never marks a tab active, so mark this one */
$tab_array = array();
$ovx_groups = function_exists('fs_tab_groups') ? fs_tab_groups() : array();
$ovx_tabs = $ovx_groups['vpn-openvpn']['tabs'] ?? array(
	array(gettext("Servers"), "vpn_openvpn_server.php"),
	array(gettext("Clients"), "vpn_openvpn_client.php"),
	array(gettext("Client Specific Overrides"), "vpn_openvpn_csc.php"),
	array(gettext("Wizards"), "wizard.php?xml=openvpn_wizard.xml"),
);
foreach ($ovx_tabs as $tab) {
	$tab_array[] = array(htmlspecialchars($tab[0]), false, htmlspecialchars($tab[1]));
}
add_package_tabs("OpenVPN", $tab_array);
foreach ($tab_array as &$tab) {
	$tab[1] = (basename((string)$tab[2]) === 'vpn_openvpn_export.php');
}
unset($tab);
display_top_tabs($tab_array);

$ovx_modes = function_exists('openvpn_build_mode_list') ? openvpn_build_mode_list() : array();
?>
<style>
.fs-ovx-summaries > [hidden] { display: none !important; }
.fs-ovx-summaries .fs-summary { margin-bottom: 0; }
.fs-ovx-summaries { margin: .25rem 0 .5rem; }
.fs-ovx-who strong { color: var(--fs-text-strong); }
.fs-ovx-sub { display: block; color: var(--fs-text-muted); font-size: var(--fs-fs-xs); }
.fs-ovx-exports { display: grid; grid-template-columns: max-content 1fr; gap: .4rem .9rem; align-items: center; }
.fs-ovx-label { color: var(--fs-text-muted); font-size: var(--fs-fs-xs); font-weight: 600; white-space: nowrap; }
.fs-ovx-label .fs-mono { font-weight: 500; }
.fs-ovx-buttons { display: flex; flex-wrap: wrap; gap: .3rem; }
.fs-ovx-buttons .btn { white-space: nowrap; margin: 0; }
.fs-ovx-notes { margin: 0; padding: .75rem 1rem .75rem 2rem;border-top: 1px solid var(--fs-border); color: var(--fs-text-muted); font-size: var(--fs-fs-sm); }
.fs-ovx-notes li + li { margin-top: .25rem; }
.fs-ovx-clients { margin: 0; padding: 0; list-style: none; display: grid; grid-template-columns: repeat(auto-fill, minmax(16rem, 1fr)); gap: .75rem 1.5rem; }
.fs-ovx-clients li { font-size: var(--fs-fs-sm); }
.fs-ovx-clients .fs-ovx-sub { margin-top: .1rem; }
#users td { vertical-align: top; }
@media (max-width: 767.98px) {
	#users thead { display: none; }
	#users, #users tbody { display: block; width: 100%; }
	#users tbody tr { display: block; padding: .5rem 0; border-bottom: 1px solid var(--fs-border); }
	#users tbody td { display: block; height: auto; border: 0; padding: .25rem .75rem; }
	#users tbody tr.fs-empty td { text-align: center; }
	.fs-ovx-exports { grid-template-columns: 1fr; gap: .2rem; }
	.fs-ovx-buttons { margin-bottom: .35rem; }
}
</style>
<?php
if (empty($ras_server)) {
	print_callout(gettext('There is no enabled remote access OpenVPN server. Client export needs a server in a remote access mode (SSL/TLS and/or user authentication).') .
	    (isAllowedPage('vpn_openvpn_server.php') ? ' <a href="vpn_openvpn_server.php?act=new">' . gettext('Add a server') . '</a>' : ''), 'info');
}

/* One summary card per server; the script shows the card of the selected server. */
?>
<div class="fs-ovx-summaries" id="ovx-summaries">
<?php
foreach ($ras_server as $server):
	$cfg = $server['cfg'];
	$protocol = $cfg['protocol'] ?? '';
	$devmode = strtoupper(empty($cfg['dev_mode']) ? 'tun' : $cfg['dev_mode']);
	$networks = implode(', ', array_filter(array($cfg['tunnel_network'] ?? '', $cfg['tunnel_networkv6'] ?? '')));
	$iface = function_exists('convert_openvpn_interface_to_friendly_descr') ? convert_openvpn_interface_to_friendly_descr($cfg['interface'] ?? '') : ($cfg['interface'] ?? '');
	$actions = array();
	if (isAllowedPage('vpn_openvpn_server.php')) {
		$actions[] = array(gettext('Edit server'), 'vpn_openvpn_server.php?act=edit&id=' . $server['cfgindex'], 'fa-pencil');
	}
?>
	<div data-ovx-summary="<?=htmlspecialchars($server['index'])?>"<?=((string)$server['index'] === (string)$pconfig['server']) ? '' : ' hidden'?>>
<?php
	fs_summary_card(array(
		'icon' => 'fa-file-export',
		'title' => $cfg['description'] ?? '',
		'placeholder' => sprintf(gettext('Server %s'), $protocol . ':' . ($cfg['local_port'] ?? '')),
		'subtitle' => gettext('Remote access server'),
		'badges' => array(fs_badge('enabled')),
		'meta' => 'ovpns' . $server['index'],
		'label' => gettext('Server summary'),
		'facts' => array(
			array(gettext('Mode'), $ovx_modes[$cfg['mode']] ?? $cfg['mode']),
			array(gettext('Protocol / port'), '', 'chips' => array_values(array_filter(array($protocol, $cfg['local_port'] ?? '', $devmode)))),
			array(gettext('Interface'), $iface),
			array(gettext('Tunnel network'), $networks, 'mono' => true),
			array(gettext('Authentication'), ($cfg['mode'] == 'server_tls') ? gettext('Certificate only') : ($cfg['authmode'] ?? ''), 'empty' => gettext('Not set')),
		),
		'actions' => $actions,
	));
?>
	</div>
<?php endforeach; ?>
</div>
<?php

$form = new Form("Save as default");

$section = new Form_Section('Server');

$serverlist = array();
foreach ($ras_server as $server) {
	$serverlist[$server['index']] = $server['name'];
}

$section->addInput(new Form_Select(
	'server',
	'Remote access server',
	$pconfig['server'],
	$serverlist
))->setHelp('The options below are saved as defaults for the selected server with "Save as default".');

$form->add($section);

$section = new Form_Section('Connection');

$useaddrlist = array(
	"serveraddr" => "Interface IP Address",
	"servermagic" => "Automagic Multi-WAN IPs (port forward targets)",
	"servermagichost" => "Automagic Multi-WAN DDNS Hostnames (port forward targets)",
	"serverhostname" => "Installation hostname"
);

foreach (config_get_path('dyndnses/dyndns', []) as $ddns) {
	if (in_array($ddns['type'], $dyndns_split_domain_types)) {
		$useaddrlist[$ddns["host"] . '.' . $ddns["domainname"]] = $ddns["host"] . '.' . $ddns["domainname"];
	} else {
		$useaddrlist[$ddns["host"]] = $ddns["host"];
	}
}

foreach (config_get_path('dnsupdates/dnsupdate', []) as $ddns) {
	$useaddrlist[$ddns["host"]] = $ddns["host"];
}

$useaddrlist["other"] = "Other";

$section->addInput(new Form_Select(
	'useaddr',
	'Host name resolution',
	$pconfig['useaddr'],
	$useaddrlist
))->setHelp('The address clients connect to.');

$section->addInput(new Form_Input(
	'useaddr_hostname',
	'Host name',
	'text',
	$pconfig['useaddr_hostname']
))->setHelp('Host name or IP address the client uses to reach this server.');

$section->addInput(new Form_Select(
	'verifyservercn',
	'Verify server CN',
	$pconfig['verifyservercn'],
	array(
		"auto" => "Automatic - Use verify-x509-name where possible",
		"none" => "Do not verify the server CN")
))->setHelp('Optionally verify the Common Name (CN) of the server certificate when the client connects.');

$section->addInput(new Form_Select(
	'bindmode',
	'Bind mode',
	$pconfig['bindmode'],
	array(
		"nobind" => "Do not bind to the local port",
		"lport0" => "Use a random local source port",
		"bind" => "Bind to the default OpenVPN port")
))->setHelp('A client bound to the default OpenVPN port (1194) cannot run twice at the same time.');

$section->addInput(new Form_Checkbox(
	'blockoutsidedns',
	'Block outside DNS',
	'Block access to DNS servers except across OpenVPN while connected',
	$pconfig['blockoutsidedns']
))->setHelp('Forces Windows 10 and later clients (OpenVPN 2.3.9+) to use only the VPN DNS servers. Other clients ignore it.');

$section->addInput(new Form_Checkbox(
	'legacy',
	'Legacy client',
	'Do not include OpenVPN 2.5 and later settings in the client configuration',
	$pconfig['legacy']
))->setHelp('For older clients (OpenVPN 2.4.x), so the export leaves out settings they do not understand.');

$form->add($section);

$section = new Form_Section('Certificate and Windows installer');

$section->addInput(new Form_Checkbox(
	'usepass',
	'Password protect certificate',
	'Use a password to protect the PKCS#12 file contents or the key in a Viscosity bundle',
	$pconfig['usepass']
));

$section->addPassword(new Form_Input(
	'pass',
	'Certificate password',
	'password',
	$pconfig['pass']
))->setHelp('Password used to protect the certificate file contents.');

$section->addInput(new Form_Select(
	'p12encryption',
	'PKCS#12 encryption',
	'high',
	$p12_encryption_levels
))->setHelp('Encryption level of an exported PKCS#12 archive. Support varies by operating system and program.');

$section->addInput(new Form_Checkbox(
	'usetoken',
	'Microsoft certificate storage',
	'Use Microsoft Certificate Storage instead of local files',
	$pconfig['usetoken']
));

$section->addInput(new Form_Checkbox(
	'usepkcs11',
	'PKCS#11 certificate storage',
	'Use a PKCS#11 device (cryptographic token, HSM, smart card) instead of local files',
	$pconfig['usepkcs11']
));

$section->addInput(new Form_Input(
	'pkcs11providers',
	'PKCS#11 providers',
	'text',
	$pconfig['pkcs11providers']
))->setHelp('Local path(s) of the PKCS#11 provider (DLL, module) on the client, separated by spaces.');

$section->addInput(new Form_Input(
	'pkcs11id',
	'PKCS#11 ID',
	'text'
))->setHelp('ID of the object on the PKCS#11 device.');

$section->addInput(new Form_Checkbox(
	'silent',
	'Silent installer',
	'Create a Windows installer for unattended deployment',
	$pconfig['silent']
))->setHelp('The installer must run with elevated permissions. It is not signed, so deployment tools may need extra configuration.');

$form->add($section);

$section = new Form_Section('Proxy', 'ovx-proxy', COLLAPSIBLE | ((!empty($input_errors) || !empty($pconfig['useproxy'])) ? SEC_OPEN : SEC_CLOSED));

$section->addInput(new Form_Checkbox(
	'useproxy',
	'Use a proxy',
	'Use a proxy to communicate with the OpenVPN server',
	$pconfig['useproxy']
));

$section->addInput(new Form_Select(
	'useproxytype',
	'Proxy type',
	$pconfig['useproxytype'],
	array(
		"http" => "HTTP",
		"socks" => "SOCKS")
));

$section->addInput(new Form_Input(
	'proxyaddr',
	'Proxy address',
	'text',
	$pconfig['proxyaddr']
))->setHelp('Host name or IP address of the proxy server.');

$section->addInput(new Form_Input(
	'proxyport',
	'Proxy port',
	'text',
	$pconfig['proxyport']
))->setHelp('Port the proxy server listens on.');

$section->addInput(new Form_Select(
	'useproxypass',
	'Proxy authentication',
	$pconfig['useproxypass'],
	array(
		"none" => "None",
		"basic" => "Basic",
		"ntlm" => "NTLM")
));

$section->addInput(new Form_Input(
	'proxyuser',
	'Proxy username',
	'text',
	$pconfig['proxyuser']
));

$section->addPassword(new Form_Input(
	'proxypass',
	'Proxy password',
	'password',
	$pconfig['proxypass']
));

$form->add($section);

$section = new Form_Section('Advanced', 'ovx-advanced', COLLAPSIBLE | ((!empty($input_errors) || !empty($pconfig['advancedoptions'])) ? SEC_OPEN : SEC_CLOSED));

$section->addInput(new Form_Textarea(
	'advancedoptions',
	'Additional configuration options',
	(!empty($pconfig['advancedoptions']) ? base64_decode($pconfig['advancedoptions']) : '')
))->setHelp('Extra options added to the exported client configuration, one per line or separated by semicolons, e.g. %1$sremote-random;%2$s', '<code>', '</code>');

$form->add($section);

print($form);
?>

<div class="panel panel-default fs-table" id="ovx-clients">
<?php fs_table_toolbar(array(
	'title' => gettext('Clients'),
	'search' => gettext('Search clients…'),
	'noun' => gettext('clients'),
	'noun_one' => gettext('client'),
)); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" id="users">
			<thead>
				<tr>
					<th data-fs-search><?=gettext("User")?></th>
					<th data-fs-search><?=gettext("Certificate")?></th>
					<th><?=gettext("Export")?></th>
				</tr>
			</thead>
			<tbody>
<?php if (empty($ras_server)) {
	fs_empty_row(3, gettext('No remote access server to export clients for.'));
} ?>
			</tbody>
		</table>
	</div>
	<ul class="fs-ovx-notes">
		<li><?=gettext('Only OpenVPN-compatible certificates are shown. A missing client usually means its certificate is signed by a different CA than the server, does not exist on this firewall, or (with local database authentication) is not assigned to a user.')?></li>
		<li><?=gettext('Clients using OpenSSL 3.0 may reject older or weaker ciphers and hashes such as SHA1, also when those signed the CA or certificate.')?></li>
		<li><?=gettext('OpenVPN 2.4.8 and later require Windows 7 or later.')?></li>
	</ul>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('OpenVPN client software')?></h2></div>
	<div class="panel-body">
		<ul class="fs-ovx-clients">
			<li><a href="https://openvpn.net/community-downloads/" rel="noopener" target="_blank"><?=gettext("OpenVPN Community Client")?></a>
				<span class="fs-ovx-sub"><?=gettext("Windows binaries (packaged in the installers above) and source for other platforms")?></span></li>
			<li><a href="https://play.google.com/store/apps/details?id=de.blinkt.openvpn" rel="noopener" target="_blank"><?=gettext("OpenVPN for Android")?></a>
				<span class="fs-ovx-sub"><?=gettext("Recommended client for Android")?></span></li>
			<li><?=gettext("OpenVPN Connect")?>: <a href="https://play.google.com/store/apps/details?id=net.openvpn.openvpn" rel="noopener" target="_blank"><?=gettext("Android")?></a> &middot; <a href="https://apps.apple.com/app/openvpn-connect/id590379981" rel="noopener" target="_blank"><?=gettext("iOS")?></a>
				<span class="fs-ovx-sub"><?=gettext("Recommended client for iOS")?></span></li>
			<li><a href="https://www.sparklabs.com/viscosity/" rel="noopener" target="_blank"><?=gettext("Viscosity")?></a>
				<span class="fs-ovx-sub"><?=gettext("Commercial client for macOS and Windows")?></span></li>
			<li><a href="https://tunnelblick.net" rel="noopener" target="_blank"><?=gettext("Tunnelblick")?></a>
				<span class="fs-ovx-sub"><?=gettext("Free client for macOS")?></span></li>
			<li><a href="https://community.openvpn.net/openvpn/wiki/OpenvpnSoftwareRepos" rel="noopener" target="_blank"><?=gettext("OpenVPN on Linux distributions")?></a>
				<span class="fs-ovx-sub"><?=gettext("Install from the OpenVPN repositories for a current version")?></span></li>
		</ul>
	</div>
</div>

<?php
/* Per server: [vpnid, users [[uindex, cindex, name, certname]], mode, certs [[cindex, certname]], authmode] */
$js_servers = array();
foreach ($ras_server as $sindex => $server) {
	$users = array();
	foreach ($server['users'] as $user) {
		if (!$server['crlref'] || !is_cert_revoked($user['cert'], $server['crlref'])) {
			$users[] = array((string)$user['uindex'], (string)$user['cindex'], (string)$user['name'], (string)$user['certname']);
		}
	}
	$certs = array();
	foreach ($server['certs'] as $cert) {
		if (!$server['crlref'] || !is_cert_revoked(config_get_path("cert/{$cert['cindex']}"), $server['crlref'])) {
			$certs[] = array((string)$cert['cindex'], (string)$cert['certname']);
		}
	}
	$js_servers[$sindex] = array((string)$server['index'], $users, (string)$server['mode'], $certs, (string)$server['authmode']);
}

// Decode applicable settings for JS code.
$serverdefaults = array_get_path($package_config, 'serverconfig/item', []);
foreach ($serverdefaults as &$item) {
	if (empty($item['advancedoptions'])) {
		continue;
	}
	$advancedoptions_decoded = base64_decode($item['advancedoptions'], true);
	if (!is_string($advancedoptions_decoded)) {
		continue;
	}
	$item['advancedoptions'] = $advancedoptions_decoded;
}
unset($item);

$js_flags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
$cur_ver = $current_openvpn_version . '-Ix' . $current_openvpn_version_rev;
$leg_ver = $legacy_openvpn_version . '-Ix' . $legacy_openvpn_version_rev;
/* [label, version note, [[act, label], ...], certificate-only (server_tls)] — same order as before */
$export_groups = array(
	array(gettext('Inline configuration'), '', array(array('confinline', gettext('Most clients')), array('confinlinedroid', gettext('Android')), array('confinlineconnect', gettext('OpenVPN Connect (iOS/Android)'))), false),
	array(gettext('Bundled configuration'), '', array(array('confzip', gettext('Archive')), array('conf', gettext('Config file only'))), false),
	array(gettext('Windows installer'), $cur_ver, array(array('inst-x64-current', gettext('64-bit')), array('inst-x86-current', gettext('32-bit'))), false),
	array(gettext('Legacy Windows installer'), $leg_ver, array(array('inst-Win10', gettext('10/2016/2019')), array('inst-Win7', gettext('7/8/8.1/2012r2'))), false),
	array(gettext('Viscosity (macOS and Windows)'), '', array(array('visc', gettext('Viscosity bundle')), array('confinlinevisc', gettext('Viscosity inline config'))), false),
	array(gettext('Yealink SIP handsets'), '', array(array('conf_yealink_t28', 'T28'), array('conf_yealink_t38g', 'T38G (1)'), array('conf_yealink_t38g2', 'T38G (2) / V83')), true),
	array(gettext('Snom SIP handsets'), '', array(array('conf_snom', 'SNOM')), true),
);
$js_text = array(
	'tlsonly' => gettext('Certificate (SSL/TLS, no auth)'),
	'extauth' => gettext('Certificate with external auth'),
	'authonly' => gettext('Authentication only (no certificate)'),
	'none' => gettext('None'),
	'empty' => gettext('No clients can be exported for this server.'),
	'download' => gettext('Download %1$s for %2$s'),
	'needhost' => gettext('Please specify an IP address or hostname.'),
);
?>
<script type="text/javascript">
//<![CDATA[
var viscosityAvailable = false;

var servers = <?=json_encode((object)$js_servers, $js_flags)?>;

var serverdefaults = <?=json_encode($serverdefaults, $js_flags)?>;

var ovxExportGroups = <?=json_encode($export_groups, $js_flags)?>;
var ovxText = <?=json_encode($js_text, $js_flags)?>;

function make_form_variable(varname, varvalue) {
	var exportinput = document.createElement("input");
	exportinput.type = "hidden";
	exportinput.name = varname;
	exportinput.value = varvalue;
	return exportinput;
}

function download_begin(act, i, j) {
	var index = document.getElementById("server").value;
	var users = servers[index][1];
	var certs = servers[index][3];
	var useaddr;

	var advancedoptions;

	if (document.getElementById("useaddr").value == "other") {
		if (document.getElementById("useaddr_hostname").value == "") {
			alert(ovxText.needhost);
			return;
		}
		useaddr = document.getElementById("useaddr_hostname").value;
	} else {
		useaddr = document.getElementById("useaddr").value;
	}

	advancedoptions = document.getElementById("advancedoptions").value;

	var verifyservercn;
	verifyservercn = document.getElementById("verifyservercn").value;

	var blockoutsidedns = 0;
	if (document.getElementById("blockoutsidedns").checked) {
		blockoutsidedns = 1;
	}
	var legacy = 0;
	if (document.getElementById("legacy").checked) {
		legacy = 1;
	}

	var bindmode = 0;
	bindmode = document.getElementById("bindmode").value;

	var usetoken = 0;
	if (document.getElementById("usetoken").checked) {
		usetoken = 1;
	}
	var usepkcs11 = 0;
	if (document.getElementById("usepkcs11").checked) {
		usepkcs11 = 1;
	}
	var silent = 0;
	if (document.getElementById("silent").checked) {
		silent = 1;
	}
	var pkcs11providers = document.getElementById("pkcs11providers").value;
	var pkcs11id = document.getElementById("pkcs11id").value;
	var usepass = 0;
	if (document.getElementById("usepass").checked) {
		usepass = 1;
	}

	var pass = document.getElementById("pass").value;
	var pass_confirm = document.getElementById("pass_confirm").value;
	if (usepass && (act.substring(0, 4) == "inst")) {
		if (!pass || !pass_confirm) {
			alert("The password or confirm field is empty");
			return;
		}
		if (pass != pass_confirm) {
			alert("The password and confirm fields must match");
			return;
		}
	}

	var p12encryption = document.getElementById("p12encryption").value;

	var useproxy = 0;
	var useproxypass = 0;
	if (document.getElementById("useproxy").checked) {
		useproxy = 1;
	}

	var proxyaddr = document.getElementById("proxyaddr").value;
	var proxyport = document.getElementById("proxyport").value;
	if (useproxy) {
		if (!proxyaddr || !proxyport) {
			alert("The proxy ip and port cannot be empty");
			return;
		}

		if (document.getElementById("useproxypass").value != 'none') {
			useproxypass = 1;
		}

		var proxytype = document.getElementById("useproxytype").value;

		var proxyauth = document.getElementById("useproxypass").value;
		var proxyuser = document.getElementById("proxyuser").value;
		var proxypass = document.getElementById("proxypass").value;
		var proxypass_confirm = document.getElementById("proxypass_confirm").value;
		if (useproxypass) {
			if (!proxyuser) {
				alert("Please fill the proxy username and password.");
				return;
			}
			if (!proxypass || !proxypass_confirm) {
				alert("The proxy password or confirm field is empty");
				return;
			}
			if (proxypass != proxypass_confirm) {
				alert("The proxy password and confirm fields must match");
				return;
			}
		}
	}

	var exportform = document.createElement("form");
	exportform.method = "POST";
	exportform.action = "/vpn_openvpn_export.php";
	exportform.target = "_self";
	exportform.style.display = "none";

	exportform.appendChild(make_form_variable("act", act));
	exportform.appendChild(make_form_variable("srvid", servers[index][0]));
	if (users[i]) {
		exportform.appendChild(make_form_variable("usrid", users[i][0]));
		exportform.appendChild(make_form_variable("crtid", users[i][1]));
	}
	if (certs[j]) {
		exportform.appendChild(make_form_variable("usrid", ""));
		exportform.appendChild(make_form_variable("crtid", certs[j][0]));
	}
	exportform.appendChild(make_form_variable("useaddr", useaddr));
	exportform.appendChild(make_form_variable("verifyservercn", verifyservercn));
	exportform.appendChild(make_form_variable("blockoutsidedns", blockoutsidedns));
	exportform.appendChild(make_form_variable("legacy", legacy));
	exportform.appendChild(make_form_variable("silent", silent));
	exportform.appendChild(make_form_variable("bindmode", bindmode));
	exportform.appendChild(make_form_variable("usetoken", usetoken));
	exportform.appendChild(make_form_variable("usepkcs11", usepkcs11));
	exportform.appendChild(make_form_variable("pkcs11providers", pkcs11providers));
	exportform.appendChild(make_form_variable("pkcs11id", pkcs11id));
	if (usepass) {
		exportform.appendChild(make_form_variable("password", pass));
	}
	exportform.appendChild(make_form_variable("p12encryption", p12encryption));
	if (useproxy) {
		exportform.appendChild(make_form_variable("proxy_type", proxytype));
		exportform.appendChild(make_form_variable("proxy_addr", proxyaddr));
		exportform.appendChild(make_form_variable("proxy_port", proxyport));
		exportform.appendChild(make_form_variable("proxy_authtype", proxyauth));
		if (useproxypass) {
			exportform.appendChild(make_form_variable("proxy_user", proxyuser));
			exportform.appendChild(make_form_variable("proxy_password", proxypass));
		}
	}
	exportform.appendChild(make_form_variable("advancedoptions", advancedoptions));

	exportform.appendChild(make_form_variable(csrfMagicName, csrfMagicToken));
	document.body.appendChild(exportform);
	exportform.submit();
}

/* small DOM helpers: all text goes through textContent */
function ovx_el(tag, cls, text) {
	var el = document.createElement(tag);
	if (cls) {
		el.className = cls;
	}
	if (text !== undefined && text !== null) {
		el.textContent = text;
	}
	return el;
}

function ovx_fmt(s, args) {
	return s.replace(/%(\d)\$s/g, function (m, n) {
		return args[n - 1];
	});
}

/* one table row: who, certificate, grouped download buttons (i = user index, j = certificate index) */
function ovx_add_row(tbody, who, whoSub, cert, i, j, tlsOnly) {
	var tr = tbody.insertRow(tbody.rows.length);
	var c0 = tr.insertCell(0);
	var c1 = tr.insertCell(1);
	var c2 = tr.insertCell(2);

	c0.className = 'fs-ovx-who';
	c0.appendChild(ovx_el('strong', '', who));
	if (whoSub) {
		c0.appendChild(ovx_el('span', 'fs-ovx-sub', whoSub));
	}

	if (cert === null) {
		c1.appendChild(ovx_el('span', 'fs-muted', ovxText.none));
	} else {
		var chips = ovx_el('div', 'fs-chips');
		chips.appendChild(ovx_el('span', 'fs-chip fs-chip--mono', cert));
		c1.appendChild(chips);
	}

	var grid = ovx_el('div', 'fs-ovx-exports');
	ovxExportGroups.forEach(function (g) {
		if (g[3] && !tlsOnly) {
			return;
		}
		var label = ovx_el('div', 'fs-ovx-label', g[0]);
		if (g[1]) {
			label.appendChild(document.createTextNode(' '));
			label.appendChild(ovx_el('span', 'fs-mono', g[1]));
		}
		var btns = ovx_el('div', 'fs-ovx-buttons');
		btns.setAttribute('role', 'group');
		btns.setAttribute('aria-label', g[0]);
		g[2].forEach(function (b) {
			var btn = ovx_el('button', 'btn btn-sm btn-outline-secondary');
			btn.type = 'button';
			btn.setAttribute('data-ovx-act', b[0]);
			btn.setAttribute('data-ovx-i', i);
			btn.setAttribute('data-ovx-j', j);
			btn.title = ovx_fmt(ovxText.download, [g[0] + ': ' + b[1], who]);
			var icon = ovx_el('i', 'fa-solid fa-download icon-embed-btn');
			icon.setAttribute('aria-hidden', 'true');
			btn.appendChild(icon);
			btn.appendChild(document.createTextNode(b[1]));
			btns.appendChild(btn);
		});
		grid.appendChild(label);
		grid.appendChild(btns);
	});
	c2.appendChild(grid);
}

function server_changed() {

	var table = document.getElementById("users");
	table = table.tBodies[0];

	while (table.rows.length > 0 ) {
		table.deleteRow(0);
	}

	function setFieldValue(field, value) {
		checkboxes = $("input[type=checkbox]#"+field);
		checkboxes.prop('checked', value == 'yes').trigger("change");

		inputboxes = $("input[type!=checkbox]#"+field);
		inputboxes.val(value);

		selectboxes = $("select#"+field);
		selectboxes.val(value);

		textareaboxes = $("textarea#"+field);
		textareaboxes.val(value);
	}

	var index = document.getElementById("server").value;

	document.querySelectorAll('[data-ovx-summary]').forEach(function (card) {
		card.hidden = (card.getAttribute('data-ovx-summary') !== index);
	});

	if (!servers[index]) {
		return;
	}

	for(i = 0; i < serverdefaults.length; i++) {
		if (serverdefaults[i]['server'] !== index) {
			continue;
		}
		fields = serverdefaults[i];
		fieldnames = Object.getOwnPropertyNames(fields);
		for (fieldnr = 0; fieldnr < fieldnames.length; fieldnr++) {
			fieldname = fieldnames[fieldnr];
			setFieldValue(fieldname, fields[fieldname]);
		}
		setFieldValue('pass_confirm', fields['pass']);
		setFieldValue('proxypass_confirm', fields['proxypass']);
		break;
	}

	var users = servers[index][1];
	var certs = servers[index][3];
	var mode = servers[index][2];
	for (var u = 0; u < users.length; u++) {
		ovx_add_row(table, users[u][2], '', users[u][3], u, -1, false);
	}
	for (var c = 0; c < certs.length; c++) {
		ovx_add_row(table, (mode == "server_tls") ? ovxText.tlsonly : ovxText.extauth, '', certs[c][1], -1, c, mode == "server_tls");
	}
	if (mode == 'server_user') {
		ovx_add_row(table, ovxText.authonly, '', null, -1, -1, false);
	}

	var root = document.getElementById('ovx-clients');
	if (table.rows.length === 0) {
		var tr = table.insertRow(0);
		tr.className = 'fs-empty';
		var td = tr.insertCell(0);
		td.colSpan = 3;
		td.appendChild(ovx_el('span', 'fs-empty-message', ovxText.empty));
		var count = root.querySelector('[data-fs-count]');
		if (count) {
			count.textContent = '';
		}
	}
	if (root._fsTable && root._fsTable.apply) {
		root._fsTable.apply(false);
	}
}

function useaddr_changed() {
	if ($('#useaddr').val() == "other") {
		hideInput('useaddr_hostname', false);
	} else {
		hideInput('useaddr_hostname', true);
	}
}

function usepkcs11_changed() {
	if ($('#usepkcs11').prop('checked')) {
		hideInput('pkcs11id', false);
		hideInput('pkcs11providers', false);
	} else {
		hideInput('pkcs11id', true);
		hideInput('pkcs11providers', true);
	}
}

function usepass_changed() {
	if ($('#usepass').prop('checked')) {
		hideInput('pass', false);
		hideInput('pass_confirm', false);
	} else {
		hideInput('pass', true);
		hideInput('pass_confirm', true);
	}
}

function useproxy_changed() {
	if ($('#useproxy').prop('checked')) {
		hideInput('useproxytype', false);
		hideInput('proxyaddr', false);
		hideInput('proxyport', false);
		hideInput('useproxypass', false);
	} else {
		hideInput('useproxytype', true);
		hideInput('proxyaddr', true);
		hideInput('proxyport', true);
		hideInput('useproxypass', true);
		hideInput('proxyuser', true);
		hideInput('proxypass', true);
		hideInput('proxypass_confirm', true);
	}
	if ($('#useproxy').prop('checked') && ($('#useproxypass').val() != 'none')) {
		hideInput('proxyuser', false);
		hideInput('proxypass', false);
		hideInput('proxypass_confirm', false);
	} else {
		hideInput('proxyuser', true);
		hideInput('proxypass', true);
		hideInput('proxypass_confirm', true);
	}
}

events.push(function(){
	// Show the summary of the selected server right under the server selector
	var summaries = document.getElementById('ovx-summaries');
	var serverGroup = document.getElementById('server') ? document.getElementById('server').closest('.form-group') : null;
	if (summaries && serverGroup) {
		serverGroup.parentNode.insertBefore(summaries, serverGroup.nextSibling);
	}

	// ---------- OnChange handlers ---------------------------------------------------------

	$('#server').on('change', function() {
		server_changed();
	});
	$('#useaddr').on('change', function() {
		useaddr_changed();
	});
	$('#usepkcs11').on('change', function() {
		usepkcs11_changed();
	});
	$('#usepass').on('change', function() {
		usepass_changed();
	});
	$('#useproxy').on('change', function() {
		useproxy_changed();
	});
	$('#useproxypass').on('change', function() {
		useproxy_changed();
	});

	// Export buttons
	$('#users').on('click', '[data-ovx-act]', function() {
		download_begin(this.getAttribute('data-ovx-act'),
		    parseInt(this.getAttribute('data-ovx-i'), 10),
		    parseInt(this.getAttribute('data-ovx-j'), 10));
	});

	// ---------- On initial page load ------------------------------------------------------------

	server_changed();
	useaddr_changed();
	usepkcs11_changed();
	usepass_changed();
	useproxy_changed();
});
//]]>
</script>

<?php
include("foot.inc");
