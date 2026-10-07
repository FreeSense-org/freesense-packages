<?php
/*
 * status_frr.php
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2004-2026 The FreeSense Project
 * Copyright (C) 2010 Nick Buraglio <nick@buraglio.com>
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

require("guiconfig.inc");
$control_script = "/usr/local/bin/frrctl";
$vtysh = "/usr/local/bin/vtysh";
$pkg_homedir = "/var/etc/frr";
global $commands;
$commands = array();

/*
 * Define a command, with a title, to be executed later over AJAX.
 * $open = false renders its card collapsed (rarely needed output).
 */
function defCmdT($idx, $title, $command, $has_filter = false, $header_size = 0, $open = true) {
	global $commands;
	$commands[$idx] = array(
		'title' => $title,
		'command' => $command,
		'has_filter' => $has_filter,
		'header_size' => $header_size,
		'open' => $open);
}

/*
 * Number of header lines at the top of a command's output. Route tables open
 * with a legend whose length depends on the FRR version (5 lines for zebra up
 * to FRR 8, about 9 in FRR 10; BGP grew too), so for those ($header_size > 1)
 * the header runs to the first blank line plus a following title line
 * ("IPv4 unicast VRF default:") or column heading ("Network  Next Hop ...").
 * Without a blank line near the top the defined size is used.
 */
function frr_header_lines(array $lines, $header_size) {
	$header_size = max(0, (int)$header_size);
	if ($header_size > 1) {
		$top = min(count($lines), 25);
		for ($i = 0; $i < $top; $i++) {
			if (trim($lines[$i]) === '') {
				$n = $i + 1;
				while (($n < count($lines)) && (trim($lines[$n]) !== '') &&
				    (preg_match('/:\s*$/', $lines[$n]) || preg_match('/^\s*Network\s+Next Hop/', $lines[$n]))) {
					$n++;
				}
				return $n;
			}
		}
	}
	return min($header_size, count($lines));
}

/*
 * Run a (fixed, page-defined) status command and return its output, escaped.
 * The filter and limit are applied here in PHP, never passed to a shell: the
 * filter is a plain text match (any characters, "/" included) on the lines
 * after the header, the limit counts the lines after the header.
 */
function doCmdT($command, $limit = "all", $filter = "", $header_size = 0) {
	$output = [];
	$fd = popen("{$command} 2>&1", "r");
	if ($fd !== false) {
		while (($line = fgets($fd)) !== false) {
			$output[] = $line;
		}
		pclose($fd);
	}

	$filter = (string)$filter;
	$use_filter = ($filter !== '') && ($filter !== 'undefined');
	$use_limit = is_numeric($limit) && ($limit > 0);
	if ($use_filter || $use_limit) {
		$hdr = frr_header_lines($output, $header_size);
		$body = array_slice($output, $hdr);
		if ($use_filter) {
			$body = array_values(array_filter($body, function ($line) use ($filter) {
				return strpos($line, $filter) !== false;
			}));
		}
		if ($use_limit) {
			$body = array_slice($body, 0, (int)$limit);
		}
		$output = array_merge(array_slice($output, 0, $hdr), $body);
	}

	return htmlspecialchars(implode('', $output), ENT_NOQUOTES);
}

function countCmdT($command) {
	$fd = popen("{$command} 2>&1", "r");
	$c = 0;
	while (fgets($fd) !== FALSE) {
		$c++;
	}
	pclose($fd);

	return $c;
}

/* Run a read-only vtysh "show ... json" command and decode it; [] on any failure. */
function frr_show_json($command) {
	global $vtysh;
	$out = [];
	exec($vtysh . ' -c ' . escapeshellarg($command) . ' 2>/dev/null', $out);
	$data = json_decode(implode("\n", $out), true);
	return is_array($data) ? $data : [];
}

/* Load configuration blocks and check which daemons are enabled. */
$frr_enabled    = ((config_get_path('installedpackages/frr/config/0/enable') == 'on')       || !empty(config_get_path('installedpackages/frrglobalraw/config/0/zebra')));
$bgpd_enabled   = ((config_get_path('installedpackages/frrbgp/config/0/enable') == 'on')    || !empty(config_get_path('installedpackages/frrglobalraw/config/0/bgpd')));
$ospfd_enabled  = ((config_get_path('installedpackages/frrospfd/config/0/enable') == 'on')  || !empty(config_get_path('installedpackages/frrglobalraw/config/0/ospfd')));
$ospf6d_enabled = ((config_get_path('installedpackages/frrospf6d/config/0/enable') == 'on') || !empty(config_get_path('installedpackages/frrglobalraw/config/0/ospf6d')));
$ripd_enabled   = ((config_get_path('installedpackages/frrripd/config/0/enable') == 'on')   || !empty(config_get_path('installedpackages/frrglobalraw/config/0/ripd')));
$bfdd_enabled   = ((config_get_path('installedpackages/frrbfd/config/0/enable') == 'on')    || !empty(config_get_path('installedpackages/frrglobalraw/config/0/bfdd')));

/* Status views: protocol => [tab label, daemon, enabled, settings page] */
$views = array(
	''      => array(gettext("Overview"), '', $frr_enabled, 'pkg_edit.php?xml=frr.xml'),
	'zebra' => array(gettext("Zebra"), 'zebra', $frr_enabled, 'pkg_edit.php?xml=frr.xml'),
	'bgp'   => array(gettext("BGP"), 'bgpd', $frr_enabled && $bgpd_enabled, 'pkg_edit.php?xml=frr/frr_bgp.xml'),
	'ospf'  => array(gettext("OSPF"), 'ospfd', $frr_enabled && $ospfd_enabled, 'pkg_edit.php?xml=frr/frr_ospf.xml'),
	'ospf6' => array(gettext("OSPF6"), 'ospf6d', $frr_enabled && $ospf6d_enabled, 'pkg_edit.php?xml=frr/frr_ospf6.xml'),
	'rip'   => array(gettext("RIP"), 'ripd', $frr_enabled && $ripd_enabled, 'pkg_edit.php?xml=frr/frr_rip.xml'),
	'bfd'   => array(gettext("BFD"), 'bfdd', $frr_enabled && $bfdd_enabled, 'pkg_edit.php?xml=frr/frr_bfd.xml'),
	'config' => array(gettext("Configuration"), '', $frr_enabled, 'pkg_edit.php?xml=frr.xml'),
);

/* The protocol view comes from the request; unknown values show the overview. */
$protocol = (string)($_REQUEST['protocol'] ?? '');
if (!array_key_exists($protocol, $views)) {
	$protocol = '';
}
$overview = ($protocol === '');

/* General commands for the overview or specific protocol pages */
if (($overview || ($protocol == "zebra")) && $frr_enabled) {
	defCmdT("zebra_routes", gettext("Zebra routes"), "{$control_script} zebra route", true, 5);
	defCmdT("zebra_routes6", gettext("Zebra IPv6 routes"), "{$control_script} zebra route6", true, 5);
}

if (($overview || ($protocol == "bgp")) && $frr_enabled && $bgpd_enabled) {
	defCmdT("bgp_routes", gettext("BGP routes"), "{$control_script} bgp route", true, 6);
	defCmdT("bgp_ipv6_routes", gettext("BGP IPv6 routes"), "{$control_script} bgp6 route", true, 6);
	defCmdT("bgp_summary", gettext("BGP summary"), "{$control_script} bgp sum");
	defCmdT("bgp_neighbors", gettext("BGP neighbors"), "{$control_script} bgp neighbor", false, 0, !$overview);
}

if (($overview || ($protocol == "ospf")) && $frr_enabled && $ospfd_enabled) {
	defCmdT("ospf_general", gettext("OSPF general"), "{$control_script} ospf general");
	defCmdT("ospf_neighbors", gettext("OSPF neighbors"), "{$control_script} ospf neighbor");
	defCmdT("ospf_routes", gettext("OSPF routes"), "{$control_script} ospf route", true, 1);
}

if (($overview || ($protocol == "ospf6")) && $frr_enabled && $ospf6d_enabled) {
	defCmdT("ospf6_general", gettext("OSPF6 general"), "{$control_script} ospf6 general");
	defCmdT("ospf6_neighbors", gettext("OSPF6 neighbors"), "{$control_script} ospf6 neighbor");
	defCmdT("ospf6_routes", gettext("OSPF6 routes"), "{$control_script} ospf6 route", true, 1);
}

if (($overview || ($protocol == "rip")) && $frr_enabled && $ripd_enabled) {
	defCmdT("rip_general", gettext("RIP general"), "{$control_script} rip general");
	defCmdT("rip_routes", gettext("RIP routes"), "{$control_script} rip routes");
}

if (($overview || ($protocol == "bfd")) && $frr_enabled && $bfdd_enabled) {
	defCmdT("bfd_peers_brief", gettext("BFD peers brief"), "{$control_script} bfd peer_br");
	defCmdT("bfd_peers", gettext("BFD peers"), "{$control_script} bfd peer");
}

$message = "";
switch ($protocol) {
	case "zebra":
		if ($frr_enabled) {
			defCmdT("zebra_interfaces", gettext("Zebra interfaces"), "{$control_script} zebra int");
			defCmdT("zebra_cpu", gettext("Zebra CPU"), "{$control_script} zebra cpu", false, 0, false);
			defCmdT("zebra_memory", gettext("Zebra memory"), "{$control_script} zebra mem", false, 0, false);
		} else {
			$message = gettext("FRR is not enabled.");
		}
		break;
	case "bgp":
		if ($frr_enabled && $bgpd_enabled) {
			defCmdT("bgp_peers", gettext("BGP peer groups"), "{$control_script} bgp peer");
			defCmdT("bgp_nexthops", gettext("BGP next hops"), "{$control_script} bgp nexthop");
			defCmdT("bgp_memory", gettext("BGP memory"), "{$control_script} bgp mem", false, 0, false);
		} else {
			$message = gettext("BGP is not enabled.");
		}
		break;
	case "ospf":
		if ($frr_enabled && $ospfd_enabled) {
			defCmdT("ospf_db", gettext("OSPF database"), "{$control_script} ospf database");
			defCmdT("ospf_routerdb", gettext("OSPF router database"), "{$control_script} ospf database router");
			defCmdT("ospf_interfaces", gettext("OSPF interfaces"), "{$control_script} ospf interfaces");
			defCmdT("ospf_cpu", gettext("OSPF CPU usage"), "{$control_script} ospf cpu", false, 0, false);
			defCmdT("ospf_memory", gettext("OSPF memory"), "{$control_script} ospf mem", false, 0, false);
		} else {
			$message = gettext("OSPF is not enabled.");
		}
		break;
	case "ospf6":
		if ($frr_enabled && $ospf6d_enabled) {
			defCmdT("ospf6_db", gettext("OSPF6 database"), "{$control_script} ospf6 database");
			defCmdT("ospf6_routerdb", gettext("OSPF6 router database"), "{$control_script} ospf6 database router");
			defCmdT("ospf6_interfaces", gettext("OSPF6 interfaces"), "{$control_script} ospf6 interfaces");
			defCmdT("ospf6_cpu", gettext("OSPF6 CPU usage"), "{$control_script} ospf6 cpu", false, 0, false);
			defCmdT("ospf6_memory", gettext("OSPF6 memory"), "{$control_script} ospf6 mem", false, 0, false);
		} else {
			$message = gettext("OSPF6 is not enabled.");
		}
		break;
	case "rip":
		if (!$frr_enabled || !$ripd_enabled) {
			$message = gettext("RIP is not enabled.");
		}
		break;
	case "bfd":
		if ($frr_enabled && $bfdd_enabled) {
			defCmdT("bfd_peers_counters", gettext("BFD peer counters"), "{$control_script} bfd counters");
		} else {
			$message = gettext("BFD is not enabled.");
		}
		break;
	case "config":
		$config_files = array(
			'frr',
			);
		foreach ($config_files as $cf) {
			if (file_exists("{$pkg_homedir}/{$cf}.conf") &&
				(filesize("{$pkg_homedir}/{$cf}.conf") > 0)) {
				defCmdT("frr_{$cf}_config", "{$cf}.conf", "/bin/cat {$pkg_homedir}/{$cf}.conf");
			}
		}
		if (empty($commands)) {
			$message = gettext("No FRR configuration has been written yet.");
		}
		break;
	default:
		if (!$frr_enabled) {
			$message = gettext("FRR is not enabled.");
		}
		break;
}

if (isset($_REQUEST['isAjax'])) {
	if (isset($_REQUEST['cmd']) && isset($commands[$_REQUEST['cmd']])) {
		echo "{$_REQUEST['cmd']}\n";
		if (isset($_REQUEST['count'])) {
			echo " of " . countCmdT($commands[$_REQUEST['cmd']]['command']) . " items";
		} else {
			echo htmlspecialchars_decode(doCmdT($commands[$_REQUEST['cmd']]['command'], $_REQUEST['limit'], $_REQUEST['filter'], $_REQUEST['header_size']));
		}
	}
	exit;
}

/* Live daemon state and parseable summaries for the tiles */
$daemons = array(
	'zebra'  => array(gettext("Zebra"), $frr_enabled, 'zebra', gettext("Core routing manager")),
	'bgpd'   => array(gettext("BGP"), $frr_enabled && $bgpd_enabled, 'bgp', gettext("Border Gateway Protocol")),
	'ospfd'  => array(gettext("OSPF"), $frr_enabled && $ospfd_enabled, 'ospf', gettext("OSPFv2 for IPv4")),
	'ospf6d' => array(gettext("OSPF6"), $frr_enabled && $ospf6d_enabled, 'ospf6', gettext("OSPFv3 for IPv6")),
	'ripd'   => array(gettext("RIP"), $frr_enabled && $ripd_enabled, 'rip', gettext("Routing Information Protocol")),
	'bfdd'   => array(gettext("BFD"), $frr_enabled && $bfdd_enabled, 'bfd', gettext("Bidirectional Forwarding Detection")),
);
$running = array();
foreach ($daemons as $proc => $d) {
	$running[$proc] = is_process_running($proc);
}

/* Running / Stopped / Disabled badge of one daemon */
$daemon_badge = function ($proc) use ($daemons, $running) {
	if ($running[$proc]) {
		return fs_badge('up', gettext('Running'));
	}
	return $daemons[$proc][1] ? fs_badge('down', gettext('Stopped')) : fs_badge('disabled');
};

$tiles = array();
$daemon_tile = function ($proc) use ($daemons, $running) {
	return array(gettext('Daemon'), $proc, $running[$proc] ? 'up' : 'down', $daemons[$proc][3]);
};
$route_tiles = function () {
	$tiles = array();
	foreach (array(array(gettext('IPv4 routes'), 'show ip route summary json'), array(gettext('IPv6 routes'), 'show ipv6 route summary json')) as $rt) {
		$sum = frr_show_json($rt[1]);
		if (!isset($sum['routesTotal'])) {
			continue;
		}
		$parts = array();
		foreach (($sum['routes'] ?? array()) as $r) {
			if (!empty($r['rib']) && !empty($r['type'])) {
				$parts[] = sprintf('%d %s', $r['rib'], $r['type']);
			}
		}
		$tiles[] = array($rt[0], (int)$sum['routesTotal'], null, implode(', ', $parts) ?: null);
	}
	return $tiles;
};
$bgp_tiles = function ($with_router = false) {
	$sum = frr_show_json('show bgp summary json');
	$peers = array();
	$established = 0;
	$prefixes = 0;
	$router = '';
	foreach ($sum as $afi) {
		if (!is_array($afi) || !isset($afi['peers'])) {
			continue;
		}
		if (empty($router) && !empty($afi['routerId'])) {
			$router = sprintf('AS %s', $afi['as'] ?? '?');
			$router_id = $afi['routerId'];
		}
		foreach ($afi['peers'] as $addr => $peer) {
			$peers[$addr] = $peers[$addr] ?? false;
			if (($peer['state'] ?? '') == 'Established') {
				$peers[$addr] = true;
				$prefixes += (int)($peer['pfxRcd'] ?? 0);
			}
		}
	}
	$established = count(array_filter($peers));
	$tiles = array(array(gettext('BGP neighbors'), sprintf('%d / %d', $established, count($peers)),
	    (count($peers) == 0) ? null : (($established == count($peers)) ? 'online' : 'degraded'), gettext('Established / configured')));
	if ($with_router) {
		$tiles[] = array(gettext('Prefixes received'), $prefixes, null, gettext('From established neighbors'));
		if (!empty($router)) {
			$tiles[] = array(gettext('Local AS'), $router, null, sprintf(gettext('Router ID %s'), $router_id));
		}
	}
	return $tiles;
};
$ospf_tiles = function ($cmd_nbr, $cmd_gen, $label) {
	$tiles = array();
	$nbr = frr_show_json($cmd_nbr);
	$count = 0;
	$full = 0;
	foreach (($nbr['neighbors'] ?? array()) as $list) {
		foreach ((array)$list as $n) {
			if (!is_array($n)) {
				continue;
			}
			$count++;
			$state = (string)($n['nbrState'] ?? ($n['state'] ?? ''));
			if (stripos($state, 'Full') === 0) {
				$full++;
			}
		}
	}
	$tiles[] = array($label, sprintf('%d / %d', $full, $count), ($count == 0) ? null : (($full == $count) ? 'online' : 'degraded'), gettext('Full / all neighbors'));
	$gen = empty($cmd_gen) ? array() : frr_show_json($cmd_gen);
	if (!empty($gen['routerId'])) {
		$tiles[] = array(gettext('Router ID'), $gen['routerId'], null, isset($gen['areas']) ? sprintf(ngettext('%d area', '%d areas', count($gen['areas'])), count($gen['areas'])) : null);
	}
	return $tiles;
};
$bfd_tiles = function () {
	$peers = frr_show_json('show bfd peers json');
	$up = 0;
	foreach ($peers as $p) {
		if (is_array($p) && (($p['status'] ?? '') == 'up')) {
			$up++;
		}
	}
	return array(array(gettext('BFD peers up'), sprintf('%d / %d', $up, count($peers)), (count($peers) == 0) ? null : (($up == count($peers)) ? 'online' : 'degraded')));
};

if (empty($message)) {
	switch ($protocol) {
		case '':
			$enabled = array_keys(array_filter($daemons, function ($d) { return $d[1]; }));
			$up = count(array_filter($enabled, function ($p) use ($running) { return $running[$p]; }));
			$tiles[] = array(gettext('Daemons running'), sprintf('%d / %d', $up, count($enabled)),
			    ($up == count($enabled)) ? 'online' : (($up == 0) ? 'down' : 'degraded'), gettext('Running / enabled'));
			if ($running['zebra']) {
				$tiles = array_merge($tiles, $route_tiles());
			}
			if ($running['bgpd']) {
				$tiles = array_merge($tiles, $bgp_tiles());
			}
			if ($running['ospfd']) {
				$tiles = array_merge($tiles, array_slice($ospf_tiles('show ip ospf neighbor json', '', gettext('OSPF neighbors')), 0, 1));
			}
			if ($running['ospf6d']) {
				$tiles = array_merge($tiles, array_slice($ospf_tiles('show ipv6 ospf6 neighbor json', '', gettext('OSPF6 neighbors')), 0, 1));
			}
			if ($running['bfdd']) {
				$tiles = array_merge($tiles, $bfd_tiles());
			}
			break;
		case 'zebra':
			$tiles[] = $daemon_tile('zebra');
			if ($running['zebra']) {
				$tiles = array_merge($tiles, $route_tiles());
			}
			break;
		case 'bgp':
			$tiles[] = $daemon_tile('bgpd');
			if ($running['bgpd']) {
				$tiles = array_merge($tiles, $bgp_tiles(true));
			}
			break;
		case 'ospf':
			$tiles[] = $daemon_tile('ospfd');
			if ($running['ospfd']) {
				$tiles = array_merge($tiles, $ospf_tiles('show ip ospf neighbor json', 'show ip ospf json', gettext('Neighbors')));
			}
			break;
		case 'ospf6':
			$tiles[] = $daemon_tile('ospf6d');
			if ($running['ospf6d']) {
				$tiles = array_merge($tiles, $ospf_tiles('show ipv6 ospf6 neighbor json', 'show ipv6 ospf6 json', gettext('Neighbors')));
			}
			break;
		case 'rip':
			$tiles[] = $daemon_tile('ripd');
			break;
		case 'bfd':
			$tiles[] = $daemon_tile('bfdd');
			if ($running['bfdd']) {
				$tiles = array_merge($tiles, $bfd_tiles());
			}
			break;
	}
}

$pgtitle = array(gettext("Status"), gettext("FRR"));
$pglinks = array("", "status_frr.php");
if (!$overview) {
	$pgtitle[] = $views[$protocol][0];
	$pglinks[] = "@self";
}

$settings_url = $views[$protocol][3];
if (isAllowedPage($settings_url)) {
	fs_page_action($overview || in_array($protocol, array('zebra', 'config')) ? gettext('FRR settings') :
	    sprintf(gettext('%s settings'), $views[$protocol][0]), '/' . $settings_url, 'fa-gear', 'secondary');
}

include("head.inc");

$tab_array = array();
foreach ($views as $key => $view) {
	$tab_array[] = array($view[0], ($key === $protocol), '/status_frr.php' . (($key === '') ? '' : '?protocol=' . $key));
}
display_top_tabs($tab_array);
?>
<style>
.fs-frr-head { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; }
.fs-frr-head .panel-title { margin: 0; flex: 1 1 auto; min-width: 0; }
.fs-frr-toggle { display: inline-flex; align-items: center; gap: .5rem; padding: 0; border: 0; background: none; color: inherit; font: inherit; text-align: left; }
.fs-frr-toggle .fa-chevron-right { transition: transform var(--fs-t-fast) var(--fs-ease); color: var(--fs-text-muted); font-size: .8em; }
.fs-frr-toggle[aria-expanded="true"] .fa-chevron-right { transform: rotate(90deg); }
.fs-frr-tools { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem .75rem; padding: .6rem 1rem; border-bottom: 1px solid var(--fs-border); font-size: var(--fs-fs-sm); }
.fs-frr-tools label { margin: 0; color: var(--fs-text-muted); }
.fs-frr-tools .form-select { width: auto; }
.fs-frr-filter { display: flex; gap: .5rem; margin-left: auto; flex: 1 1 16rem; max-width: 26rem; }
.fs-frr-filter .form-control { flex: 1 1 auto; min-width: 0; }
.fs-frr-filter .btn { flex: none; display: inline-flex; align-items: center; gap: .35rem; white-space: nowrap; }
.fs-frr-count { color: var(--fs-text-muted); white-space: nowrap; }
.fs-frr-cmd .fs-console { white-space: pre; overflow-x: auto; margin: 0; border: 0; border-radius: 0 0 var(--fs-r-md) var(--fs-r-md); }
.fs-frr-cmd .fs-console.is-loading { color: var(--fs-text-muted); }
.fs-frr-jump { margin-bottom: 1rem; }
.fs-frr-jump a { text-decoration: none; }
.fs-frr-sub { display: block; font-size: var(--fs-fs-xs); }
@media (max-width: 575.98px) { .fs-frr-filter { margin-left: 0; max-width: none; } }
</style>
<?php
if (!empty($message)):
?>
<div class="panel panel-default">
	<div class="fs-tool-empty">
		<i class="fa-solid fa-route" aria-hidden="true"></i>
		<span><?=htmlspecialchars($message)?><?php if (isAllowedPage($settings_url) && ($protocol != 'config')): ?> <a href="/<?=htmlspecialchars($settings_url)?>"><?=gettext('Open settings')?></a><?php endif; ?></span>
	</div>
</div>
<?php
endif;

if (!empty($tiles)):
?>
<div class="fs-tiles">
<?php
	foreach ($tiles as $t) {
		fs_tile($t[0], $t[1], $t[2], $t[3] ?? null);
	}
?>
</div>
<?php
endif;

if ($overview && empty($message)):
?>
<div class="panel panel-default fs-table">
<?php fs_table_toolbar([
	'title' => gettext('Routing daemons'),
	'search' => false,
	'noun' => gettext('daemons'),
	'noun_one' => gettext('daemon'),
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover">
			<thead>
				<tr>
					<th class="fs-col-status"><?=gettext('Status')?></th>
					<th><?=gettext('Daemon')?></th>
					<th><?=gettext('Protocol')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php	foreach ($daemons as $proc => $d):
		$actions = array();
		if ($d[1] || $running[$proc]) {
			$actions[] = ['custom', '/status_frr.php?protocol=' . $d[2], $d[0], ['icon' => 'fa-chart-line', 'label' => sprintf(gettext('Show %s status'), $d[0])]];
		}
		if (isAllowedPage($views[$d[2]][3])) {
			$actions[] = ['custom', '/' . $views[$d[2]][3], $d[0], ['icon' => 'fa-gear', 'label' => sprintf(gettext('%s settings'), $d[0])]];
		}
?>
				<tr<?=($d[1] || $running[$proc]) ? '' : ' class="fs-row-disabled"'?>>
					<td><?=$daemon_badge($proc)?></td>
					<td><span class="fs-mono"><?=htmlspecialchars($proc)?></span></td>
					<td><?=htmlspecialchars($d[0])?><span class="fs-frr-sub fs-muted"><?=htmlspecialchars($d[3])?></span></td>
					<td class="fs-col-actions"><?=fs_row_actions($actions)?></td>
				</tr>
<?php	endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php
endif;

if (count($commands) > 3):
?>
<nav class="fs-chips fs-frr-jump" aria-label="<?=gettext('Sections on this page')?>">
<?php	foreach ($commands as $idx => $command): ?>
	<a class="fs-chip" href="#sec-<?=htmlspecialchars($idx)?>"><?=htmlspecialchars($command['title'])?></a>
<?php	endforeach; ?>
</nav>
<?php
endif;

foreach ($commands as $idx => $command):
	$id = htmlspecialchars($idx);
	$open = $command['open'];
?>
<div class="panel panel-default fs-frr-cmd" id="sec-<?=$id?>">
	<div class="panel-heading fs-frr-head">
		<h2 class="panel-title">
			<button type="button" class="fs-frr-toggle" data-bs-toggle="collapse" data-bs-target="#body-<?=$id?>" aria-expanded="<?=$open ? 'true' : 'false'?>" aria-controls="body-<?=$id?>">
				<i class="fa-solid fa-chevron-right" aria-hidden="true"></i><?=htmlspecialchars($command['title'])?>
			</button>
		</h2>
		<button type="button" class="btn btn-sm btn-outline-secondary" data-fs-copy="#<?=$id?>" aria-label="<?=htmlspecialchars(sprintf(gettext('Copy %s'), $command['title']))?>"><i class="fa-regular fa-copy icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy')?></button>
	</div>
	<div class="collapse<?=$open ? ' show' : ''?>" id="body-<?=$id?>">
<?php	if ($command['has_filter']):
		$limit_options = array("10", "50", "100", "200", "500", "1000", "all");
		$limit_default = "100";
?>
		<div class="fs-frr-tools">
			<label for="<?=$id?>_limit"><?=gettext('Show')?></label>
			<select class="form-select form-select-sm" name="<?=$id?>_limit" id="<?=$id?>_limit" data-frr-limit="<?=$id?>" data-header-size="<?=(int)$command['header_size']?>">
<?php		foreach ($limit_options as $item): ?>
				<option value="<?=$item?>"<?=($item == $limit_default) ? ' selected' : ''?>><?=($item == 'all') ? gettext('all') : $item?></option>
<?php		endforeach; ?>
			</select>
			<span class="fs-frr-count" id="<?=$id?>_count"><?=gettext('lines')?></span>
			<div class="fs-frr-filter">
				<input type="search" class="form-control form-control-sm fs-mono" name="<?=$id?>_filter" id="<?=$id?>_filter" data-frr-filter="<?=$id?>"
				    value="<?=htmlspecialchars($_REQUEST["{$idx}_filter"] ?? '')?>" placeholder="<?=gettext('Filter expression')?>" aria-label="<?=htmlspecialchars(sprintf(gettext('Filter %s'), $command['title']))?>">
				<button type="button" class="btn btn-sm btn-outline-secondary" data-frr-apply="<?=$id?>"><i class="fa-solid fa-filter icon-embed-btn" aria-hidden="true"></i><?=gettext('Filter')?></button>
			</div>
		</div>
<?php	endif; ?>
		<pre class="fs-console is-loading" id="<?=$id?>" data-frr-cmd="<?=$id?>" data-header-size="<?=(int)$command['header_size']?>" data-has-filter="<?=$command['has_filter'] ? '1' : '0'?>"><?=gettext('Gathering data, please wait…')?></pre>
	</div>
</div>
<?php
endforeach;
?>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	var protocol = <?=json_encode($protocol)?>;
	var noOutput = <?=json_encode(gettext('No output.'))?>;
	var ofLines = <?=json_encode(gettext('of %d lines'))?>;

	function post(params, done) {
		$.ajax('status_frr.php', {type: 'post', data: params, success: done});
	}

	/* "cmd\n of N items" -> "of N lines" next to the limit select */
	function updateCount(cmd, headerSize) {
		post('isAjax=true&protocol=' + encodeURIComponent(protocol) + '&count=true&cmd=' + cmd + '&header_size=' + headerSize, function (text) {
			var lines = String(text).split('\n');
			var el = document.getElementById(lines[0] + '_count');
			var n = /(\d+)/.exec(lines[1] || '');
			if (el && n) {
				el.textContent = ofLines.replace('%d', n[1]);
			}
		});
	}

	/* first response line is the command id, the rest is plain text output */
	function updateOutput(cmd, headerSize) {
		var limitField = document.getElementById(cmd + '_limit');
		var limit = limitField ? limitField.value : undefined;
		var filter = limitField ? document.getElementById(cmd + '_filter').value : undefined;
		post('isAjax=true&protocol=' + encodeURIComponent(protocol) + '&cmd=' + cmd + '&limit=' + limit +
		    '&filter=' + ((filter === undefined) ? filter : encodeURIComponent(filter)) + '&header_size=' + headerSize, function (text) {
			var lines = String(text).split('\n');
			var pre = document.getElementById(lines.shift());
			if (!pre) {
				return;
			}
			var out = lines.join('\n');
			pre.classList.remove('is-loading');
			pre.textContent = out.trim() ? out : noOutput;
		});
	}

	document.querySelectorAll('pre[data-frr-cmd]').forEach(function (pre) {
		var cmd = pre.getAttribute('data-frr-cmd');
		var hs = pre.getAttribute('data-header-size');
		if (pre.getAttribute('data-has-filter') === '1') {
			updateCount(cmd, hs);
		}
		updateOutput(cmd, hs);
	});

	$(document).on('change', 'select[data-frr-limit]', function () {
		updateOutput(this.getAttribute('data-frr-limit'), this.getAttribute('data-header-size'));
	});
	$(document).on('click', 'button[data-frr-apply]', function () {
		var cmd = this.getAttribute('data-frr-apply');
		updateOutput(cmd, document.getElementById(cmd).getAttribute('data-header-size'));
	});
	$(document).on('keydown', 'input[data-frr-filter]', function (e) {
		if (e.key === 'Enter') {
			e.preventDefault();
			var cmd = this.getAttribute('data-frr-filter');
			updateOutput(cmd, document.getElementById(cmd).getAttribute('data-header-size'));
		}
	});
});
//]]>
</script>

<?php include("foot.inc");
