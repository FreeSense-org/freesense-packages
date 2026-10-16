<?php
/*
 * fleet_template_settings.inc
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2026 The FreeSense Project
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

/*
 * Settings templates: one set of settings pushed to many firewalls (time
 * and NTP, DNS servers, SNMP, remote logging). Unlike alias templates a
 * firewall has one of each, so a firewall gets at most one template of a
 * kind. Each kind is described once here: its form, the route it reads
 * and writes, the values a firewall has (from that route or from its
 * newest config backup, so previews and drift need no network) and the
 * difference. Everything here is pure.
 *
 * A secret (the SNMP community) cannot be read back: it is sent when the
 * template changes and never shown as drift.
 */

define('FLEET_TSET_KINDS', array(
	'time' => array('Time and NTP', 'fa-clock', 'Time zone and NTP servers', '/api/v1/system/general', 0),
	'dns' => array('DNS servers', 'fa-globe', 'The DNS servers the firewall itself uses', '/api/v1/system/general', 0),
	'snmp' => array('SNMP', 'fa-chart-line', 'SNMP on or off, location, contact and community', '/api/v1/services/snmp', 0),
	'syslog' => array('Remote logging', 'fa-file-lines', 'Send logs to central syslog servers', '/api/v1/system/syslog-remote', 10),
));
define('FLEET_TSET_SYSLOG_CONTENTS', array('system' => 'System', 'filter' => 'Firewall', 'resolver' => 'DNS resolver', 'dhcp' => 'DHCP', 'ppp' => 'PPP',
    'auth' => 'Authentication', 'portalauth' => 'Captive portal', 'vpn' => 'VPN', 'dpinger' => 'Gateway monitor', 'hostapd' => 'Wireless', 'routing' => 'Routing',
    'ntpd' => 'NTP'));

/* pure: a host name or address (an NTP or DNS server). */
function fleet_tset_host_ok(string $h): bool {
	return (filter_var($h, FILTER_VALIDATE_IP) !== false) ||
	    ((strlen($h) <= 253) && (bool)preg_match('/^(?=.*[a-z])([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/Di', $h));
}

/* pure: a list typed one per line, by comma or by space. */
function fleet_tset_list(string $text): array {
	return array_values(array_unique(preg_split('/[\s,]+/', trim($text), -1, PREG_SPLIT_NO_EMPTY)));
}

/*
 * pure: a kind's settings from the template form ("set_<field>"), checked.
 * Throws InvalidArgumentException. The SNMP community may be left empty
 * on a change to keep the stored one ($old).
 */
function fleet_tset_from(string $kind, array $in, array $old = array()): array {
	$v = function ($k) use ($in) {
		return trim((string)($in['set_' . $k] ?? ''));
	};
	switch ($kind) {
	case 'time':
		$tz = $v('timezone');
		if (!in_array($tz, timezone_identifiers_list(), true) && ($tz !== 'Etc/UTC')) {
			throw new InvalidArgumentException('Choose a time zone like Europe/Copenhagen.');
		}
		$servers = fleet_tset_list($v('timeservers'));
		if (empty($servers) || (count($servers) > 5)) {
			throw new InvalidArgumentException('Give 1 to 5 NTP servers.');
		}
		foreach ($servers as $s) {
			if (!fleet_tset_host_ok($s)) {
				throw new InvalidArgumentException("\"{$s}\" is not a host name or address.");
			}
		}
		return array('timezone' => $tz, 'timeservers' => $servers);
	case 'dns':
		$servers = fleet_tset_list($v('dnsservers'));
		if (empty($servers) || (count($servers) > 8)) {
			throw new InvalidArgumentException('Give 1 to 8 DNS servers.');
		}
		foreach ($servers as $s) {
			if (filter_var($s, FILTER_VALIDATE_IP) === false) {
				throw new InvalidArgumentException("\"{$s}\" is not an IP address (DNS servers are addresses).");
			}
		}
		return array('dnsservers' => $servers, 'dnsallowoverride' => !empty($in['set_dnsallowoverride']));
	case 'snmp':
		$enable = !empty($in['set_enable']);
		$out = array('enable' => $enable, 'syslocation' => mb_substr($v('syslocation'), 0, 100), 'syscontact' => mb_substr($v('syscontact'), 0, 100));
		foreach (array('syslocation', 'syscontact') as $k) {
			if (preg_match('/[\x00-\x1f\x7f"\\\\]/u', $out[$k])) {
				throw new InvalidArgumentException('Location and contact are plain text (no quotes or backslashes).');
			}
		}
		$community = $v('rocommunity');
		if ($community === '') {
			$community = (string)($old['rocommunity'] ?? '');
		}
		if ($enable && !preg_match('/^[A-Za-z0-9._~!@#%^&*+=-]{6,64}$/D', $community)) {
			throw new InvalidArgumentException('Give a read community of 6 to 64 characters (not "public": anyone guesses it).');
		}
		if (strtolower($community) === 'public') {
			throw new InvalidArgumentException('Not "public": anyone guesses it. Choose another read community.');
		}
		$out['rocommunity'] = $community;
		return $out;
	case 'syslog':
		$enable = !empty($in['set_enable']);
		$servers = fleet_tset_list($v('servers'));
		if (count($servers) > 3) {
			throw new InvalidArgumentException('Give at most 3 syslog servers.');
		}
		if ($enable && empty($servers)) {
			throw new InvalidArgumentException('Remote logging needs at least one server.');
		}
		foreach ($servers as $s) {
			$host = preg_replace('/^\[(.*)\](:\d+)?$/', '$1', preg_replace('/^([^:\[\]]+):\d{1,5}$/', '$1', $s));
			if (!fleet_tset_host_ok($host) || ctype_digit(explode(':', $s)[0])) {
				throw new InvalidArgumentException("\"{$s}\" is not a server (a host name or address, optionally :port).");
			}
		}
		$contents = (string)($in['set_contents'] ?? 'all');
		$list = array_values(array_intersect((array)($in['set_contents_list'] ?? array()), array_keys(FLEET_TSET_SYSLOG_CONTENTS)));
		if (($contents !== 'all') && empty($list)) {
			throw new InvalidArgumentException('Choose which logs to send, or all of them.');
		}
		return array('enable' => $enable, 'servers' => $servers, 'ipproto' => (($in['set_ipproto'] ?? '') === 'ipv6') ? 'ipv6' : 'ipv4',
		    'contents' => ($contents === 'all') ? 'all' : $list);
	}
	throw new InvalidArgumentException('Unknown template kind.');
}

/* pure: what a kind's route answered, as the comparable settings. */
function fleet_tset_current(string $kind, array $data): array {
	switch ($kind) {
	case 'time':
		return array('timezone' => (string)($data['timezone'] ?? ''), 'timeservers' => fleet_tset_list((string)($data['timeservers'] ?? '')));
	case 'dns':
		return array('dnsservers' => array_values(array_filter(array_map(function ($s) { return (string)($s['address'] ?? ''); }, (array)($data['dnsservers'] ?? array())), 'strlen')),
		    'dnsallowoverride' => !empty($data['dnsallowoverride']));
	case 'snmp':
		return array('enable' => !empty($data['enable']), 'syslocation' => (string)($data['syslocation'] ?? ''), 'syscontact' => (string)($data['syscontact'] ?? ''));
	case 'syslog':
		return array('enable' => !empty($data['enable']), 'servers' => array_values((array)($data['servers'] ?? array())), 'ipproto' => (string)($data['ipproto'] ?? 'ipv4'),
		    'contents' => (($data['contents'] ?? 'all') === 'all') ? 'all' : array_values((array)$data['contents']));
	}
	return array();
}

/* pure: the same from a config.xml (a backup); null when it cannot be read. */
function fleet_tset_from_config(string $kind, string $xml): ?array {
	$prev = libxml_use_internal_errors(true);
	$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET);
	libxml_use_internal_errors($prev);
	if ($doc === false) {
		return null;
	}
	$sys = $doc->system;
	switch ($kind) {
	case 'time':
		return array('timezone' => (string)$sys->timezone, 'timeservers' => fleet_tset_list((string)$sys->timeservers));
	case 'dns':
		$list = array();
		foreach ($sys->dnsserver as $d) {
			if ((string)$d !== '') {
				$list[] = (string)$d;
			}
		}
		return array('dnsservers' => $list, 'dnsallowoverride' => isset($sys->dnsallowoverride));
	case 'snmp':
		$s = $doc->snmpd;
		return array('enable' => isset($s->enable), 'syslocation' => (string)$s->syslocation, 'syscontact' => (string)$s->syscontact);
	case 'syslog':
		$s = $doc->syslog;
		$servers = array();
		foreach (array('remoteserver', 'remoteserver2', 'remoteserver3') as $k) {
			if ((string)$s->$k !== '') {
				$servers[] = (string)$s->$k;
			}
		}
		$on = function ($k) use ($s) {
			return isset($s->$k) && ((string)$s->$k !== '0') && (strtolower((string)$s->$k) !== 'false');
		};
		$contents = $on('logall') ? 'all' : array_values(array_filter(array_keys(FLEET_TSET_SYSLOG_CONTENTS), $on));
		return array('enable' => $on('enable'), 'servers' => $on('enable') ? $servers : array(), 'ipproto' => ((string)$s->ipproto === 'ipv6') ? 'ipv6' : 'ipv4', 'contents' => $contents);
	}
	return null;
}

/* pure: how a value reads for people. */
function fleet_tset_text($v): string {
	if (is_bool($v)) {
		return $v ? 'on' : 'off';
	}
	if (is_array($v)) {
		return empty($v) ? '(none)' : implode(', ', $v);
	}
	return ($v === '') ? '(empty)' : (string)$v;
}

/* pure: field labels per kind. */
function fleet_tset_labels(string $kind): array {
	return array(
		'time' => array('timezone' => 'Time zone', 'timeservers' => 'NTP servers'),
		'dns' => array('dnsservers' => 'DNS servers', 'dnsallowoverride' => 'Allow DNS from WAN (DHCP/PPP)'),
		'snmp' => array('enable' => 'SNMP', 'syslocation' => 'Location', 'syscontact' => 'Contact', 'rocommunity' => 'Read community'),
		'syslog' => array('enable' => 'Remote logging', 'servers' => 'Servers', 'ipproto' => 'IP version', 'contents' => 'Logs sent'),
	)[$kind] ?? array();
}

/*
 * pure: what would change on a firewall: list of array(field, label,
 * from, to). Secrets are not compared ($current has none). With remote
 * logging off, its servers and logs do not matter.
 */
function fleet_tset_diff(string $kind, array $want, array $current): array {
	$out = array();
	$labels = fleet_tset_labels($kind);
	foreach ($want as $k => $v) {
		if (!array_key_exists($k, $current)) {
			continue;
		}
		if (($kind === 'syslog') && empty($want['enable']) && ($k !== 'enable')) {
			continue;
		}
		if (($kind === 'snmp') && empty($want['enable']) && ($k !== 'enable')) {
			continue;
		}
		$a = $v;
		$b = $current[$k];
		if (is_array($a) && is_array($b) && ($k !== 'dnsservers') && ($k !== 'timeservers') && ($k !== 'servers')) {
			sort($a);
			sort($b);
		}
		if ($a !== $b) {
			$out[] = array($k, $labels[$k] ?? $k, fleet_tset_text($b), fleet_tset_text($v));
		}
	}
	return $out;
}

/* pure: the PUT body for a kind's route. */
function fleet_tset_body(string $kind, array $want): array {
	switch ($kind) {
	case 'time':
		return array('timezone' => $want['timezone'], 'timeservers' => implode(' ', $want['timeservers']));
	case 'dns':
		return array('dnsservers' => array_map(function ($a) { return array('address' => $a); }, $want['dnsservers']), 'dnsallowoverride' => $want['dnsallowoverride']);
	case 'snmp':
		return $want['enable'] ? $want : array('enable' => false);
	case 'syslog':
		return $want['enable'] ? $want : array('enable' => false, 'servers' => array());
	}
	return array();
}

/* pure: a one-line summary for lists and cards. */
function fleet_tset_summary(string $kind, array $s): string {
	switch ($kind) {
	case 'time':
		return $s['timezone'] . '; NTP ' . implode(', ', $s['timeservers']);
	case 'dns':
		return implode(', ', $s['dnsservers']) . ($s['dnsallowoverride'] ? '; WAN may override' : '');
	case 'snmp':
		return $s['enable'] ? trim('On; ' . $s['syslocation'] . ($s['syscontact'] !== '' ? ', ' . $s['syscontact'] : ''), '; ,') : 'Off';
	case 'syslog':
		return $s['enable'] ? implode(', ', $s['servers']) . '; ' . (($s['contents'] === 'all') ? 'all logs' : count($s['contents']) . ' kinds of log') : 'Off';
	}
	return '';
}
