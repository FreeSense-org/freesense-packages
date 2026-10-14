<?php
/*
 * threatshield_pf.inc
 * FreeSense Threat Shield - pf rule builders (pure; system facts come in $ctx)
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 *
 * FreeSense asks packages for rules three times (filter.inc,
 * discover_pkg_rules): 'nat' (translation section), 'pfearly' (first filter
 * category, before every user rule) and 'filter' (after all user rules).
 * Threat Shield answers 'nat' with the DNS redirect and 'pfearly' with tables,
 * blocks and the passes of ports a policy explicitly owns.
 *
 * $ctx:
 *   ifmap    [friendly => real interface]
 *   gw4/gw6  [friendly => gateway address] (reply-to for owned passes)
 *   replyto  bool, false when reply-to is disabled system-wide
 *   healthy  bool, the DNS listener answered (DNS redirect gate)
 *   dnsbl_up bool, the DNSBL daemon runs
 *   db       state directory
 *   ensure   callable(string $file, string $table) creating a missing table
 *            file and loading it into pf, or null
 *   aliases  list of alias names usable as $name
 */

const THREATSHIELD_T_ALLOW = 'threatshield_ip_allow';
const THREATSHIELD_T_DOH = 'threatshield_doh';
const THREATSHIELD_T_EXCL = 'threatshield_dns_excl';
const THREATSHIELD_T_FLOOD = 'threatshield_flood';
const THREATSHIELD_T_BAD = 'threatshield_dnsbl_bad';
const THREATSHIELD_T_KNOWN = 'threatshield_dnsbl_known';
const THREATSHIELD_T_KNOWNF = 'threatshield_dnsbl_known_f';
const THREATSHIELD_T_FAIL = 'threatshield_dnsbl_fail';

function threatshield_pf_list($v): array {
	if (is_array($v) && array_key_exists('item', $v) && count($v) === 1) $v = $v['item'];
	return is_array($v) ? array_values($v) : [];
}

function threatshield_pf_real(array $ctx, string $friendly): ?string {
	$real = (string)($ctx['ifmap'][$friendly] ?? '');
	return ($real !== '' && threatshield_valid_ifname($real)) ? $real : null;
}

function threatshield_pf_table(array $ctx, string $name, string $file): string {
	if (isset($ctx['ensure']) && is_callable($ctx['ensure'])) ($ctx['ensure'])($file, $name);
	return "table <{$name}> persist file \"{$file}\"\n";
}

/* Sources never redirected nor blocked by anti-bypass rules. */
function threatshield_pf_dns_exclusions(array $cfg): array {
	$out = [];
	foreach (threatshield_text_list((string)($cfg['dns_redirect_exclude'] ?? '')) as $item) {
		$n = threatshield_cidr_normalize($item);
		if ($n !== null) $out[] = $n;
	}
	return $out;
}

function threatshield_pf_redirect_target(array $cfg): int {
	return (($cfg['dns_coordination_mode'] ?? 'primary') === 'proxy') ? 5354 : (int)($cfg['listen_port'] ?? 53);
}

/* ------------------------------------------------------------------- nat */

function threatshield_pf_nat_rules(array $cfg, array $ctx): string {
	if (($cfg['enable'] ?? 'off') !== 'on' || ($cfg['catch_rogue_dns'] ?? 'off') !== 'on') return '';
	$ifs = threatshield_pf_list($cfg['dns_intercept_interfaces'] ?? []);
	if (empty($ifs)) return '';
	if (empty($ctx['healthy'])) {
		/* Redirecting to a listener that doesn't answer would take DNS down
		 * for every client; the health check reloads the filter once it does. */
		return "# Threat Shield: DNS redirection skipped, the DNS listener is not answering\n";
	}
	$target = threatshield_pf_redirect_target($cfg);
	$excl = threatshield_pf_dns_exclusions($cfg);
	$excl4 = array_values(array_filter($excl, fn($c) => strpos($c, ':') === false));
	$rules = "# Threat Shield DNS redirection\n";
	foreach ($ifs as $friendly) {
		$real = threatshield_pf_real($ctx, (string)$friendly);
		if ($real === null) continue;
		/* queries to the firewall itself keep their normal path (local names
		 * in proxy mode, DHCP host names) */
		$rules .= "no rdr on {$real} inet proto { tcp udp } from any to ({$real}) port 53\n";
		if (!empty($excl4)) {
			$rules .= "no rdr on {$real} inet proto { tcp udp } from { " . implode(' ', $excl4) . " } to any port 53\n";
		}
		$rules .= "rdr pass on {$real} inet proto { tcp udp } from any to any port 53 -> 127.0.0.1 port {$target}\n";
	}
	return $rules;
}

/* --------------------------------------------------------------- pfearly */

function threatshield_pf_early_rules(array $cfg, array $ctx): string {
	if (($cfg['enable'] ?? 'off') !== 'on') return '';
	$db = rtrim((string)($ctx['db'] ?? '/var/db/threatshield'), '/');
	$tables = '';
	$rules = '';
	$declared = [];
	$declare = function (string $name, string $file) use (&$tables, &$declared, $ctx) {
		if (isset($declared[$name])) return;
		$declared[$name] = true;
		$tables .= threatshield_pf_table($ctx, $name, $file);
	};

	/* A. anti-bypass on the protected (LAN-side) interfaces, inbound only, so
	 * Threat Shield's own encrypted upstream queries keep working */
	$lan_ifs = threatshield_pf_list($cfg['dns_intercept_interfaces'] ?? []);
	$excl = threatshield_pf_dns_exclusions($cfg);
	$from = 'from any';
	if (!empty($excl)) {
		$tables .= "table <" . THREATSHIELD_T_EXCL . "> persist { " . implode(' ', $excl) . " }\n";
		$from = 'from ! <' . THREATSHIELD_T_EXCL . '>';
	}
	foreach ($lan_ifs as $friendly) {
		$real = threatshield_pf_real($ctx, (string)$friendly);
		if ($real === null) continue;
		if (($cfg['block_dot'] ?? 'off') === 'on') {
			$rules .= "block in log quick on {$real} proto { tcp udp } {$from} to ! (self) port 853 label \"ThreatShield anti-bypass DoT/DoQ\"\n";
		}
		if (($cfg['block_doh_ips'] ?? 'off') === 'on') {
			$declare(THREATSHIELD_T_DOH, "{$db}/ip/doh.txt");
			$rules .= "block in log quick on {$real} proto { tcp udp } {$from} to <" . THREATSHIELD_T_DOH . "> port { 443 853 } label \"ThreatShield anti-bypass DoH\"\n";
		}
		if (($cfg['catch_rogue_dns'] ?? 'off') === 'on' && ($cfg['block_dns6_bypass'] ?? 'off') === 'on') {
			$rules .= "block in log quick on {$real} inet6 proto { tcp udp } {$from} to ! (self) port 53 label \"ThreatShield anti-bypass DNS IPv6\"\n";
		}
	}

	/* B. IP threat lists */
	if (($cfg['ipbl_enable'] ?? 'off') === 'on') {
		$wan_ifs = threatshield_pf_list($cfg['ipbl_wan_interfaces'] ?? []);
		$ipbl_lan = threatshield_pf_list($cfg['ipbl_lan_interfaces'] ?? []);
		foreach (threatshield_pf_list($cfg['ip_feeds'] ?? []) as $feed) {
			if (!is_array($feed) || ($feed['enabled'] ?? 'off') !== 'on' || ($feed['kind'] ?? 'threat') !== 'threat') continue;
			$id = threatshield_pf_ident((string)($feed['id'] ?? ''));
			if ($id === '') continue;
			$table = 'ts_ipf_' . $id;
			$declare($table, "{$db}/ip/{$id}.txt");
			$log = (($feed['log'] ?? 'on') === 'on') ? ' log' : '';
			$dir = (string)($feed['direction'] ?? 'in');
			if ($dir === 'in' || $dir === 'both') {
				foreach ($wan_ifs as $friendly) {
					$real = threatshield_pf_real($ctx, (string)$friendly);
					if ($real !== null) $rules .= "block in{$log} quick on {$real} from <{$table}> to any label \"ThreatShield IP list {$id} inbound\"\n";
				}
			}
			if ($dir === 'out' || $dir === 'both') {
				foreach ($ipbl_lan as $friendly) {
					$real = threatshield_pf_real($ctx, (string)$friendly);
					if ($real !== null) $rules .= "block in{$log} quick on {$real} from any to <{$table}> label \"ThreatShield IP list {$id} outbound\"\n";
				}
			}
		}
	}

	/* C. GeoIP country policies */
	if (($cfg['geoip_enable'] ?? 'off') === 'on') {
		$family = (($cfg['geoip_ipv6'] ?? 'off') === 'on') ? '' : ' inet';
		$seen = [];
		foreach (threatshield_pf_list($cfg['geoip_policies'] ?? []) as $policy) {
			if (!is_array($policy) || ($policy['enable'] ?? 'on') !== 'on' || empty(threatshield_pf_list($policy['countries'] ?? []))) continue;
			$id = threatshield_geoip_policy_id($policy);
			if (isset($seen[$id])) continue;    // two policies would share one table
			$seen[$id] = true;
			$table = 'freesense_geoip_' . $id;
			$declare($table, "{$db}/geoip/{$id}.cidrs");
			$proto = in_array(($policy['protocol'] ?? 'any'), ['tcp', 'udp'], true) ? ' proto ' . $policy['protocol'] : '';
			$ports = ($proto !== '') ? threatshield_pf_ports((string)($policy['ports'] ?? 'any')) : '';
			$port = ($ports === '') ? '' : ' port ' . $ports;
			$direction = (string)($policy['direction'] ?? 'in');
			foreach (threatshield_pf_list($policy['interfaces'] ?? []) as $friendly) {
				$real = threatshield_pf_real($ctx, (string)$friendly);
				if ($real === null) continue;
				/* "allow selected" blocks everything outside the list, both ways */
				$match = (($policy['action'] ?? 'block_selected') === 'allow_selected') ? "! <{$table}>" : "<{$table}>";
				if ($direction === 'in' || $direction === 'both') {
					$rules .= "block in log quick on {$real}{$family}{$proto} from {$match} to any{$port} label \"ThreatShield GeoIP {$id} inbound\"\n";
				}
				if ($direction === 'out' || $direction === 'both') {
					$rules .= "block out log quick on {$real}{$family}{$proto} from any to {$match}{$port} label \"ThreatShield GeoIP {$id} outbound\"\n";
				}
			}
		}
	}

	/* D. inbound protection: DNSBL reputation gate and flood limits */
	$policies = array_values(array_filter(threatshield_pf_list($cfg['inbound_policies'] ?? []),
	    fn($p) => is_array($p) && ($p['enable'] ?? 'on') === 'on'));
	if (!empty($policies)) {
		$rules .= threatshield_pf_inbound_rules($cfg, $ctx, $policies, $declare, $db);
	}

	if ($tables === '' && $rules === '') return '';
	return "# FreeSense Threat Shield\n" . $tables . threatshield_pf_add_trackers($rules);
}

/* filterlog reports a rule by its tracker (ridentifier). Threat Shield
 * rules get a fixed number per label, so log lines keep pointing at the right
 * rule across filter reloads. 4100000000 and up lies above the base rules
 * (1000000000 + n) and the time-based trackers of user rules. */
const THREATSHIELD_TRACKER_BASE = 4100000000;

function threatshield_pf_tracker(string $label, array &$used): int {
	$n = THREATSHIELD_TRACKER_BASE + (crc32($label) % 100000000);
	while (isset($used[$n]) && $used[$n] !== $label) $n++;
	$used[$n] = $label;
	return $n;
}

function threatshield_pf_add_trackers(string $rules): string {
	$used = [];
	$by_label = [];
	return (string)preg_replace_callback('/ label "(ThreatShield [^"]*)"/', function ($m) use (&$used, &$by_label) {
		$by_label[$m[1]] = $by_label[$m[1]] ?? threatshield_pf_tracker($m[1], $used);
		return $m[0] . ' ridentifier ' . $by_label[$m[1]];
	}, $rules);
}

function threatshield_pf_policy_dest(string $dest, array $ctx): ?string {
	$dest = trim($dest);
	if ($dest === '' || $dest === 'self') return '(self)';
	$n = threatshield_cidr_normalize($dest);
	if ($n !== null) return (substr($n, -3) === '/32' || substr($n, -4) === '/128') ? explode('/', $n)[0] : $n;
	if (preg_match('/^[A-Za-z0-9_]{1,31}$/', $dest) && in_array($dest, (array)($ctx['aliases'] ?? []), true)) return '$' . $dest;
	return null;
}

function threatshield_pf_policy_has_flood(array $p): bool {
	return ($p['owned'] ?? 'off') === 'on' && ((int)($p['flood_max_conn'] ?? 0) > 0 ||
	    trim((string)($p['flood_conn_rate'] ?? '')) !== '' || (int)($p['flood_max_states'] ?? 0) > 0);
}

function threatshield_pf_inbound_rules(array $cfg, array $ctx, array $policies, callable $declare, string $db): string {
	$rules = '';
	$dnsbl = ($cfg['dnsbl_enable'] ?? 'off') === 'on';
	$dnsbl_up = !empty($ctx['dnsbl_up']);
	$flood_ifs = [];
	foreach ($policies as $p) {
		if (!threatshield_pf_policy_has_flood($p)) continue;
		foreach (threatshield_pf_list($p['interfaces'] ?? []) as $f) $flood_ifs[(string)$f] = true;
	}
	if (!empty($flood_ifs)) {
		$declare(THREATSHIELD_T_FLOOD, "{$db}/flood.txt");
		foreach (array_keys($flood_ifs) as $friendly) {
			$real = threatshield_pf_real($ctx, $friendly);
			if ($real !== null) $rules .= "block drop in log quick on {$real} from <" . THREATSHIELD_T_FLOOD . "> to any label \"ThreatShield flood offender\"\n";
		}
	}
	foreach ($policies as $p) {
		$id = threatshield_pf_ident((string)($p['id'] ?? ''));
		$dst = threatshield_pf_policy_dest((string)($p['dest'] ?? 'self'), $ctx);
		$ports = threatshield_pf_ports((string)($p['ports'] ?? ''));
		if ($id === '' || $dst === null || $ports === '') continue;
		$protos = ['tcp' => ['tcp'], 'udp' => ['udp'], 'both' => ['tcp', 'udp']][(string)($p['protocol'] ?? 'tcp')] ?? ['tcp'];
		$log = (($p['log'] ?? 'on') === 'on') ? ' log' : '';
		$mode = $dnsbl ? (string)($p['dnsbl_mode'] ?? 'off') : 'off';
		$deny_on_fail = (($p['on_failure'] ?? 'allow') === 'deny');
		/* without the daemon nobody would ever vouch for a source: an
		 * allow-on-failure policy then lets traffic through, deny stays closed */
		$gate = ($mode !== 'off') && ($dnsbl_up || $deny_on_fail);
		$owned = (($p['owned'] ?? 'off') === 'on');
		if ($mode !== 'off') {
			$declare(THREATSHIELD_T_BAD, "{$db}/dnsbl/bad.txt");
			if ($gate) {
				$declare($deny_on_fail ? THREATSHIELD_T_KNOWN : THREATSHIELD_T_KNOWNF, $deny_on_fail ? "{$db}/dnsbl/known.txt" : "{$db}/dnsbl/known_f.txt");
				if ($mode === 'failopen') {
					$declare(THREATSHIELD_T_KNOWNF, "{$db}/dnsbl/known_f.txt");
					if ($deny_on_fail) $declare(THREATSHIELD_T_FAIL, "{$db}/dnsbl/fail.txt");
				}
			}
		}
		if ($owned) $declare(THREATSHIELD_T_ALLOW, "{$db}/ip/allow.txt");
		foreach (threatshield_pf_list($p['interfaces'] ?? []) as $friendly) {
			$real = threatshield_pf_real($ctx, (string)$friendly);
			if ($real === null) continue;
			foreach ($protos as $proto) {
				$flags = ($proto === 'tcp') ? ' flags S/SA' : '';
				$match = "on {$real} proto {$proto}";
				$to = "to {$dst} port {$ports}";
				if ($owned) {
					$rules .= "pass in quick {$match} from <" . THREATSHIELD_T_ALLOW . "> {$to}{$flags} keep state label \"ThreatShield {$id} allowlisted\"\n";
				}
				if ($mode !== 'off') {
					$rules .= "block drop in{$log} quick {$match} from <" . THREATSHIELD_T_BAD . "> {$to} label \"ThreatShield {$id} DNSBL listed\"\n";
				}
				if ($gate && $mode === 'greylist') {
					$known = $deny_on_fail ? THREATSHIELD_T_KNOWN : THREATSHIELD_T_KNOWNF;
					$rules .= "block drop in log (to pflog1) quick {$match} from ! <{$known}> {$to}{$flags} label \"ThreatShield {$id} DNSBL pending\"\n";
				} elseif ($gate && $mode === 'failopen') {
					if ($deny_on_fail) {
						$rules .= "block drop in{$log} quick {$match} from <" . THREATSHIELD_T_FAIL . "> {$to} label \"ThreatShield {$id} DNSBL unverified\"\n";
					}
					$rules .= "match in log (to pflog1) {$match} from ! <" . THREATSHIELD_T_KNOWNF . "> {$to}{$flags} label \"ThreatShield {$id} DNSBL check\"\n";
				}
				if ($owned) {
					$rules .= threatshield_pf_owned_pass($p, $ctx, (string)$friendly, $real, $proto, $to, $flags, $id);
				}
			}
		}
	}
	return $rules;
}

function threatshield_pf_owned_pass(array $p, array $ctx, string $friendly, string $real, string $proto, string $to, string $flags, string $id): string {
	$opts = [];
	if ((int)($p['flood_max_conn'] ?? 0) > 0 && $proto === 'tcp') $opts[] = 'max-src-conn ' . (int)$p['flood_max_conn'];
	$rate = trim((string)($p['flood_conn_rate'] ?? ''));
	if ($rate !== '' && threatshield_valid_rate($rate) && $proto === 'tcp') $opts[] = 'max-src-conn-rate ' . $rate;
	if ((int)($p['flood_max_states'] ?? 0) > 0) $opts[] = 'max-src-states ' . (int)$p['flood_max_states'];
	if (!empty($opts)) $opts[] = 'overload <' . THREATSHIELD_T_FLOOD . '> flush global';
	$state = (($p['synproxy'] ?? 'off') === 'on' && $proto === 'tcp') ? 'synproxy state' : 'keep state';
	if (!empty($opts)) $state .= ' (' . implode(', ', $opts) . ')';
	$out = '';
	$families = ['inet' => (string)($ctx['gw4'][$friendly] ?? ''), 'inet6' => (string)($ctx['gw6'][$friendly] ?? '')];
	$dst_family = (strpos($to, '(self)') !== false || strpos($to, '$') !== false) ? null : ((strpos(explode(' port ', $to)[0], ':') !== false) ? 'inet6' : 'inet');
	foreach ($families as $family => $gw) {
		if ($dst_family !== null && $dst_family !== $family) continue;
		$reply = (!empty($ctx['replyto']) && $gw !== '' && filter_var($gw, FILTER_VALIDATE_IP)) ? " reply-to ({$real} {$gw})" : '';
		$log = empty($ctx['log_pass']) ? '' : ' log';
		$out .= "pass in{$log} quick on {$real}{$reply} {$family} proto {$proto} from any {$to}{$flags} {$state} label \"ThreatShield {$id} pass\"\n";
	}
	return $out;
}
