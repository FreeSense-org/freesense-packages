<?php
/*
 * threatshield_geo.inc
 * FreeSense Threat Shield - offline IP location (country, AS) for the threat
 * map, built from the DB-IP Lite databases (CC BY 4.0, "IP Geolocation by
 * DB-IP", https://db-ip.com)
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 *
 * The CSV ranges become sorted fixed-width records, searched with strcmp()
 * on the binary start address, so no extension or GMP is needed:
 *   country4.bin  4-byte IPv4 start + 2-byte country ("--" = unknown)
 *   country6.bin  first 8 bytes (/64) of the IPv6 start + 2-byte country
 *   asn4.bin      4-byte start + 4-byte AS number (0 = unknown)
 *   asn6.bin      8-byte /64 start + 4-byte AS number
 *   asn.idx       sorted 4-byte AS number + 4-byte offset + 2-byte length
 *   asn.txt       AS organisation names
 *   meta.json     source, licence, month, build time, record counts
 */

if (!defined('THREATSHIELD_GEO_DIR')) define('THREATSHIELD_GEO_DIR', '/var/db/threatshield/geodb');
const THREATSHIELD_GEO_ATTRIBUTION = 'IP Geolocation by DB-IP';
const THREATSHIELD_GEO_ATTRIBUTION_URL = 'https://db-ip.com';

/* Download URLs for this month, then last month (published monthly). */
function threatshield_geo_dbip_urls(string $kind, int $now): array {
	$months = [gmdate('Y-m', $now), gmdate('Y-m', strtotime('first day of last month', $now))];
	return array_map(fn($m) => "https://download.db-ip.com/free/dbip-{$kind}-lite-{$m}.csv.gz", $months);
}

/* Big-endian increment of a binary address; null past the last address. */
function threatshield_geo_bin_next(string $bin): ?string {
	for ($i = strlen($bin) - 1; $i >= 0; $i--) {
		$c = ord($bin[$i]);
		if ($c < 255) return substr($bin, 0, $i) . chr($c + 1) . str_repeat("\0", strlen($bin) - $i - 1);
	}
	return null;
}

/* Fixed-width key length for an address: 4 bytes (IPv4) or the /64 (IPv6). */
function threatshield_geo_key(string $ip): ?string {
	$bin = @inet_pton($ip);
	if ($bin === false) return null;
	return (strlen($bin) === 4) ? $bin : substr($bin, 0, 8);
}

/* Streams sorted ranges into a record file, filling gaps with $gap and
 * merging neighbours with the same value. */
final class ThreatShieldGeoWriter {
	private $fh;
	private string $buf = '';    // PHP does not buffer writes to plain files
	private ?string $next = null;
	private ?string $pend_key = null;
	private ?string $pend_val = null;
	public int $count = 0;

	public function __construct(string $file, private string $gap) {
		$this->fh = fopen($file, 'wb');
	}

	public function add(string $start, string $end, string $value): void {
		if ($this->next !== null && strcmp($start, $this->next) > 0) $this->emit($this->next, $this->gap);
		elseif ($this->next === null && $this->pend_key === null && trim($start, "\0") !== '') $this->emit(str_repeat("\0", strlen($start)), $this->gap);
		$this->emit($start, $value);
		$this->next = threatshield_geo_bin_next($end);
	}

	private function emit(string $key, string $value): void {
		if ($this->pend_key !== null) {
			if ($key === $this->pend_key) { $this->pend_val = $value; return; }    // same /64: keep the latest
			if ($value === $this->pend_val) return;                                 // continues the previous range
			$this->buf .= $this->pend_key . $this->pend_val;
			$this->count++;
			if (strlen($this->buf) >= 262144) {
				fwrite($this->fh, $this->buf);
				$this->buf = '';
			}
		}
		$this->pend_key = $key;
		$this->pend_val = $value;
	}

	public function close(): void {
		if ($this->next !== null) $this->emit($this->next, $this->gap);
		if ($this->pend_key !== null) {
			$this->buf .= $this->pend_key . $this->pend_val;
			$this->count++;
		}
		fwrite($this->fh, $this->buf);
		$this->buf = '';
		fclose($this->fh);
	}
}

/* Builds the record files from the DB-IP CSV files (gzip or plain) into
 * $dest; the previous database stays until the new one is complete. */
function threatshield_geo_build(string $country_csv, ?string $asn_csv, string $dest, ?array &$stats = null): bool {
	$tmp = $dest . '.new';
	threatshield_geo_rmdir($tmp);
	if (!@mkdir($tmp, 0755, true)) return false;
	$stats = ['country4' => 0, 'country6' => 0, 'asn4' => 0, 'asn6' => 0, 'asn_names' => 0, 'rows' => 0];

	$in = @gzopen($country_csv, 'rb');
	if (!$in) return false;
	$w4 = new ThreatShieldGeoWriter("{$tmp}/country4.bin", '--');
	$w6 = new ThreatShieldGeoWriter("{$tmp}/country6.bin", '--');
	while (($line = gzgets($in)) !== false) {
		$f = explode(',', trim($line));
		if (count($f) < 3) continue;
		$a = @inet_pton($f[0]);
		$b = @inet_pton($f[1]);
		$cc = strtoupper(substr(trim($f[2], '"'), 0, 2));
		if ($a === false || $b === false || strlen($a) !== strlen($b) || !preg_match('/^[A-Z]{2}$/', $cc)) continue;
		$stats['rows']++;
		if ($cc === 'ZZ') $cc = '--';    // reserved and private ranges
		if (strlen($a) === 4) $w4->add($a, $b, $cc);
		else $w6->add(substr($a, 0, 8), substr($b, 0, 8), $cc);
	}
	gzclose($in);
	$w4->close();
	$w6->close();
	$stats['country4'] = $w4->count;
	$stats['country6'] = $w6->count;

	if ($asn_csv !== null) {
		$in = @gzopen($asn_csv, 'rb');
		if (!$in) return false;
		$a4 = new ThreatShieldGeoWriter("{$tmp}/asn4.bin", pack('N', 0));
		$a6 = new ThreatShieldGeoWriter("{$tmp}/asn6.bin", pack('N', 0));
		$names = [];
		while (($line = gzgets($in)) !== false) {
			$f = str_getcsv(trim($line), ',', '"', '');
			if (count($f) < 3) continue;
			$a = @inet_pton($f[0]);
			$b = @inet_pton($f[1]);
			$asn = (int)$f[2];
			if ($a === false || $b === false || strlen($a) !== strlen($b) || $asn <= 0 || $asn > 4294967295) continue;
			if (!isset($names[$asn]) && isset($f[3]) && $f[3] !== '') $names[$asn] = substr($f[3], 0, 120);
			if (strlen($a) === 4) $a4->add($a, $b, pack('N', $asn));
			else $a6->add(substr($a, 0, 8), substr($b, 0, 8), pack('N', $asn));
		}
		gzclose($in);
		$a4->close();
		$a6->close();
		ksort($names);
		$idx = '';
		$txt = '';
		foreach ($names as $asn => $name) {
			$idx .= pack('NNn', $asn, strlen($txt), strlen($name));
			$txt .= $name;
		}
		file_put_contents("{$tmp}/asn.idx", $idx);
		file_put_contents("{$tmp}/asn.txt", $txt);
		$stats['asn4'] = $a4->count;
		$stats['asn6'] = $a6->count;
		$stats['asn_names'] = count($names);
	}
	if ($stats['country4'] < 1000) {
		threatshield_geo_rmdir($tmp);
		return false;
	}
	file_put_contents("{$tmp}/meta.json", json_encode([
		'source' => 'DB-IP Lite', 'licence' => 'CC BY 4.0', 'attribution' => THREATSHIELD_GEO_ATTRIBUTION,
		'month' => (preg_match('/(\d{4}-\d{2})\.csv/', $country_csv, $m) ? $m[1] : gmdate('Y-m')),
		'asn' => $asn_csv !== null, 'built' => time(), 'counts' => $stats,
	]));
	threatshield_geo_rmdir($dest . '.old');
	if (is_dir($dest) && !@rename($dest, $dest . '.old')) return false;
	if (!@rename($tmp, $dest)) return false;
	threatshield_geo_rmdir($dest . '.old');
	return true;
}

function threatshield_geo_rmdir(string $dir): void {
	if (!is_dir($dir)) return;
	foreach ((array)glob($dir . '/*') as $f) @unlink($f);
	@rmdir($dir);
}

final class ThreatShieldGeo {
	private array $blobs = [];
	private array $memo = [];
	private ?array $meta = null;

	private function __construct(private string $dir) {}

	public static function open(string $dir = THREATSHIELD_GEO_DIR): ?self {
		return is_file($dir . '/country4.bin') ? new self($dir) : null;
	}

	public function meta(): array {
		if ($this->meta === null) {
			$m = json_decode((string)@file_get_contents($this->dir . '/meta.json'), true);
			$this->meta = is_array($m) ? $m : [];
		}
		return $this->meta;
	}

	private function blob(string $name): string {
		return $this->blobs[$name] ??= (string)@file_get_contents($this->dir . '/' . $name);
	}

	/* Offset of the last record whose key is <= $key, or -1. */
	public static function search(string $blob, int $rec, int $klen, string $key): int {
		$lo = 0;
		$hi = intdiv(strlen($blob), $rec) - 1;
		$found = -1;
		while ($lo <= $hi) {
			$mid = ($lo + $hi) >> 1;
			if (strcmp(substr($blob, $mid * $rec, $klen), $key) <= 0) {
				$found = $mid;
				$lo = $mid + 1;
			} else {
				$hi = $mid - 1;
			}
		}
		return ($found < 0) ? -1 : $found * $rec;
	}

	/* ['cc' => 'DK' or '', 'asn' => int, 'org' => string] */
	public function lookup(string $ip): array {
		if (isset($this->memo[$ip])) return $this->memo[$ip];
		$out = ['cc' => '', 'asn' => 0, 'org' => ''];
		$key = threatshield_geo_key($ip);
		if ($key !== null) {
			$klen = strlen($key);
			$v6 = ($klen === 8);
			$blob = $this->blob($v6 ? 'country6.bin' : 'country4.bin');
			$at = self::search($blob, $klen + 2, $klen, $key);
			if ($at >= 0) {
				$cc = substr($blob, $at + $klen, 2);
				if ($cc !== '--') $out['cc'] = $cc;
			}
			$blob = $this->blob($v6 ? 'asn6.bin' : 'asn4.bin');
			if ($blob !== '') {
				$at = self::search($blob, $klen + 4, $klen, $key);
				if ($at >= 0) {
					$out['asn'] = unpack('N', substr($blob, $at + $klen, 4))[1];
					$out['org'] = $this->asn_name($out['asn']);
				}
			}
		}
		if (count($this->memo) > 5000) $this->memo = [];
		return $this->memo[$ip] = $out;
	}

	public function asn_name(int $asn): string {
		if ($asn <= 0) return '';
		$idx = $this->blob('asn.idx');
		$at = self::search($idx, 10, 4, pack('N', $asn));
		if ($at < 0) return '';
		$r = unpack('Nasn/Noff/nlen', substr($idx, $at, 10));
		if ($r['asn'] !== $asn) return '';
		return substr($this->blob('asn.txt'), $r['off'], $r['len']);
	}
}

/* Country name, position and dot spread; [name, lat, lon, spread] or null. */
function threatshield_geo_country(string $cc): ?array {
	static $countries = null;
	if ($countries === null) {
		require_once(__DIR__ . '/threatshield_geo_countries.inc');
		$countries = threatshield_geo_countries();
	}
	return $countries[strtoupper($cc)] ?? null;
}

/* A fixed position near the country's label point per /24 (IPv4) or /48
 * (IPv6) network, so the sources of one network share a dot. */
function threatshield_geo_position(string $ip, string $cc): ?array {
	$c = threatshield_geo_country($cc);
	if ($c === null) return null;
	$bin = @inet_pton($ip);
	if ($bin === false) return null;
	$net = (strlen($bin) === 4) ? substr($bin, 0, 3) : substr($bin, 0, 6);
	$h = crc32($net);
	$angle = (($h & 0xffff) / 65535) * 2 * M_PI;
	$r = sqrt((($h >> 16) & 0xffff) / 65535) * $c[3];
	$lat = max(-58.0, min(83.0, $c[1] + $r * sin($angle)));
	$lon = $c[2] + $r * cos($angle) / max(0.25, cos(deg2rad($c[1])));
	if ($lon > 180) $lon -= 360;
	if ($lon < -180) $lon += 360;
	return [round($lat, 2), round($lon, 2)];
}

/* Coordinates from zone1970.tab ("+5540+01235" or "+554000+0123500"). */
function threatshield_geo_parse_iso6709(string $s): ?array {
	if (!preg_match('/^([+-])(\d{2})(\d{2})(\d{2})?([+-])(\d{3})(\d{2})(\d{2})?$/', $s, $m)) return null;
	$lat = (int)$m[2] + (int)$m[3] / 60 + (int)($m[4] ?? 0) / 3600;
	$lon = (int)$m[6] + (int)$m[7] / 60 + (int)($m[8] ?? 0) / 3600;
	return [round(($m[1] === '-' ? -$lat : $lat), 3), round(($m[5] === '-' ? -$lon : $lon), 3)];
}

/* [lat, lon, cc] of a time zone from zone1970.tab, or null. */
function threatshield_geo_zone_location(string $tab, string $tz): ?array {
	foreach (explode("\n", $tab) as $line) {
		if ($line === '' || $line[0] === '#') continue;
		$f = explode("\t", $line);
		if (count($f) >= 3 && $f[2] === $tz) {
			$pos = threatshield_geo_parse_iso6709($f[1]);
			if ($pos !== null) return [$pos[0], $pos[1], substr($f[0], 0, 2)];
		}
	}
	return null;
}
