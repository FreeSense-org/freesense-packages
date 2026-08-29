<?php
/*
 * threatshield_update.php
 * Automated Feed & GeoIP Country Downloader for FreeSense Threat Shield
 */

require_once('threatshield.inc');

$mode = $argv[1] ?? 'all';
$force = ($argv[2] ?? '') === 'force';
$cfg = threatshield_config();

safe_mkdir(THREATSHIELD_DB_DIR, 0750);
safe_mkdir(THREATSHIELD_GEOIP_DIR, 0750);

function threatshield_download_file(string $url, string $dest): bool {
	$parts = parse_url($url);
	if (!is_array($parts) || strtolower($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])) {
		return false;
	}
	$tmp = $dest . '.tmp.' . getmypid();
	$ch = curl_init($url);
	$fp = fopen($tmp, 'x');
	if (!$fp) return false;

	curl_setopt($ch, CURLOPT_FILE, $fp);
	curl_setopt($ch, CURLOPT_TIMEOUT, 30);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
	curl_setopt($ch, CURLOPT_USERAGENT, 'FreeSense-ThreatShield/1.0');
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
	curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
	curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
	curl_setopt($ch, CURLOPT_NOPROGRESS, false);
	curl_setopt($ch, CURLOPT_PROGRESSFUNCTION, static function ($resource, $downloadSize, $downloaded) {
		return $downloaded > THREATSHIELD_MAX_FEED_BYTES ? 1 : 0;
	});

	$success = curl_exec($ch);
	$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
	curl_close($ch);
	fclose($fp);

	if (!$success || $code < 200 || $code >= 300) {
		@unlink($tmp);
		return false;
	}
	if (!@rename($tmp, $dest)) {
		@unlink($tmp);
		return false;
	}
	return true;
}

function threatshield_interval_due(string $kind, string $interval): bool {
	$hours = ['6hours' => 6, '12hours' => 12, 'daily' => 24, 'weekly' => 168][$interval] ?? 24;
	$file = THREATSHIELD_DB_DIR . '/last_' . $kind . '_update';
	$last = is_file($file) ? (int)trim((string)file_get_contents($file)) : 0;
	return $last <= 0 || (time() - $last) >= ($hours * 3600);
}
function threatshield_mark_updated(string $kind): void {
	file_put_contents(THREATSHIELD_DB_DIR . '/last_' . $kind . '_update', (string)time() . "\n", LOCK_EX);
}

if (($mode === 'all' || $mode === 'feeds') && ($force || threatshield_interval_due('feeds', (string)($cfg['feed_update_interval'] ?? 'daily')))) {
	echo "[ThreatShield] Updating DNS Blocklists...\n";
	$reload_needed = false;

	if (!empty($cfg['feeds']) && is_array($cfg['feeds'])) {
		foreach ($cfg['feeds'] as $idx => $feed) {
			if (empty($feed['enabled']) || $feed['enabled'] !== 'on') continue;
			$url = $feed['url'] ?? '';
			if ($url === '') continue;

			echo "  - Fetching {$feed['name']} ({$url})...\n";
			$dest = THREATSHIELD_DB_DIR . '/feed_' . md5($url) . '.txt';
			if (threatshield_download_file($url, $dest)) {
				echo "    [OK] " . filesize($dest) . " bytes downloaded.\n";
				$reload_needed = true;
			} else {
				echo "    [FAIL] Unable to download feed.\n";
			}
		}
	}

	$applied = $reload_needed;
	if ($reload_needed && threatshield_is_running()) {
		echo "[ThreatShield] Applying locally downloaded DNS blocklists...\n";
		$refresh = threatshield_api_request('filtering/refresh', 'POST', []);
		$applied = $refresh !== null;
		if (!$applied) echo "    [FAIL] AdGuard Home rejected the filter reload; the updater will retry.\n";
	}
	if ($applied) threatshield_mark_updated('feeds');
}

if (($mode === 'all' || $mode === 'geoip') && ($force || threatshield_interval_due('geoip', (string)($cfg['geoip_update_interval'] ?? 'weekly')))) {
	echo "[ThreatShield] Updating GeoIP Country CIDR Databases...\n";
	if ($cfg['geoip_enable'] === 'on' && !empty($cfg['geoip_policies'])) {
		$countries = [];
		foreach (threatshield_normalize_list($cfg['geoip_policies']) as $policy) $countries = array_merge($countries, threatshield_normalize_list($policy['countries'] ?? []));
		foreach (array_unique($countries) as $cc) {
			$cc_clean = strtolower(preg_replace('/[^a-zA-Z]/', '', $cc));
			if ($cc_clean === '') continue;

			$url = "https://www.ipdeny.com/ipblocks/data/countries/{$cc_clean}.zone";
			$dest = THREATSHIELD_GEOIP_DIR . '/' . strtoupper($cc_clean) . '.zone';

			echo "  - Fetching country CIDRs for " . strtoupper($cc_clean) . "...\n";
			if (threatshield_download_file($url, $dest)) {
				echo "    [OK] Saved " . strtoupper($cc_clean) . " (" . filesize($dest) . " bytes)\n";
			} else {
				echo "    [FAIL] Could not fetch CIDRs for " . strtoupper($cc_clean) . "\n";
			}
		}

		echo "[ThreatShield] Rebuilding pf kernel GeoIP tables...\n";
		threatshield_update_geoip();
		threatshield_mark_updated('geoip');
	}
}

echo "[ThreatShield] Update complete.\n";
