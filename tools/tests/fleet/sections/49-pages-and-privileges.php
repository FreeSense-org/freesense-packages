<?php
/* Fleet controller tests: every page has a privilege and every page that changes something is gated. Loaded by ../run.php (shares its variables). */

$pkgroot = $repo . '/sysutils/FreeSense-pkg-Fleet/files';
$priv_list = array();
require($pkgroot . '/etc/inc/priv/fleet.priv.inc');
$match_of = function (string $page) use ($priv_list): array {
	$hits = array();
	foreach ($priv_list as $ident => $p) {
		foreach ($p['match'] as $m) {
			if (fnmatch($m, "fleet/{$page}") || fnmatch($m, "fleet/{$page}*")) {
				$hits[$ident] = true;
			}
		}
	}
	return array_keys($hits);
};
/* The NOC kiosk pages are opened by a screen key, not by a WebUI account. */
$keyed = array('kiosk.php', 'kiosk_data.php');
$pages = array_map('basename', glob($pkgroot . '/usr/local/www/fleet/*.php'));
$bad = array();
foreach ($pages as $page) {
	$hits = $match_of($page);
	if (in_array($page, $keyed, true)) {
		if (!empty($hits)) {
			$bad[] = "{$page} is key-only but a privilege matches it";
		}
	} elseif (count($hits) !== 1) {
		$bad[] = "{$page} is matched by " . count($hits) . ' privileges';
	}
}
check(empty($bad), 'every Fleet page is matched by exactly one privilege (the NOC kiosk pages by none): ' . implode('; ', $bad));

/* The inline ##|+PRIV block of fleet.php names a privilege that exists and matches the page. */
$fp = (string)file_get_contents($pkgroot . '/usr/local/www/fleet/fleet.php');
preg_match('/##\|\*IDENT=(\S+)/', $fp, $mi);
preg_match('/##\|\*MATCH=(\S+)/', $fp, $mm);
check(isset($mi[1], $mm[1]) && isset($priv_list[$mi[1]]) && in_array($mm[1], $priv_list[$mi[1]]['match'], true),
    'the privilege block in fleet.php is the one in fleet.priv.inc (same ident, its match is one of the listed ones)');

/* Any page that reads POST either belongs to the full privilege or checks it itself. */
$full = 'page-system-fleet-controller';
$ungated = array();
foreach ($pages as $page) {
	if (in_array($page, $keyed, true)) {
		continue;
	}
	$text = (string)file_get_contents($pkgroot . '/usr/local/www/fleet/' . $page);
	if ((strpos($text, '$_POST') !== false) && !in_array($full, $match_of($page), true) && (strpos($text, "isAllowedPage('fleet/fleet.php')") === false)) {
		$ungated[] = $page;
	}
}
check(empty($ungated), 'a page that reads POST is in the full Fleet privilege or checks it: ' . implode(', ', $ungated));
