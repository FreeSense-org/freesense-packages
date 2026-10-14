<?php
/*
 * threatshield_catalog.inc
 * FreeSense Threat Shield - curated presets: DNS lists, IP lists, DNSBL zones
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

/* DNS block and allow lists.  'levels' lists the protection levels that turn
 * the feed on; an empty list means an optional add-on. */
function threatshield_feed_catalog(): array {
	$hagezi = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/';
	return [
		'adguard_dns' => ['name' => 'AdGuard DNS filter', 'url' => 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt',
		    'kind' => 'block', 'category' => 'Ads & tracking', 'levels' => ['light', 'normal']],
		'hagezi_light' => ['name' => 'HaGeZi Light', 'url' => $hagezi . 'light.txt',
		    'kind' => 'block', 'category' => 'Ads & tracking', 'levels' => ['light']],
		'hagezi_multi' => ['name' => 'HaGeZi Multi Normal', 'url' => $hagezi . 'multi.txt',
		    'kind' => 'block', 'category' => 'Ads & tracking', 'levels' => ['normal']],
		'hagezi_pro' => ['name' => 'HaGeZi Pro', 'url' => $hagezi . 'pro.txt',
		    'kind' => 'block', 'category' => 'Ads & tracking', 'levels' => []],
		'hagezi_proplus' => ['name' => 'HaGeZi Pro++', 'url' => $hagezi . 'pro.plus.txt',
		    'kind' => 'block', 'category' => 'Ads & tracking', 'levels' => ['aggressive']],
		'oisd_small' => ['name' => 'OISD Small', 'url' => 'https://small.oisd.nl',
		    'kind' => 'block', 'category' => 'Ads & tracking', 'levels' => []],
		'oisd_big' => ['name' => 'OISD Big', 'url' => 'https://big.oisd.nl',
		    'kind' => 'block', 'category' => 'Ads & tracking', 'levels' => ['aggressive']],
		'phishing_army' => ['name' => 'Phishing Army extended', 'url' => 'https://phishing.army/download/phishing_army_blocklist_extended.txt',
		    'kind' => 'block', 'category' => 'Phishing & malware', 'levels' => ['light', 'normal', 'aggressive']],
		'hagezi_tif' => ['name' => 'HaGeZi Threat Intelligence (medium)', 'url' => $hagezi . 'tif.medium.txt',
		    'kind' => 'block', 'category' => 'Phishing & malware', 'levels' => ['aggressive']],
		'hagezi_bypass' => ['name' => 'HaGeZi DoH, VPN and proxy bypass', 'url' => $hagezi . 'doh-vpn-proxy-bypass.txt',
		    'kind' => 'block', 'category' => 'Anti-bypass', 'levels' => ['aggressive']],
		'stevenblack' => ['name' => 'Steven Black unified hosts', 'url' => 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
		    'kind' => 'block', 'category' => 'Ads & malware', 'levels' => []],
		'hagezi_referral' => ['name' => 'HaGeZi referral allowlist', 'url' => $hagezi . 'whitelist-referral.txt',
		    'kind' => 'allow', 'category' => 'Fewer false positives', 'levels' => ['normal', 'aggressive']],
	];
}

function threatshield_feed_levels(): array {
	return [
		'light' => [gettext('Light'), gettext('Ads and phishing with very few false positives.')],
		'normal' => [gettext('Normal'), gettext('Ads, trackers and phishing. Recommended for most networks.')],
		'aggressive' => [gettext('Aggressive'), gettext('Adds threat intelligence and DoH/VPN bypass domains; may block a few legitimate sites.')],
	];
}

/* IP lists for pf tables.  'direction' is the default: in = block sources
 * arriving on WAN, out = block LAN clients connecting to them. */
function threatshield_ipfeed_catalog(): array {
	return [
		'spamhaus_drop' => ['id' => 'shdrop', 'name' => 'Spamhaus DROP (IPv4)', 'url' => 'https://www.spamhaus.org/drop/drop.txt', 'kind' => 'threat', 'direction' => 'both'],
		'spamhaus_drop6' => ['id' => 'shdrop6', 'name' => 'Spamhaus DROP (IPv6)', 'url' => 'https://www.spamhaus.org/drop/dropv6.txt', 'kind' => 'threat', 'direction' => 'both'],
		'firehol_l1' => ['id' => 'fhl1', 'name' => 'FireHOL level 1', 'url' => 'https://iplists.firehol.org/files/firehol_level1.netset', 'kind' => 'threat', 'direction' => 'in'],
		'feodo' => ['id' => 'feodo', 'name' => 'abuse.ch Feodo Tracker botnet C2', 'url' => 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 'kind' => 'threat', 'direction' => 'out'],
		'et_compromised' => ['id' => 'etcomp', 'name' => 'Emerging Threats compromised hosts', 'url' => 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'kind' => 'threat', 'direction' => 'in'],
		'cins' => ['id' => 'cins', 'name' => 'CINS Army bad guys', 'url' => 'https://cinsscore.com/list/ci-badguys.txt', 'kind' => 'threat', 'direction' => 'in'],
		'doh_ipv4' => ['id' => 'doh4', 'name' => 'Public DoH/DoT resolvers (IPv4)', 'url' => 'https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt', 'kind' => 'doh', 'direction' => 'out'],
		'doh_ipv6' => ['id' => 'doh6', 'name' => 'Public DoH/DoT resolvers (IPv6)', 'url' => 'https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt', 'kind' => 'doh', 'direction' => 'out'],
	];
}

/* DNSBL zones.  ZEN's match range leaves out the PBL (127.0.0.10/11): it
 * lists ordinary home connections, which would lock out remote users. */
function threatshield_dnsbl_zone_catalog(): array {
	return [
		'zen' => ['name' => 'Spamhaus ZEN', 'zone' => 'zen.spamhaus.org', 'match' => '127.0.0.2-127.0.0.9', 'ipv6' => 'off',
		    'note' => gettext('Free for low volume. Queries must come from your own resolver, not a public one.')],
		'zen_dqs' => ['name' => 'Spamhaus ZEN (DQS key)', 'zone' => '{key}.zen.dq.spamhaus.net', 'match' => '127.0.0.2-127.0.0.9', 'ipv6' => 'on',
		    'note' => gettext('Needs a free Spamhaus Data Query Service key; works through any resolver.')],
		'dronebl' => ['name' => 'DroneBL', 'zone' => 'dnsbl.dronebl.org', 'match' => 'any', 'ipv6' => 'on',
		    'note' => gettext('Botnets, open proxies and abusive hosts.')],
		'blocklist_de' => ['name' => 'blocklist.de', 'zone' => 'all.bl.blocklist.de', 'match' => 'any', 'ipv6' => 'off',
		    'note' => gettext('Hosts reported for SSH, mail and web attacks.')],
		'barracuda' => ['name' => 'Barracuda Reputation', 'zone' => 'b.barracudacentral.org', 'match' => '127.0.0.2', 'ipv6' => 'off',
		    'note' => gettext('Requires registering your resolver address with Barracuda.')],
	];
}

/* AdGuard Home 0.107.79 blocked-service identifiers (GET
 * /control/blocked_services/all) with name, group and icon. */
function threatshield_services_info(): array {
	return [
		'4chan' => ['4chan', 'Social media', 'users'],
		'500px' => ['500px', 'Social media', 'users'],
		'9gag' => ['9GAG', 'Social media', 'users'],
		'activision_blizzard' => ['Activision Blizzard', 'Online gaming', 'gamepad'],
		'aliexpress' => ['AliExpress', 'Shopping', 'cart-shopping'],
		'amazon' => ['Amazon', 'Shopping', 'cart-shopping'],
		'amazon_streaming' => ['Amazon Streaming', 'Video & music streaming', 'play'],
		'amino' => ['Amino', 'Social media', 'users'],
		'apple_streaming' => ['Apple Streaming', 'Video & music streaming', 'play'],
		'battle_net' => ['Battle.net', 'Online gaming', 'gamepad'],
		'betano' => ['Betano', 'Gambling', 'dice'],
		'betfair' => ['Betfair', 'Gambling', 'dice'],
		'betway' => ['Betway', 'Gambling', 'dice'],
		'bigo_live' => ['Bigo Live', 'Video & music streaming', 'play'],
		'bilibili' => ['Bilibili', 'Video & music streaming', 'play'],
		'blaze' => ['Blaze', 'Gambling', 'dice'],
		'blizzard_entertainment' => ['Blizzard Entertainment', 'Online gaming', 'gamepad'],
		'bluesky' => ['Bluesky', 'Social media', 'users'],
		'box' => ['Box', 'Hosting & CDN', 'cloud'],
		'canais_globo' => ['Canais Globo', 'Video & music streaming', 'play'],
		'chatgpt' => ['ChatGPT', 'AI assistants', 'robot'],
		'claro' => ['Claro', 'Video & music streaming', 'play'],
		'claude' => ['Claude', 'AI assistants', 'robot'],
		'cloudflare' => ['Cloudflare', 'Hosting & CDN', 'cloud'],
		'clubhouse' => ['Clubhouse', 'Social media', 'users'],
		'coolapk' => ['CoolApk', 'Shopping', 'cart-shopping'],
		'copilot' => ['Copilot', 'AI assistants', 'robot'],
		'crunchyroll' => ['Crunchyroll', 'Video & music streaming', 'play'],
		'dailymotion' => ['Dailymotion', 'Video & music streaming', 'play'],
		'deepseek' => ['DeepSeek', 'AI assistants', 'robot'],
		'deezer' => ['Deezer', 'Video & music streaming', 'play'],
		'directvgo' => ['DirecTV Go', 'Video & music streaming', 'play'],
		'discord' => ['Discord', 'Social media', 'users'],
		'discoveryplus' => ['Discovery+', 'Video & music streaming', 'play'],
		'disneyplus' => ['Disney+', 'Video & music streaming', 'play'],
		'douban' => ['Douban', 'Social media', 'users'],
		'dropbox' => ['Dropbox', 'Hosting & CDN', 'cloud'],
		'ebay' => ['eBay', 'Shopping', 'cart-shopping'],
		'electronic_arts' => ['Electronic Arts', 'Online gaming', 'gamepad'],
		'epic_games' => ['Epic Games', 'Online gaming', 'gamepad'],
		'espn' => ['ESPN', 'Video & music streaming', 'play'],
		'facebook' => ['Facebook', 'Social media', 'users'],
		'fdj_united' => ['FDJ United', 'Gambling', 'dice'],
		'fifa' => ['FIFA', 'Video & music streaming', 'play'],
		'flickr' => ['Flickr', 'Hosting & CDN', 'cloud'],
		'gemini' => ['Google Gemini', 'AI assistants', 'robot'],
		'globoplay' => ['Globoplay', 'Video & music streaming', 'play'],
		'gog' => ['GOG', 'Online gaming', 'gamepad'],
		'grindr' => ['Grindr', 'Dating', 'heart'],
		'grok' => ['Grok', 'AI assistants', 'robot'],
		'hbomax' => ['HBO Max', 'Video & music streaming', 'play'],
		'hulu' => ['Hulu', 'Video & music streaming', 'play'],
		'icloud_private_relay' => ['iCloud Private Relay', 'Privacy tools', 'user-secret'],
		'iheartradio' => ['iHeartRadio', 'Video & music streaming', 'play'],
		'imgur' => ['Imgur', 'Hosting & CDN', 'cloud'],
		'instagram' => ['Instagram', 'Social media', 'users'],
		'io_interactive' => ['IO Interactive', 'Online gaming', 'gamepad'],
		'iqiyi' => ['iQIYI', 'Video & music streaming', 'play'],
		'kakaotalk' => ['KakaoTalk', 'Chat & voice', 'comments'],
		'kik' => ['Kik', 'Chat & voice', 'comments'],
		'kook' => ['KOOK', 'Social media', 'users'],
		'lazada' => ['Lazada', 'Shopping', 'cart-shopping'],
		'leagueoflegends' => ['League of Legends', 'Online gaming', 'gamepad'],
		'line' => ['LINE', 'Social media', 'users'],
		'linkedin' => ['LinkedIn', 'Social media', 'users'],
		'lionsgateplus' => ['Lionsgate+', 'Video & music streaming', 'play'],
		'looke' => ['Looke', 'Video & music streaming', 'play'],
		'mail_ru' => ['Mail.ru', 'Social media', 'users'],
		'manus' => ['Manus', 'AI assistants', 'robot'],
		'mastodon' => ['Mastodon', 'Social media', 'users'],
		'max' => ['MAX', 'Chat & voice', 'comments'],
		'mercado_libre' => ['Mercado Libre', 'Shopping', 'cart-shopping'],
		'meta_ai' => ['Meta AI', 'AI assistants', 'robot'],
		'microsoft_teams' => ['Microsoft Teams', 'Chat & voice', 'comments'],
		'minecraft' => ['Minecraft', 'Online gaming', 'gamepad'],
		'nebula' => ['Nebula', 'Video & music streaming', 'play'],
		'netflix' => ['Netflix', 'Video & music streaming', 'play'],
		'nintendo' => ['Nintendo', 'Online gaming', 'gamepad'],
		'nvidia' => ['Nvidia', 'Software', 'download'],
		'odysee' => ['Odysee', 'Social media', 'users'],
		'ok' => ['OK.ru', 'Social media', 'users'],
		'olvid' => ['Olvid', 'Chat & voice', 'comments'],
		'onlyfans' => ['OnlyFans', 'Social media', 'users'],
		'origin' => ['Origin', 'Online gaming', 'gamepad'],
		'paramountplus' => ['Paramount Plus', 'Video & music streaming', 'play'],
		'peacock_tv' => ['Peacock TV', 'Video & music streaming', 'play'],
		'perplexity' => ['Perplexity', 'AI assistants', 'robot'],
		'pinterest' => ['Pinterest', 'Social media', 'users'],
		'playstation' => ['PlayStation', 'Online gaming', 'gamepad'],
		'playstore' => ['Google Play Store', 'Software', 'download'],
		'plenty_of_fish' => ['Plenty of Fish', 'Dating', 'heart'],
		'plex' => ['Plex', 'Video & music streaming', 'play'],
		'pluto_tv' => ['Pluto TV', 'Video & music streaming', 'play'],
		'privacy' => ['Privacy', 'Privacy tools', 'user-secret'],
		'proton' => ['Proton', 'Privacy tools', 'user-secret'],
		'qq' => ['QQ', 'Video & music streaming', 'play'],
		'rakuten_viki' => ['Rakuten Viki', 'Video & music streaming', 'play'],
		'reddit' => ['Reddit', 'Social media', 'users'],
		'riot_games' => ['Riot Games', 'Online gaming', 'gamepad'],
		'roblox' => ['Roblox', 'Online gaming', 'gamepad'],
		'rockstar_games' => ['Rockstar Games', 'Online gaming', 'gamepad'],
		'samsung_tv_plus' => ['Samsung TV Plus', 'Video & music streaming', 'play'],
		'shein' => ['Shein', 'Shopping', 'cart-shopping'],
		'shell_shockers' => ['Shell Shockers', 'Online gaming', 'gamepad'],
		'shopee' => ['Shopee', 'Shopping', 'cart-shopping'],
		'signal' => ['Signal', 'Chat & voice', 'comments'],
		'skype' => ['Skype', 'Chat & voice', 'comments'],
		'slack' => ['Slack', 'Chat & voice', 'comments'],
		'snapchat' => ['Snapchat', 'Social media', 'users'],
		'soundcloud' => ['SoundCloud', 'Video & music streaming', 'play'],
		'spotify' => ['Spotify', 'Video & music streaming', 'play'],
		'spotify_video' => ['Spotify Video', 'Video & music streaming', 'play'],
		'steam' => ['Steam', 'Online gaming', 'gamepad'],
		'telegram' => ['Telegram (Web)', 'Chat & voice', 'comments'],
		'temu' => ['Temu', 'Shopping', 'cart-shopping'],
		'tidal' => ['Tidal', 'Video & music streaming', 'play'],
		'tiktok' => ['TikTok', 'Social media', 'users'],
		'tinder' => ['Tinder', 'Dating', 'heart'],
		'tumblr' => ['Tumblr', 'Social media', 'users'],
		'twitch' => ['Twitch', 'Video & music streaming', 'play'],
		'twitter' => ['X (formerly Twitter)', 'Social media', 'users'],
		'ubisoft' => ['Ubisoft', 'Online gaming', 'gamepad'],
		'valorant' => ['Valorant', 'Online gaming', 'gamepad'],
		'viber' => ['Viber', 'Chat & voice', 'comments'],
		'vimeo' => ['Vimeo', 'Video & music streaming', 'play'],
		'vivo_play' => ['Vivo Play', 'Video & music streaming', 'play'],
		'vk' => ['VK.com', 'Social media', 'users'],
		'voot' => ['Voot', 'Video & music streaming', 'play'],
		'wargaming' => ['Wargaming', 'Online gaming', 'gamepad'],
		'warnerbrosgames' => ['Warner Bros. Games', 'Online gaming', 'gamepad'],
		'wechat' => ['WeChat', 'Chat & voice', 'comments'],
		'weibo' => ['Weibo', 'Video & music streaming', 'play'],
		'whatsapp' => ['WhatsApp', 'Chat & voice', 'comments'],
		'wizz' => ['Wizz', 'Dating', 'heart'],
		'xboxlive' => ['Xbox Live', 'Online gaming', 'gamepad'],
		'xiaohongshu' => ['Xiaohongshu', 'Shopping', 'cart-shopping'],
		'youtube' => ['YouTube', 'Video & music streaming', 'play'],
		'yy' => ['YY', 'Video & music streaming', 'play'],
		'zhihu' => ['Zhihu', 'Social media', 'users'],
	];
}

function threatshield_services_catalog(): array {
	return array_keys(threatshield_services_info());
}

/* A feed record built from a catalog entry. */
function threatshield_feed_from_catalog(string $preset, bool $enabled): ?array {
	$c = threatshield_feed_catalog()[$preset] ?? null;
	if ($c === null) return null;
	return [
		'id' => substr(md5($c['url']), 0, 8), 'name' => $c['name'], 'url' => $c['url'],
		'enabled' => $enabled ? 'on' : 'off', 'category' => $c['category'], 'kind' => $c['kind'], 'preset' => $preset,
	];
}

/* Feeds for a protection level: catalog entries of that level on, custom
 * (non-preset) feeds the user added are kept as they are. */
function threatshield_apply_feed_level(array $feeds, string $level): array {
	$out = [];
	$present = [];
	foreach ($feeds as $feed) {
		if (!is_array($feed)) continue;
		$preset = (string)($feed['preset'] ?? '');
		if ($preset !== '' && isset(threatshield_feed_catalog()[$preset])) {
			$feed['enabled'] = in_array($level, threatshield_feed_catalog()[$preset]['levels'], true) ? 'on' : 'off';
			$present[$preset] = true;
		}
		$out[] = $feed;
	}
	foreach (threatshield_feed_catalog() as $preset => $c) {
		if (!isset($present[$preset]) && in_array($level, $c['levels'], true)) {
			$out[] = threatshield_feed_from_catalog($preset, true);
		}
	}
	return $out;
}

function threatshield_ipfeed_from_catalog(string $preset, bool $enabled): ?array {
	$c = threatshield_ipfeed_catalog()[$preset] ?? null;
	if ($c === null) return null;
	return [
		'id' => $c['id'], 'name' => $c['name'], 'url' => $c['url'],
		'enabled' => $enabled ? 'on' : 'off', 'kind' => $c['kind'], 'direction' => $c['direction'],
		'log' => 'on', 'preset' => $preset,
	];
}

function threatshield_dnsbl_zone_from_catalog(string $preset, bool $enabled): ?array {
	$c = threatshield_dnsbl_zone_catalog()[$preset] ?? null;
	if ($c === null) return null;
	return [
		'id' => $preset, 'name' => $c['name'], 'zone' => $c['zone'], 'access_key' => '',
		'enabled' => $enabled ? 'on' : 'off', 'match' => $c['match'], 'ipv6' => $c['ipv6'], 'preset' => $preset,
	];
}
