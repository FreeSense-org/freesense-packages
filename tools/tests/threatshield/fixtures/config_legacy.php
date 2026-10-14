<?php
/* A configuration as Threat Shield 1.0.0_6 saved it (documentation addresses only). */
return [
	'enable' => 'on',
	'dns_coordination_mode' => 'primary',
	'listen_port' => '53',
	'interfaces' => ['item' => ['all']],
	'catch_rogue_dns' => 'on',
	'dns_intercept_interfaces' => ['item' => ['lan']],
	'upstreams' => "https://dns.quad9.net/dns-query\r\nhttps://cloudflare-dns.com/dns-query",
	'feeds' => ['item' => [
		['name' => 'AdGuard DNS Filter', 'url' => 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt', 'enabled' => 'on', 'category' => 'Ads & Tracking'],
		['name' => 'My list', 'url' => 'https://lists.example.org/block.txt', 'enabled' => 'off', 'category' => 'Custom'],
	]],
	'custom_rules' => "! bank login breaks\n@@||bank.example^\n||tracker.example^\n@@|exact.example^\n@@||regex.example^\$client=192.0.2.5\n@@||bank.example^",
	'geoip_enable' => 'on',
	'geoip_mode' => 'whitelist_inbound',
	'geoip_countries' => ['item' => ['DK', 'SE']],
	'clients' => ['item' => [['name' => 'Kids', 'ids' => ['item' => ['192.0.2.20']], 'filtering' => 'inherit', 'blocked_services' => ['item' => ['tiktok']]]]],
	'_unbound_state' => ['managed' => 'on', 'port' => '53', 'active_interface' => 'all', 'enable' => 'on', 'custom_options' => ''],
];
