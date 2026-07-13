#!/usr/local/bin/php -f
<?php
require_once('config.inc');
require_once('/usr/local/pkg/crowdsec/crowdsec.inc');
if (config_get_path('installedpackages/crowdsec/enable') !== 'on') exit(0);
exec('/usr/local/bin/cscli decisions list -o json 2>/dev/null', $lines, $rc);
if ($rc !== 0) { logger(LOG_ERR, 'CrowdSec decision refresh failed'); exit(1); }
$decoded=json_decode(implode("\n",$lines),true); if (!is_array($decoded)) exit(1);
$addresses=[];
foreach ($decoded as $decision) {
	$value=$decision['value']??$decision['Value']??'';
	if (filter_var($value,FILTER_VALIDATE_IP) || preg_match('#^(?:[0-9A-Fa-f:.]+)/[0-9]{1,3}$#D',$value)) $addresses[$value]=true;
}
$tmp=FREESENSE_CROWDSEC_FILE.'.tmp'; file_put_contents($tmp,implode("\n",array_keys($addresses)).($addresses?"\n":''),LOCK_EX); chmod($tmp,0640); rename($tmp,FREESENSE_CROWDSEC_FILE);
exec('/sbin/pfctl -t '.escapeshellarg(FREESENSE_CROWDSEC_ALIAS).' -T replace -f '.escapeshellarg(FREESENSE_CROWDSEC_FILE).' 2>&1',$out,$pf_rc);
exit($pf_rc);
