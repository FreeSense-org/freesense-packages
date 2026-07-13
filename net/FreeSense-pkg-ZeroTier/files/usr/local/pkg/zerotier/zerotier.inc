<?php
function zerotier_cli_json(array $arguments, &$error = null) {
	$command='/usr/local/bin/zerotier-cli -j';
	foreach($arguments as $argument) $command.=' '.escapeshellarg($argument);
	exec($command.' 2>&1',$lines,$rc);
	if($rc!==0){$error=implode("\n",$lines);return null;}
	$data=json_decode(implode("\n",$lines),true);
	if(json_last_error()!==JSON_ERROR_NONE){$error='ZeroTier returned invalid JSON.';return null;}
	return $data;
}

function zerotier_valid_network_id($id) { return preg_match('/^[0-9a-fA-F]{16}$/D',$id); }

function zerotier_set_network_option($network,$option,$enabled,&$error=null) {
	$allowed=['allowManaged','allowGlobal','allowDefault','allowDNS'];
	if(!zerotier_valid_network_id($network)||!in_array($option,$allowed,true)){ $error='Invalid ZeroTier option.'; return false; }
	$command='/usr/local/bin/zerotier-cli set '.escapeshellarg($network).' '.escapeshellarg($option.'='.($enabled?'1':'0'));
	exec($command.' 2>&1',$out,$rc); if($rc!==0)$error=implode("\n",$out); return $rc===0;
}
