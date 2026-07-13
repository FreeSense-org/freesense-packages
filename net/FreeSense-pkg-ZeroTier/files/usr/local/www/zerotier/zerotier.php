<?php
##|+PRIV
##|*IDENT=page-vpn-zerotier
##|*NAME=VPN: ZeroTier
##|*DESCR=Manage ZeroTier networks and peers.
##|*MATCH=zerotier/zerotier.php*
##|*MATCH=zerotier/zerotier_peers.php*
##|-PRIV
require_once('guiconfig.inc'); require_once('/usr/local/pkg/zerotier/zerotier.inc');
$pgtitle=[gettext('VPN'),gettext('ZeroTier')];$pglinks=['','@self'];$input_errors=[];
if($_SERVER['REQUEST_METHOD']==='POST'){
	$id=strtolower(trim($_POST['network']??''));
	if(isset($_POST['join'])){if(!zerotier_valid_network_id($id))$input_errors[]=gettext('Network ID must be 16 hexadecimal characters.');else zerotier_cli_json(['join',$id],$cli_error);}
	elseif(isset($_POST['leave'])){if(zerotier_valid_network_id($id))zerotier_cli_json(['leave',$id],$cli_error);}
	elseif(isset($_POST['apply'])){if(!zerotier_valid_network_id($id))$input_errors[]=gettext('Invalid network ID.');else foreach(['allowManaged','allowGlobal','allowDefault','allowDNS'] as $option)zerotier_set_network_option($id,$option,isset($_POST[$option]),$cli_error);}
	if(!empty($cli_error))$input_errors[]=$cli_error;
}
$info=zerotier_cli_json(['info'],$error)?:[];$networks=zerotier_cli_json(['listnetworks'],$network_error)?:[];
include('head.inc');if($input_errors)print_input_errors($input_errors);$tabs=[[gettext('Networks'),true,'/zerotier/zerotier.php'],[gettext('Peers'),false,'/zerotier/zerotier_peers.php']];display_top_tabs($tabs);
?>
<div class="row g-3 mb-3"><div class="col-md-4"><div class="card h-100"><div class="card-body"><h2 class="h6"><?=gettext('Node ID')?></h2><code><?=htmlspecialchars($info['address']??gettext('Unavailable'))?></code></div></div></div><div class="col-md-4"><div class="card h-100"><div class="card-body"><h2 class="h6"><?=gettext('Status')?></h2><span class="badge <?=($info['online']??false)?'text-bg-success':'text-bg-danger'?>"><?=($info['online']??false)?gettext('Online'):gettext('Offline')?></span></div></div></div><div class="col-md-4"><div class="card h-100"><div class="card-body"><h2 class="h6"><?=gettext('Version')?></h2><?=htmlspecialchars($info['version']??'—')?></div></div></div></div>
<div class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><?=gettext('Networks')?></h2></div><div class="card-body table-responsive"><table class="table table-hover align-middle"><thead><tr><th><?=gettext('Network')?></th><th><?=gettext('Status')?></th><th><?=gettext('Interface')?></th><th><?=gettext('Addresses')?></th><th><?=gettext('Route consent')?></th><th></th></tr></thead><tbody>
<?php foreach($networks as $network):$id=$network['nwid']??'';?><tr><td><strong><?=htmlspecialchars($network['name']??gettext('Unnamed'))?></strong><br><code><?=htmlspecialchars($id)?></code></td><td><?=htmlspecialchars($network['status']??'')?></td><td><code><?=htmlspecialchars($network['portDeviceName']??'')?></code><br><a href="/interfaces_assign.php"><?=gettext('Assign interface')?></a></td><td><?=htmlspecialchars(implode(', ',$network['assignedAddresses']??[]))?></td><td><form method="post"><input type="hidden" name="network" value="<?=htmlspecialchars($id)?>"><?php foreach(['allowManaged'=>'Managed','allowGlobal'=>'Global','allowDefault'=>'Default route','allowDNS'=>'DNS'] as $option=>$label):?><div class="form-check"><input class="form-check-input" type="checkbox" name="<?=$option?>" id="<?=$option.$id?>" <?=!empty($network[$option])?'checked':''?>><label class="form-check-label" for="<?=$option.$id?>"><?=gettext($label)?></label></div><?php endforeach;?><button class="btn btn-primary btn-sm mt-1" name="apply" value="1"><?=gettext('Apply consent')?></button></form></td><td><form method="post"><input type="hidden" name="network" value="<?=htmlspecialchars($id)?>"><button class="btn btn-danger btn-sm" name="leave" value="1"><?=gettext('Leave')?></button></form></td></tr><?php endforeach;?></tbody></table></div></div>
<div class="card"><div class="card-header"><h2 class="h5 mb-0"><?=gettext('Join network')?></h2></div><div class="card-body"><form method="post" class="row g-2"><div class="col-md-6"><input class="form-control font-monospace" name="network" maxlength="16" required placeholder="16-character network ID"></div><div class="col"><button class="btn btn-primary" name="join" value="1"><?=gettext('Join')?></button></div></form><div class="form-text"><?=gettext('Managed routes, global routes, default routes, and DNS remain disabled until explicitly accepted above.')?></div></div></div>
<?php include('foot.inc');?>
