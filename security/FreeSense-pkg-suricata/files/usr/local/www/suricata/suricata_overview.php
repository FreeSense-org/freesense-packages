<?php
require_once('guiconfig.inc');
require_once('/usr/local/pkg/suricata/suricata.inc');

$pgtitle=[gettext('Services'),gettext('Suricata'),gettext('Overview')];
$pglinks=['','@self','@self'];
$input_errors=[];
$interfaces=config_get_path('installedpackages/suricata/rule',[]);

if($_SERVER['REQUEST_METHOD']==='POST'&&isset($_POST['action'],$_POST['uuid'])){
	$selected=null;
	foreach($interfaces as $entry) if((string)($entry['uuid']??'')===(string)$_POST['uuid']){$selected=$entry;break;}
	if(!$selected)$input_errors[]=gettext('The selected Suricata interface no longer exists.');
	else{
		$real=get_real_interface($selected['interface']);
		switch($_POST['action']){
			case 'start': suricata_generate_yaml($selected);suricata_start($selected,$real);break;
			case 'restart': suricata_generate_yaml($selected);suricata_stop($selected,$real);suricata_start($selected,$real);break;
			case 'stop': suricata_stop($selected,$real);break;
			case 'validate': $path=SURICATADIR."suricata_{$selected['uuid']}_{$real}/suricata.yaml";if(!suricata_validate_config_file($path,$validation_output))$input_errors[]=$validation_output;else{@file_put_contents("{$path}.validated",date(DATE_ATOM)." Suricata ".SURICATA_BIN_VERSION."\n",LOCK_EX);$savemsg=gettext('The active Suricata configuration is valid.');}break;
		}
	}
}

$running=0;$enabled=0;
foreach($interfaces as $entry){$real=get_real_interface($entry['interface']??'');if(($entry['enable']??'')==='on')$enabled++;if($real&&suricata_is_running($entry['uuid'],$real))$running++;}
$rules_mtime=0;foreach(glob(SURICATADIR.'rules/*.rules')?:[] as $file)$rules_mtime=max($rules_mtime,filemtime($file));
include('head.inc');if($input_errors)print_input_errors($input_errors);if(!empty($savemsg))print_info_box($savemsg,'success');suricata_display_primary_navigation('overview');
?>
<div class="row g-3 mb-3">
<div class="col-md-3"><div class="card h-100"><div class="card-body"><div class="text-body-secondary"><?=gettext('Engine')?></div><div class="fs-4 fw-semibold"><?=htmlspecialchars(SURICATA_BIN_VERSION)?></div><div class="small"><?=gettext('Integration')?> <?=htmlspecialchars(SURICATA_PKG_VER)?></div></div></div></div>
<div class="col-md-3"><div class="card h-100"><div class="card-body"><div class="text-body-secondary"><?=gettext('Interfaces')?></div><div class="fs-4 fw-semibold"><?=$running?> / <?=$enabled?></div><div class="small"><?=gettext('running / enabled')?></div></div></div></div>
<div class="col-md-3"><div class="card h-100"><div class="card-body"><div class="text-body-secondary"><?=gettext('Rules')?></div><div class="fs-5 fw-semibold"><?=$rules_mtime?htmlspecialchars(date('Y-m-d H:i',$rules_mtime)):gettext('Not downloaded')?></div><div class="small"><?=gettext('last local change')?></div></div></div></div>
<div class="col-md-3"><div class="card h-100"><div class="card-body"><div class="text-body-secondary"><?=gettext('Mode')?></div><div class="fs-5 fw-semibold"><?=gettext('Suricata 8')?></div><div class="small"><?=gettext('FreeBSD netmap IPS supported per interface')?></div></div></div></div>
</div>
<div class="card"><div class="card-header d-flex justify-content-between align-items-center"><h2 class="h5 mb-0"><?=gettext('Interface health')?></h2><a class="btn btn-primary btn-sm" href="/suricata/suricata_interfaces_edit.php?id=<?=count($interfaces)?>"><i class="fa-solid fa-plus me-1"></i><?=gettext('Add interface')?></a></div><div class="card-body table-responsive"><table class="table table-hover align-middle"><thead><tr><th><?=gettext('Interface')?></th><th><?=gettext('Mode')?></th><th><?=gettext('Status')?></th><th><?=gettext('Configuration')?></th><th><?=gettext('Actions')?></th></tr></thead><tbody>
<?php foreach($interfaces as $entry):$real=get_real_interface($entry['interface']??'');$is_running=$real&&suricata_is_running($entry['uuid'],$real);$config_path=SURICATADIR."suricata_{$entry['uuid']}_{$real}/suricata.yaml";$validation_marker="{$config_path}.validated";$valid=is_file($config_path)&&is_file($validation_marker)&&filemtime($validation_marker)>=filemtime($config_path);?>
<tr><td><strong><?=htmlspecialchars($entry['descr']??$entry['interface'])?></strong><br><code><?=htmlspecialchars($real)?></code></td><td><?=($entry['ips_mode']??'')==='ips_mode_inline'?'<span class="badge text-bg-warning">IPS inline</span>':'<span class="badge text-bg-info">IDS</span>'?></td><td><span class="badge <?=$is_running?'text-bg-success':'text-bg-secondary'?>"><?=$is_running?gettext('Running'):gettext('Stopped')?></span></td><td><span class="badge <?=$valid?'text-bg-success':'text-bg-danger'?>"><?=$valid?gettext('Valid'):gettext('Invalid or missing')?></span></td><td><div class="btn-group"><a class="btn btn-outline-primary btn-sm" href="/suricata/suricata_interfaces_edit.php?id=<?=array_search($entry,$interfaces,true)?>"><?=gettext('Configure')?></a><form method="post" class="d-inline"><input type="hidden" name="uuid" value="<?=htmlspecialchars($entry['uuid'])?>"><button class="btn btn-outline-secondary btn-sm" name="action" value="<?=$is_running?'restart':'start'?>"><?=$is_running?gettext('Restart'):gettext('Start')?></button><?php if($is_running):?><button class="btn btn-outline-danger btn-sm" name="action" value="stop"><?=gettext('Stop')?></button><?php endif;?><button class="btn btn-outline-secondary btn-sm" name="action" value="validate"><?=gettext('Validate')?></button></form></div></td></tr>
<?php endforeach;?></tbody></table><?php if(!$interfaces):?><div class="text-center text-body-secondary py-4"><?=gettext('No Suricata interfaces are configured.')?></div><?php endif;?></div></div>
<?php include('foot.inc');?>
