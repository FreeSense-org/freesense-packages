<?php
##|+PRIV
##|*IDENT=page-services-crowdsec
##|*NAME=Services: CrowdSec
##|*DESCR=Manage CrowdSec and view decisions.
##|*MATCH=crowdsec/crowdsec.php*
##|*MATCH=crowdsec/crowdsec_decisions.php*
##|-PRIV
require_once('guiconfig.inc'); require_once('/usr/local/pkg/crowdsec/crowdsec.inc');
$pgtitle=[gettext('Services'),gettext('CrowdSec')]; $pglinks=['','@self']; $input_errors=[];
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['save'])) {
	config_set_path('installedpackages/crowdsec/enable',isset($_POST['enable'])?'on':'off');
	write_config(gettext('Updated CrowdSec settings.')); crowdsec_sync_config();
}
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['enroll'])) {
	$token=trim($_POST['token']??'');
	if (!preg_match('/^[A-Za-z0-9._-]{10,512}$/D',$token)) $input_errors[]=gettext('Invalid enrollment token.');
	else { exec('/usr/local/bin/cscli console enroll '.escapeshellarg($token).' 2>&1',$enroll_output,$enroll_rc); if($enroll_rc!==0)$input_errors[]=implode(' ',$enroll_output); }
}
exec('/usr/local/bin/cscli version 2>/dev/null',$version); exec('/usr/local/bin/cscli metrics -o human 2>/dev/null',$metrics,$metrics_rc);
include('head.inc'); if($input_errors)print_input_errors($input_errors);
$tabs=[[gettext('Settings'),true,'/crowdsec/crowdsec.php'],[gettext('Decisions'),false,'/crowdsec/crowdsec_decisions.php']]; display_top_tabs($tabs);
?>
<div class="row g-3 mb-3"><div class="col-md-4"><div class="card h-100"><div class="card-body"><h2 class="h6"><?=gettext('Engine')?></h2><div><?=htmlspecialchars(implode(' ',$version)?:gettext('Unavailable'))?></div></div></div></div><div class="col-md-4"><div class="card h-100"><div class="card-body"><h2 class="h6"><?=gettext('Enforcement')?></h2><div><?=gettext('FreeSense alias')?> <code><?=FREESENSE_CROWDSEC_ALIAS?></code></div></div></div></div></div>
<div class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><?=gettext('Protection')?></h2></div><div class="card-body"><form method="post"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" name="enable" id="enable" <?=config_get_path('installedpackages/crowdsec/enable')==='on'?'checked':''?>><label class="form-check-label" for="enable"><?=gettext('Enable CrowdSec and block active decisions on WAN')?></label></div><button class="btn btn-primary mt-3" name="save" value="1"><?=gettext('Save and apply')?></button></form></div></div>
<div class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><?=gettext('Console enrollment')?></h2></div><div class="card-body"><form method="post" class="row g-2"><div class="col-md-8"><input class="form-control" type="password" name="token" autocomplete="new-password" placeholder="Enrollment token"></div><div class="col"><button class="btn btn-secondary" name="enroll" value="1"><?=gettext('Enroll once')?></button></div></form><div class="form-text"><?=gettext('The token is passed once to cscli and is not stored in FreeSense configuration.')?></div></div></div>
<div class="card"><div class="card-header"><h2 class="h5 mb-0"><?=gettext('Metrics')?></h2></div><div class="card-body"><pre class="mb-0" style="max-height:30rem;overflow:auto"><?=htmlspecialchars(implode("\n",array_slice($metrics,0,500)))?></pre></div></div>
<?php include('foot.inc'); ?>
