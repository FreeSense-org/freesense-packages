<?php
##|+PRIV
##|*IDENT=page-services-crowdsec
##|*NAME=Services: CrowdSec
##|*DESCR=Manage CrowdSec and view decisions.
##|*MATCH=crowdsec/crowdsec.php*
##|*MATCH=crowdsec/crowdsec_decisions.php*
##|-PRIV
require_once('guiconfig.inc'); require_once('/usr/local/pkg/crowdsec/crowdsec.inc');
$pgtitle=[gettext('Services'),gettext('CrowdSec'),gettext('Overview')]; $pglinks=['','/crowdsec/crowdsec.php','@self']; $input_errors=[]; $savemsg=null;
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['save'])) {
	config_set_path('installedpackages/crowdsec/enable',isset($_POST['enable'])?'on':'off');
	write_config(gettext('Updated CrowdSec settings.')); crowdsec_sync_config();
	$savemsg=gettext('CrowdSec settings saved and applied.');
}
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['enroll'])) {
	$token=trim($_POST['token']??'');
	if (!preg_match('/^[A-Za-z0-9._-]{10,512}$/D',$token)) $input_errors[]=gettext('Invalid enrollment token.');
	else { exec('/usr/local/bin/cscli console enroll '.escapeshellarg($token).' 2>&1',$enroll_output,$enroll_rc); if($enroll_rc!==0)$input_errors[]=implode(' ',$enroll_output); else $savemsg=gettext('Enrollment requested. Accept the engine in the CrowdSec console to finish.'); }
}

$enabled = config_get_path('installedpackages/crowdsec/enable') === 'on';
$running = is_process_running('crowdsec');
exec('/usr/local/bin/cscli version 2>/dev/null', $version);
/* cscli metrics needs the local API; crowdsec_cscli() only runs it while CrowdSec runs, with a timeout */
$metrics = [];
crowdsec_cscli('metrics -o human 2>/dev/null', $metrics, $metrics_rc);
$decisions = $running ? crowdsec_decisions() : null;

/* "version: v1.7.8-freebsd-..." is the first line of cscli version */
$engine = '';
foreach ($version as $line) {
	if (preg_match('/^\s*version:\s*(\S+)/i', $line, $m)) { $engine = $m[1]; break; }
}
if ($engine === '' && !empty($version)) $engine = trim((string)$version[0]);

fs_page_action(gettext('Enroll in console'), '#', 'fa-link', 'secondary', ['data-fs-modal' => '#crowdsec-enroll']);

include('head.inc');
if ($input_errors) print_input_errors($input_errors);
if ($savemsg) print_info_box($savemsg, 'success');
$tabs=[[gettext('Overview'),true,'/crowdsec/crowdsec.php'],[gettext('Decisions'),false,'/crowdsec/crowdsec_decisions.php']]; display_top_tabs($tabs);

if ($enabled && !$running) {
	print_callout(gettext('CrowdSec is enabled but not running. Start it from Status > Services or check its log.'), 'warning');
}

fs_summary_card([
	'icon' => 'fa-people-group',
	'title' => 'CrowdSec',
	'subtitle' => gettext('Collaborative intrusion detection; blocks addresses with an active decision'),
	'badges' => [
		$enabled ? fs_badge('enabled') : fs_badge('disabled'),
		$running ? fs_badge('up', gettext('Running')) : fs_badge($enabled ? 'down' : 'neutral', gettext('Stopped')),
	],
	'label' => gettext('CrowdSec summary'),
	'facts' => [
		[gettext('Engine'), $engine, 'mono' => true, 'empty' => gettext('Unavailable')],
		[gettext('Enforcement'), gettext('Block on WAN'), 'note' => sprintf(gettext('Alias %s'), FREESENSE_CROWDSEC_ALIAS)],
		[gettext('Active decisions'), ($decisions === null) ? '' : (string)count($decisions), 'href' => 'crowdsec_decisions.php',
		    'empty' => $running ? gettext('Could not be read') : gettext('Not running')],
	],
	'actions' => [[gettext('Decisions'), 'crowdsec_decisions.php', 'fa-gavel']],
]);

$form = new Form();
$section = new Form_Section('Protection');
$section->addInput(new Form_Checkbox('enable', 'Enable', 'Enable CrowdSec and block active decisions on WAN', $enabled, 'on'))
	->setHelp(sprintf(gettext('Adds a WAN block rule for the alias %s, which is refreshed every minute from the active decisions.'), FREESENSE_CROWDSEC_ALIAS));
$form->add($section);
print($form);
?>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext('Metrics')?></h2>
<?php if (!empty($metrics)): ?>
		<button type="button" class="btn btn-sm btn-outline-secondary" data-fs-copy="#crowdsec-metrics">
			<i class="fa-regular fa-copy icon-embed-btn" aria-hidden="true"></i><?=gettext('Copy')?>
		</button>
<?php endif; ?>
	</div>
<?php if (!empty($metrics)): ?>
	<pre class="fs-console" id="crowdsec-metrics"><?=htmlspecialchars(implode("\n", array_slice($metrics, 0, 500)))?></pre>
<?php else: ?>
	<div class="fs-tool-empty">
		<i class="fa-solid fa-chart-column" aria-hidden="true"></i>
		<span><?=$running ? gettext('CrowdSec returned no metrics yet.') : gettext('Metrics are shown while CrowdSec is running.')?></span>
	</div>
<?php endif; ?>
</div>

<?php
fs_modal_form_begin('crowdsec-enroll', gettext('Enroll in the CrowdSec console'), '', [], ($input_errors && isset($_POST['enroll'])) ? ['token' => ''] : null);
?>
	<p><?=gettext('Links this engine to your account at app.crowdsec.net, so its alerts and decisions show up there.')?></p>
	<div class="mb-3">
		<label class="form-label" for="token"><?=gettext('Enrollment token')?></label>
		<input class="form-control fs-mono" type="password" id="token" name="token" autocomplete="new-password" required>
		<div class="form-text"><?=gettext('The token is passed once to cscli and is not stored in the FreeSense configuration.')?></div>
	</div>
<?php
fs_modal_form_end(gettext('Enroll'), 'enroll', '1', 'fa-link');
?>

<?php include('foot.inc'); ?>
