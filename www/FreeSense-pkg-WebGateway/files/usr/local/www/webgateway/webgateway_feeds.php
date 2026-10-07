<?php
/* FreeSense Web Gateway 2.0: native threat/category feeds. */
require_once('guiconfig.inc');require_once('webgateway.inc');
$wg_config=webgateway_config();$pconfig=$wg_config;$input_errors=[];$savemsg=null;
if($_POST&&isset($_POST['update_now'])){if(webgateway_update_feeds($message))$savemsg=$message;else $input_errors[]=$message;}
elseif($_POST){$pconfig=array_merge($wg_config,$_POST);$pconfig['feeds_enable']=isset($_POST['feeds_enable'])?'on':'';$pconfig['feed_urls']=webgateway_encode_list($_POST['feed_urls_text']??'');if(webgateway_save_candidate($pconfig,gettext('Web Gateway feed settings changed'),$input_errors)){$savemsg=gettext('Feed settings saved and applied. Use Update now to compile the first domain database into Squid policy.');$wg_config=$pconfig=webgateway_config();}}
$status=webgateway_feed_status();
$pgtitle=[gettext('Services'),gettext('Web Gateway'),gettext('Feeds')];
$pglinks=['', '/webgateway/webgateway.php', '@self'];
include('head.inc');webgateway_display_tabs('feeds');if($input_errors)print_input_errors($input_errors);if($savemsg)print_info_box($savemsg,'success');
?>
<div class="fs-tiles">
<?php
fs_tile(gettext('Scheduled updates'), ($wg_config['feeds_enable'] === 'on') ? sprintf(gettext('Every %s h'), $wg_config['feed_interval']) : gettext('Off'));
fs_tile(gettext('Compiled entries'), number_format($status['entries'] ?? 0));
fs_tile(gettext('Sources'), number_format($status['sources'] ?? 0), null, sprintf(gettext('%d configured'), count(webgateway_lines($wg_config['feed_urls']))));
fs_tile(gettext('Last successful update'), isset($status['updated']) ? date('Y-m-d H:i', $status['updated']) : gettext('Never'));
?>
</div>
<?php
$form = new Form(gettext('Save and apply'));
$update = new Form_Button('update_now', gettext('Update now'), null, 'fa-solid fa-arrows-rotate');
$update->addClass('btn-outline-secondary');
$form->addGlobal($update);

$section = new Form_Section(gettext('Policy feeds'), 'wg-feeds');
$section->addInput(new Form_Checkbox('feeds_enable', gettext('Scheduled updates'), gettext('Enable scheduled feed updates'), $pconfig['feeds_enable'] === 'on', 'on'))
	->setHelp(gettext('An hourly FreeSense scheduler checks the interval below. Update now compiles the feeds immediately.'));
$section->addInput(new Form_Textarea('feed_urls_text', gettext('HTTPS feed URLs'), webgateway_decode_list($pconfig['feed_urls'])))
	->setRows(7)
	->addClass('fs-mono')
	->setAttribute('placeholder', 'https://provider.example/domains.txt')
	->setHelp(gettext('One URL per line. Plain domain or hosts-format feeds are normalized and deduplicated. Downloads are staged and the last-known-good database stays active after any failure.'));
$group = new Form_Group(gettext('Limits'));
$group->add(new Form_Input('feed_interval', gettext('Interval'), 'number', $pconfig['feed_interval'], ['min' => 1, 'max' => 720]))
	->setHelp(gettext('Interval (hours)'));
$group->add(new Form_Input('feed_max_mb', gettext('Maximum download'), 'number', $pconfig['feed_max_mb'], ['min' => 1, 'max' => 1024]))
	->setHelp(gettext('Maximum download (MiB)'));
$group->add(new Form_Input('feed_max_entries', gettext('Maximum entries'), 'number', $pconfig['feed_max_entries'], ['min' => 1, 'max' => 5000000]))
	->setHelp(gettext('Maximum entries'));
$section->add($group);
$form->add($section);

print($form);

print_callout(htmlspecialchars(gettext('FreeSense does not silently bundle third-party blocklists. Review each provider’s licensing, privacy terms and false-positive process before adding it.')), 'warning');
include('foot.inc');
