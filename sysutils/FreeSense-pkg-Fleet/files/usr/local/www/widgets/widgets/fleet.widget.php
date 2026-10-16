<?php
/*
 * fleet.widget.php
 *
 * part of FreeSense (https://freesense.org)
 * Copyright (c) 2025-2026 FreeSense
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The FreeSense Fleet dashboard widget: health tiles, the firewalls that
 * need attention, availability over 24 hours, and the controller with its
 * standby. The parts, a group to focus on and the number of rows are the
 * widget's settings. The logic is in fleet_widget.inc.
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/fleet.inc");
require_once("/usr/local/www/widgets/include/fleet.inc");

/* $widgetkey comes from the Dashboard, or from the request when saving or refreshing. */
if ($_POST['widgetkey'] || $_GET['widgetkey']) {
	$rwidgetkey = isset($_POST['widgetkey']) ? $_POST['widgetkey'] : (isset($_GET['widgetkey']) ? $_GET['widgetkey'] : null);
	if (is_valid_widgetkey($rwidgetkey, $user_settings, __FILE__)) {
		$widgetkey = $rwidgetkey;
	} else {
		print gettext("Invalid Widget Key");
		exit;
	}
}

$fleet_cfg = fleet_widget_cfg((array)($user_settings['widgets'][$widgetkey] ?? array()));

/* The refresh: only the body. */
if ($_REQUEST['ajax'] ?? false) {
	print(fleet_widget_html(fleet_widget_data($fleet_cfg), $fleet_cfg));
	exit;
}

/* Saving the settings. */
if ($_POST['widgetkey'] ?? false) {
	set_customwidgettitle($user_settings);
	$k = $_POST['widgetkey'];
	if (!is_array($user_settings['widgets'][$k] ?? null)) {
		$user_settings['widgets'][$k] = array();
	}
	$user_settings['widgets'][$k]['fleet_parts'] = implode(',', array_intersect(array_keys(FLEET_WIDGET_PARTS), (array)($_POST['fleet_parts'] ?? array())));
	$user_settings['widgets'][$k]['fleet_group'] = (string)max(0, (int)($_POST['fleet_group'] ?? 0));
	$user_settings['widgets'][$k]['fleet_rows'] = (string)(in_array((int)($_POST['fleet_rows'] ?? 5), FLEET_WIDGET_ROWS, true) ? (int)$_POST['fleet_rows'] : 5);
	save_widget_settings($_SESSION['Username'], $user_settings['widgets'], gettext("Updated FreeSense Fleet widget settings via dashboard."));
	header("Location: /");
	exit(0);
}

$fleet_body_id = $widgetkey . '-fleet';
$fleet_groups = (fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db')) ? fleet_groups_all() : array();
?>
<link rel="stylesheet" href="/fleet/assets/fleet.css?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet.css')?>"/>
<div class="fs-fleet-widget" id="<?=htmlspecialchars($fleet_body_id)?>">
<?=fleet_widget_html(fleet_widget_data($fleet_cfg), $fleet_cfg)?>
</div>
<!-- close the body we're wrapped in and add a configuration-panel -->
</div><div id="<?=$widget_panel_footer_id?>" class="panel-footer collapse">
<form action="/widgets/widgets/fleet.widget.php" method="post" class="form-horizontal">
	<input type="hidden" name="widgetkey" value="<?=htmlspecialchars($widgetkey)?>"/>
	<?=gen_customwidgettitle_div($widgetconfig['title']); ?>
	<div class="form-group">
		<label class="col-sm-4 control-label"><?=gettext('Show')?></label>
		<div class="col-sm-8">
<?php foreach (FLEET_WIDGET_PARTS as $part => $label): ?>
			<label class="form-check"><input class="form-check-input" type="checkbox" name="fleet_parts[]" value="<?=$part?>"<?=in_array($part, $fleet_cfg['parts'], true) ? ' checked' : ''?>/> <span class="form-check-label"><?=htmlspecialchars(gettext($label))?></span></label>
<?php endforeach; ?>
		</div>
	</div>
	<div class="form-group">
		<label class="col-sm-4 control-label" for="<?=htmlspecialchars($widgetkey)?>-fleet-group"><?=gettext('Firewalls')?></label>
		<div class="col-sm-8">
			<select class="form-select" id="<?=htmlspecialchars($widgetkey)?>-fleet-group" name="fleet_group">
				<option value="0"><?=gettext('All firewalls')?></option>
<?php foreach ($fleet_groups as $fleet_grp): ?>
				<option value="<?=(int)$fleet_grp['id']?>"<?=((int)$fleet_grp['id'] === $fleet_cfg['group']) ? ' selected' : ''?>><?=htmlspecialchars(sprintf(gettext('Group %s'), $fleet_grp['name']))?></option>
<?php endforeach; ?>
			</select>
		</div>
	</div>
	<div class="form-group">
		<label class="col-sm-4 control-label" for="<?=htmlspecialchars($widgetkey)?>-fleet-rows"><?=gettext('List at most')?></label>
		<div class="col-sm-8">
			<select class="form-select" id="<?=htmlspecialchars($widgetkey)?>-fleet-rows" name="fleet_rows">
<?php foreach (FLEET_WIDGET_ROWS as $n): ?>
				<option value="<?=$n?>"<?=($n === $fleet_cfg['rows']) ? ' selected' : ''?>><?=htmlspecialchars(sprintf(gettext('%d firewalls'), $n))?></option>
<?php endforeach; ?>
			</select>
		</div>
	</div>
	<div class="form-group">
		<div class="col-sm-offset-4 col-sm-8">
			<button type="submit" class="btn btn-primary"><i class="fa-solid fa-floppy-disk icon-embed-btn" aria-hidden="true"></i><?=gettext('Save')?></button>
		</div>
	</div>
</form>

<script>
//<![CDATA[
events.push(function() {
	/* Refresh the widget body every 30 seconds through the Dashboard's refresh system. */
	var fleetObject = new Object();
	fleetObject.name = "FreeSense Fleet";
	fleetObject.url = "/widgets/widgets/fleet.widget.php";
	fleetObject.callback = function(s) {
		$(<?=json_encode('#' . $fleet_body_id)?>).html(s);
	};
	fleetObject.parms = {ajax: "ajax", widgetkey: <?=json_encode($widgetkey)?>};
	fleetObject.freq = 30;
	register_ajax(fleetObject);
});
//]]>
</script>
