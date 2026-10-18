<?php
/*
 * fleet_setup_view.inc
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
 * The controller's first-run guide, step by step, inside the Controller
 * settings form of fleet.php (which includes it): switch on, where firewalls
 * connect, firewall rules, Tailscale, review, then the finish.
 */

$setup_steps = array('on' => gettext('Switch on'), 'where' => gettext('Where firewalls connect'), 'rules' => gettext('Firewall rules'),
    'tailscale' => gettext('Tailscale'), 'review' => gettext('Review'));

if ($setup_done):
	fs_stepper($setup_steps + array('done' => gettext('Done')), 'done', array(), gettext('Set up this controller'));
?>
	<div class="fs-fleet-setup-done">
		<h3 class="h5"><i class="fa-solid fa-circle-check" aria-hidden="true"></i> <?=gettext('This firewall is now a FreeSense Fleet controller')?></h3>
		<p><?=gettext('Fleet runs, its ports are open on the connection points you chose, and Settings > Self-check shows whether firewalls can reach it.')?></p>
		<p class="mb-0"><a class="btn btn-primary" href="/fleet/fleet.php?view=invite&amp;add=1"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add your first firewall')?></a>
			<a class="btn btn-outline-secondary" href="/fleet/fleet.php?tab=settings&amp;view=selfcheck"><?=gettext('Self-check')?></a>
			<a class="btn btn-link" href="/fleet/fleet.php?tab=settings&amp;view=controller"><?=gettext('All controller settings')?></a></p>
	</div>
<?php
	return;
endif;

list($setup_ts_problems, $setup_ts_addr) = fleet_ts_join_ready();
?>
	<input type="hidden" name="setup_guide" value="1"/>
<?php if ($setup_again): ?>
	<div class="fs-fleet-note"><?=gettext('This controller already runs. The guide starts from its current settings and saves them when you select Apply.')?>
		<a href="?tab=settings&amp;view=controller"><?=gettext('Back to the settings')?></a></div>
<?php endif; ?>
<?php
fs_steps_begin($setup_steps, null, gettext('Set up this controller'));

fs_step_begin('on', gettext('A Fleet controller watches and manages other FreeSense firewalls: status, backups, updates, policies and more.'));
?>
	<ul class="fs-fleet-steps">
		<li><?=gettext('Firewalls start the connection to this controller, so they may sit behind NAT. Only this controller must be reachable.')?></li>
		<li><?=gettext('Each firewall joins with a one-time invitation and is approved here with a 6-digit code.')?></li>
		<li><?=gettext('Nothing changes on this firewall until you select Switch on at the end.')?></li>
	</ul>
	<div class="form-check form-switch mt-3">
		<input class="form-check-input" type="checkbox" role="switch" id="enable" name="enable" checked required/>
		<label class="form-check-label" for="enable"><?=gettext('Run this firewall as a FreeSense Fleet controller')?></label>
	</div>
<?php
fs_step_end();

fs_step_begin('where', gettext('Choose the interfaces firewalls reach this controller on: WAN for firewalls on the internet (they join, then keep a WireGuard tunnel), LAN or another internal interface for firewalls on your own networks (they can then be reached directly, without the internet). The address is found by itself.'));
$points_table($rows);
?>
	<div class="fs-fleet-field"><label class="form-label" for="wg_port"><?=gettext('Tunnel port (UDP)')?></label>
		<input class="form-control fs-mono" id="wg_port" name="wg_port" inputmode="numeric" value="<?=(int)$s['wg_port']?>" style="max-width:9rem" required pattern="[0-9]{1,5}"/>
		<div class="fs-fleet-hint"><?=gettext('One for every connection point: the Fleet tunnel (WireGuard) listens on a single port.')?></div></div>
<?php
fs_step_end();

fs_step_begin('rules', gettext('Firewalls must reach the ports you chose. Fleet can open them for you.'));
?>
	<fieldset class="fs-fleet-ways"><legend class="visually-hidden"><?=gettext('Firewall rules')?></legend>
		<label class="fs-fleet-way"><input class="form-check-input" type="radio" name="rules_manual" value=""<?=$s['rules_manual'] ? '' : ' checked'?> data-review-text="<?=gettext('Fleet opens and closes them (locked rules)')?>"/>
			<span><strong><?=gettext('Fleet opens the ports')?></strong> <?=fs_badge('pass', gettext('Recommended'))?>
				<span class="fs-fleet-hint d-block"><?=gettext('Locked rules under Firewall > Rules > Floating, changed only here. Removed when you remove a connection point or switch Fleet off.')?></span></span></label>
		<label class="fs-fleet-way"><input class="form-check-input" type="radio" name="rules_manual" value="on"<?=$s['rules_manual'] ? ' checked' : ''?> data-review-text="<?=gettext('I open them myself')?>"/>
			<span><strong><?=gettext('I open them myself')?></strong>
				<span class="fs-fleet-hint d-block"><?=gettext('Fleet adds no rules. Self-check tests the ports from outside afterwards.')?></span></span></label>
	</fieldset>
	<p class="form-label mt-3 mb-1"><?=gettext('The ports')?></p>
	<ul class="fs-fleet-steps" data-setup-rules></ul>
<?php
fs_step_end();

fs_step_begin('tailscale', gettext('Optional. Firewalls in your tailnet can join without any public port.'));
?>
<?php if (empty($setup_ts_problems)): ?>
	<p><?=fs_badge('pass', gettext('Ready'))?> <?=sprintf(gettext('This firewall is in a tailnet at %s.'), '<span class="fs-mono">' . htmlspecialchars($setup_ts_addr) . '</span>')?></p>
	<div class="form-check">
		<input class="form-check-input" type="checkbox" id="ts_point" name="ts_point" value="1"<?=in_array('tailscale', array_column($rows, 'iface'), true) ? ' checked' : ''?>/>
		<label class="form-check-label" for="ts_point"><?=gettext('Firewalls may also connect over Tailscale')?></label>
	</div>
<?php else: ?>
	<p><?=fs_badge('neutral', gettext('Not set up'))?> <?=htmlspecialchars(implode(' ', array_map('gettext', $setup_ts_problems)))?></p>
	<div class="form-check">
		<input class="form-check-input" type="checkbox" id="ts_setup" name="ts_setup" value="1"/>
		<label class="form-check-label" for="ts_setup"><?=gettext('Set it up for me')?></label>
		<div class="fs-fleet-hint"><?=gettext('Fleet installs the Tailscale package on this controller if it is missing, logs it in with a one-time key and adds Tailscale as a connection point. This needs internet and can take a few minutes after you select Switch on.')?></div>
	</div>
	<div class="fs-fleet-field" data-fleet-requires="ts_setup">
<?php if (fleet_ts_token() === null): ?>
		<label class="form-label" for="ts_api_token"><?=gettext('Tailscale API access token')?></label>
		<input class="form-control fs-mono" id="ts_api_token" name="ts_api_token" type="password" autocomplete="off" maxlength="220" placeholder="tskey-api-..."/>
		<div class="fs-fleet-hint"><?=gettext('Make one in the Tailscale admin console under Settings > Keys (access token). Fleet keeps it sealed and uses it to make a one-time key for this controller and for each new firewall.')?></div>
<?php else: ?>
		<div class="fs-fleet-hint"><?=gettext('The Tailscale API token Fleet already has is used.')?></div>
<?php endif; ?>
	</div>
	<p class="fs-fleet-hint"><?=gettext('Or skip it: Tailscale can be set up later with Settings > Controller > Run the setup guide.')?></p>
<?php endif; ?>
<?php
fs_step_end();

fs_step_begin('review', gettext('This is what Switch on does.'));
?>
	<dl class="fs-fleet-tset" data-setup-review>
		<dt><?=gettext('Firewalls connect on')?></dt><dd data-show="points">-</dd>
		<dt><?=gettext('Tunnel port (UDP)')?></dt><dd data-show="wg_port">-</dd>
		<dt><?=gettext('Firewall rules')?></dt><dd data-show="rules">-</dd>
		<dt><?=gettext('Tailscale')?></dt><dd data-show="tailscale"><?=gettext('No')?></dd>
	</dl>
	<p class="mt-3 mb-0"><button class="btn btn-primary" type="submit" name="save_settings" value="1" data-fs-step-submit>
		<i class="fa-solid fa-power-off icon-embed-btn" aria-hidden="true"></i><?=$setup_again ? gettext('Apply') : gettext('Switch on')?></button></p>
<?php
fs_step_end();
fs_steps_end();
