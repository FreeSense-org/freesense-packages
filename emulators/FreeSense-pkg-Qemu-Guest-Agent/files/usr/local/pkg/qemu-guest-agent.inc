<?php
/*
 * qemu-guest-agent.inc
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2025-2026 The FreeSense Project
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
require_once("service-utils.inc");
require_once("util.inc");

define('LOG_PREFIX_PKG_QEMUGA', 'qemu-guest-agent');
/* The virtio-serial port the host connects the agent to (the VM needs a "virtserialport" of this name). */
define('QEMU_GA_CHANNEL', '/dev/vtcon/org.qemu.guest_agent.0');
define('QEMU_GA_RC', '/usr/local/etc/rc.d/qemu-guest-agent');

function qemu_guest_agent_deinstall() {
	@unlink(QEMU_GA_RC . '.sh');
	mwexec('/usr/sbin/sysrc -x qemu_guest_agent_enable');
}

/*
 * Turn the agent on and start it. rc.start_packages only runs *.sh scripts
 * from rc.d, so the real script gets a .sh link, as the VMware tools do.
 * Without the host's channel the agent cannot run: the package stays on, says
 * so in the log, and starts at the next boot or start once the VM has the channel.
 */
function qemu_guest_agent_install() {
	if (!is_executable(QEMU_GA_RC)) {
		logger(LOG_ERR, localize_text("The QEMU guest agent service script %s is missing", QEMU_GA_RC), LOG_PREFIX_PKG_QEMUGA);
		return;
	}
	mwexec('/usr/sbin/sysrc qemu_guest_agent_enable=YES');
	@unlink(QEMU_GA_RC . '.sh');
	@symlink(QEMU_GA_RC, QEMU_GA_RC . '.sh');
	if (!file_exists(QEMU_GA_CHANNEL)) {
		logger(LOG_WARNING, localize_text("No QEMU guest agent channel (%s): add a virtio-serial port named org.qemu.guest_agent.0 to this virtual machine (Proxmox: Options > QEMU Guest Agent), then start the service", QEMU_GA_CHANNEL), LOG_PREFIX_PKG_QEMUGA);
		return;
	}
	start_service("qemu-guest-agent");
}

?>
