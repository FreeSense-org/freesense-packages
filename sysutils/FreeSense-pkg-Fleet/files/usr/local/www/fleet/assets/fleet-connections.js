/*
 * fleet-connections.js: the connection modal shows the interface field
 * only for a direct path, and "as above" only for groups and firewalls
 * (the fleet default has nothing above it).
 */
(function () {
	'use strict';
	var modal = document.getElementById('conn-modal');
	if (!modal) {
		return;
	}
	function sync() {
		var kind = modal.querySelector('input[name=kind]').value;
		var inherit = modal.querySelector('[data-conn-inherit]');
		inherit.hidden = (kind === 'fleet');
		var picked = modal.querySelector('input[name=conn_method]:checked');
		if (!picked) {
			picked = modal.querySelector('input[name=conn_method][value="' + (kind === 'fleet' ? 'wireguard' : '') + '"]');
			picked.checked = true;
		}
		var direct = (picked.value === 'direct') || (picked.value === 'both');
		modal.querySelector('[data-conn-iface]').hidden = !direct;
		modal.querySelector('input[name=conn_iface]').required = direct;
	}
	modal.addEventListener('change', sync);
	modal.addEventListener('show.bs.modal', function () { setTimeout(sync, 0); });
	modal.addEventListener('shown.bs.modal', sync);
})();
