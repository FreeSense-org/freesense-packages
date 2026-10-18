/*
 * FreeSense Fleet: the controller's first-run guide. Shows the ports Fleet
 * will open for the connection points chosen, and the review before Switch on.
 */
(function () {
	'use strict';

	var review = document.querySelector('[data-setup-review]');
	if (!review) {
		return;
	}
	var form = review.closest('form');
	var list = form.querySelector('[data-setup-rules]');

	function points() {
		var out = [];
		var tailnet = false;
		form.querySelectorAll('select[name^="points["]').forEach(function (sel) {
			if (sel.value === '') {
				return;
			}
			tailnet = tailnet || (sel.value === 'tailscale');
			var row = sel.closest('tr');
			var port = row.querySelector('input[name$="[port]"]');
			var addr = row.querySelector('input[name$="[address]"]');
			out.push({
				name: sel.options[sel.selectedIndex].textContent.trim(),
				port: port ? port.value.trim() : '',
				address: addr ? (addr.value.trim() || addr.placeholder) : ''
			});
		});
		var ts = form.querySelector('#ts_point, #ts_setup');
		/* A tailnet row in the table is the same connection point: list it once. */
		if (ts && ts.checked && !tailnet) {
			out.push({name: 'Tailscale', port: '8443', address: ''});
		}
		return out;
	}

	function manual() {
		var r = form.querySelector('[name="rules_manual"]:checked');
		return r && r.value === 'on';
	}

	function wg() {
		var el = form.querySelector('#wg_port');
		return el ? el.value.trim() : '';
	}

	function draw() {
		var ps = points();
		if (list) {
			list.textContent = '';
			ps.forEach(function (p) {
				var li = document.createElement('li');
				li.textContent = 'TCP ' + p.port + ' (joining) and UDP ' + wg() + ' (tunnel) on ' + p.name;
				list.appendChild(li);
			});
		}
		var set = function (k, text) {
			var dd = review.querySelector('[data-show="' + k + '"]');
			if (dd) {
				dd.textContent = text || '-';
			}
		};
		set('points', ps.map(function (p) { return p.name + ' :' + p.port + (p.address ? ' (' + p.address + ')' : ''); }).join(', '));
		set('wg_port', wg());
		var r = form.querySelector('[name="rules_manual"]:checked');
		set('rules', r ? r.getAttribute('data-review-text') : '');
		var ts = form.querySelector('#ts_point, #ts_setup');
		set('tailscale', ts && ts.checked ? (ts.id === 'ts_setup' ? 'Yes: set up on this controller, also over Tailscale' : 'Yes, also over Tailscale') : 'No');
		if (list) {
			list.classList.toggle('fs-muted', manual());
		}
	}

	form.addEventListener('change', draw);
	form.addEventListener('input', draw);
	form.addEventListener('fs:step-next', draw);
	draw();
}());

/* Settings sub-sections that only matter while a switch is on (data-fleet-requires="<switch id>"). The fields stay in the form, so saving still sends them. */
(function () {
	'use strict';
	Array.prototype.forEach.call(document.querySelectorAll('[data-fleet-requires]'), function (box) {
		var sw = document.getElementById(box.getAttribute('data-fleet-requires'));
		if (!sw) {
			return;
		}
		var sync = function () {
			box.hidden = !sw.checked;
		};
		sw.addEventListener('change', sync);
		sync();
	});
}());
