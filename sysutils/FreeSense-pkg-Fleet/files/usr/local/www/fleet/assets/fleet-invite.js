/*
 * FreeSense Fleet: the Add a firewall guide (a step-by-step modal). The
 * internal network is asked only for Direct, and the review step shows what
 * was chosen before anything is made.
 */
(function () {
	'use strict';

	var modal = document.getElementById('invite-modal');
	if (!modal) {
		return;
	}
	var form = modal.querySelector('form');
	var direct = modal.querySelector('[data-fleet-direct]');

	function chosen(name) {
		var els = form.querySelectorAll('[name="' + name + '"]');
		for (var i = 0; i < els.length; i++) {
			var el = els[i];
			if (el.type === 'radio') {
				if (el.checked) {
					return el.getAttribute('data-review-text') || el.value;
				}
			} else if (el.tagName === 'SELECT') {
				return el.value === '' ? '' : el.options[el.selectedIndex].textContent.trim();
			} else {
				return el.value.trim();
			}
		}
		return '';
	}

	function value(name) {
		var el = form.querySelector('[name="' + name + '"]:checked') || form.querySelector('[name="' + name + '"]');
		return el ? el.value : '';
	}

	var pubip = modal.querySelector('[data-fleet-public-ip]');

	/* The internal network is asked only for Direct; the expected public address does not apply to Tailscale. */
	function directShown() {
		if (direct) {
			direct.hidden = value('via') !== 'direct';
			direct.querySelectorAll('select').forEach(function (s) { s.disabled = direct.hidden; });
		}
		if (pubip) {
			pubip.hidden = value('via') === 'tailscale';
			pubip.querySelectorAll('input').forEach(function (i) { i.disabled = pubip.hidden; });
		}
	}

	function review() {
		var set = function (k, text) {
			var dd = modal.querySelector('[data-show="' + k + '"]');
			if (dd) {
				dd.textContent = text || '-';
			}
		};
		set('label', chosen('label'));
		set('role', chosen('role'));
		set('naming_group', value('naming_group') === '0' ? '' : chosen('naming_group'));
		set('site_host', [chosen('site'), chosen('hostname')].filter(Boolean).join(' / '));
		set('via', chosen('via') + (value('via') === 'direct' ? ' (' + chosen('via_iface') + ')' : ''));
		set('hours', chosen('hours'));
		set('public_ip', chosen('public_ip'));
		modal.querySelectorAll('[data-review-public-ip]').forEach(function (el) { el.hidden = value('via') === 'tailscale'; });
	}

	form.addEventListener('change', function (e) {
		if (e.target.name === 'via') {
			directShown();
		}
	});
	/* Fill the review on every step change, and when the modal opens on it after an error. */
	modal.addEventListener('fs:step-next', review);
	modal.addEventListener('shown.bs.modal', function () {
		directShown();
		review();
	});
	directShown();
	review();
}());
