/*
 * WireGuardHelpers.js
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2021 R. Christian McDonald (https://github.com/rcmcdonald91)
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

function wgRegTrimHandler() {
	$('body').on('change', '.trim', function () {
		$(this).val($(this).val().replace(/\s/g, ''));
	});
}

/* Copy buttons: <button class="wg-copy" data-wg-copy="text"> */
function wgRegCopyHandler() {
	$('body').on('click', '[data-wg-copy]', function (e) {
		e.preventDefault();
		var btn = this;
		var text = btn.getAttribute('data-wg-copy');
		var done = function () {
			btn.classList.add('is-done');
			setTimeout(function () {
				btn.classList.remove('is-done');
			}, 1500);
		};

		if (navigator.clipboard && window.isSecureContext) {
			navigator.clipboard.writeText(text).then(done);
			return;
		}

		var tmp = document.createElement('textarea');
		tmp.value = text;
		tmp.setAttribute('readonly', '');
		tmp.style.position = 'fixed';
		tmp.style.opacity = '0';
		document.body.appendChild(tmp);
		tmp.select();
		try {
			document.execCommand('copy');
			done();
		} catch (err) {
			console.warn('Copy failed');
		}
		document.body.removeChild(tmp);
	});
}

/*
 * Nested rows: a child row (tr[data-wg-parent="<id>"]) follows its parent row
 * when search or a filter hides it; [data-wg-toggle] buttons show / hide the
 * element named by aria-controls.
 */
function wgRegNestedRows(root) {
	root = root || document;

	root.querySelectorAll('tr[data-wg-parent]').forEach(function (child) {
		var parent = document.getElementById(child.getAttribute('data-wg-parent'));
		if (!parent) {
			return;
		}
		var sync = function () {
			child.hidden = parent.hidden;
		};
		new MutationObserver(sync).observe(parent, {attributes: true, attributeFilter: ['hidden']});
		sync();
	});

	root.querySelectorAll('[data-wg-toggle]').forEach(function (btn) {
		btn.addEventListener('click', function () {
			var open = btn.getAttribute('aria-expanded') !== 'true';
			btn.setAttribute('aria-expanded', open ? 'true' : 'false');
			var target = document.getElementById(btn.getAttribute('aria-controls'));
			if (target) {
				target.hidden = !open;
			}
		});
	});
}
