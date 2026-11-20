<?php
/* Fleet controller tests: controller init. Loaded by ../run.php (shares its variables). */

fleet_controller_init();
check(is_file("{$data}/master.key") && (fileperms("{$data}/master.key") & 0077) === 0 && strlen(fleet_master_key()) === 32, 'a private master key');
$fp = fleet_cert_fingerprint(fleet_tls_pem());
check(preg_match('/^[0-9a-f]{64}$/D', $fp) === 1, 'an enrollment certificate');
fleet_controller_init();
check(fleet_cert_fingerprint(fleet_tls_pem()) === $fp, 'init is idempotent: the pinned certificate never changes');
check(strpos(fleet_signing_public(), 'BEGIN PUBLIC KEY') !== false, 'a signing key');
