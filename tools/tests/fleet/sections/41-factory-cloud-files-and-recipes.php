<?php
/* Fleet controller tests: Factory: cloud files and recipes. Loaded by ../run.php (shares its variables). */

$fmr = array('site' => 'cph', 'label' => 'Copenhagen', 'serial' => '', 'instance_id' => '', 'domain' => 'shops.example', 'hostname' => 'cph-fw01');
$fmseed = array('version' => 1, 'link' => 'https://fleet.example:8443/fleet/join#x', 'mode' => 'unattended', 'key' => 'FLT-X');
$fmc = fleet_factory_cloud_files($fmr, 'cph-fw01', 'cph-fw01', $fmseed);
$fmud = json_decode(substr($fmc['user-data'], strlen("#cloud-config\n")), true);
check((strpos($fmc['user-data'], "#cloud-config\n") === 0) && ($fmud['freesense']['fleet'] === $fmseed) && ($fmud['fqdn'] === 'cph-fw01.shops.example') &&
    (strpos($fmc['meta-data'], "instance-id: fleet-cph-fw01\n") === 0) &&
    (strpos(fleet_factory_cloud_files(array('instance_id' => 'i-abc') + $fmr, 'x', '', $fmseed)['meta-data'], 'instance-id: i-abc') === 0),
    'cloud-init for each firewall: the seed under freesense.fleet, its name, and the instance id it is bound to');
$fmrec = fleet_factory_recipes(array('name' => 'Spring'), array('cph-fw01' => array('name' => 'cph-fw01', 'instance_id' => 'fleet-cph-fw01')));
check((strpos($fmrec['proxmox-qm.sh'], 'local:iso/cph-fw01-cidata.iso') !== false) && (strpos($fmrec['virt-install.sh'], "'cph-fw01-cidata.iso',device=cdrom") !== false) &&
    (strpos($fmrec['terraform/main.tf'], 'local:iso/${each.value.cidata_iso}') !== false) &&
    (json_decode($fmrec['terraform/instances.auto.tfvars.json'], true)['firewalls']['cph-fw01']['instance_id'] === 'fleet-cph-fw01'),
    'the batch recipes make one VM per firewall with its own cidata.iso (qm, virt-install, Terraform)');
