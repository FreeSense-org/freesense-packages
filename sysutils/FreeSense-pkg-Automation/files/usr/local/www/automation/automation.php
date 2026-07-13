<?php
##|+PRIV
##|*IDENT=page-services-automation
##|*NAME=Services: Automation
##|*DESCR=Manage scheduled tasks and service watchdog rules.
##|*MATCH=automation/automation.php*
##|-PRIV
require_once('guiconfig.inc');
require_once('/usr/local/pkg/automation/automation.inc');

$pgtitle = [gettext('Services'), gettext('Automation')];
$pglinks = ['', '@self'];
$input_errors = [];
$tasks = config_get_path('installedpackages/automation/tasks', []);
$watchdog = config_get_path('installedpackages/automation/watchdog', []);

function automation_valid_schedule_field($value) {
	return preg_match('/^(?:\*|\*\/[1-9][0-9]*|[0-9]+(?:-[0-9]+)?(?:,[0-9]+)*)$/D', $value);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$action = $_POST['action'] ?? '';
	if ($action === 'add_task') {
		$task = ['name'=>trim($_POST['name'] ?? ''),'command'=>trim($_POST['command'] ?? ''),'minute'=>trim($_POST['minute'] ?? ''),'hour'=>trim($_POST['hour'] ?? ''),'mday'=>trim($_POST['mday'] ?? ''),'month'=>trim($_POST['month'] ?? ''),'wday'=>trim($_POST['wday'] ?? ''),'enabled'=>isset($_POST['enabled'])?'on':'off'];
		foreach (['minute','hour','mday','month','wday'] as $field) if (!automation_valid_schedule_field($task[$field])) $input_errors[] = sprintf(gettext('Invalid %s schedule field.'), $field);
		if (!preg_match('#^/(?:usr/)?(?:local/)?(?:s?bin|pkg)/[^\r\n;&|`$<>]+#D', $task['command'])) $input_errors[] = gettext('Commands must use an absolute executable path and may not contain shell control operators.');
		if ($task['name'] === '') $input_errors[] = gettext('A task name is required.');
		if (!$input_errors) $tasks[] = $task;
	} elseif ($action === 'delete_task' && ctype_digit((string)($_POST['index'] ?? ''))) {
		unset($tasks[(int)$_POST['index']]); $tasks = array_values($tasks);
	} elseif ($action === 'add_watchdog') {
		$service = trim($_POST['service'] ?? '');
		if (!preg_match('/^[A-Za-z0-9_.-]{1,64}$/D', $service)) $input_errors[] = gettext('Enter a valid registered service name.'); else $watchdog[] = ['service'=>$service];
	} elseif ($action === 'delete_watchdog' && ctype_digit((string)($_POST['index'] ?? ''))) {
		unset($watchdog[(int)$_POST['index']]); $watchdog = array_values($watchdog);
	}
	if (!$input_errors) {
		config_set_path('installedpackages/automation/tasks', $tasks);
		config_set_path('installedpackages/automation/watchdog', $watchdog);
		write_config(gettext('Updated FreeSense automation settings.'));
		automation_sync();
	}
}

include('head.inc'); if ($input_errors) print_input_errors($input_errors);
print_info_box(gettext('Automation commands run as root. Only add commands from trusted, absolute paths.'), 'warning');
?>
<div class="card mb-3"><div class="card-header"><h2 class="h5 mb-0"><?=gettext('Scheduled tasks')?></h2></div><div class="card-body table-responsive">
<table class="table table-hover align-middle"><thead><tr><th><?=gettext('Task')?></th><th><?=gettext('Schedule')?></th><th><?=gettext('Command')?></th><th></th></tr></thead><tbody>
<?php foreach ($tasks as $i=>$task): ?><tr><td><?=htmlspecialchars($task['name'])?> <?=$task['enabled']==='on'?'<span class="badge text-bg-success">Enabled</span>':'<span class="badge text-bg-secondary">Disabled</span>'?></td><td><code><?=htmlspecialchars("{$task['minute']} {$task['hour']} {$task['mday']} {$task['month']} {$task['wday']}")?></code></td><td><code><?=htmlspecialchars($task['command'])?></code></td><td><form method="post"><input type="hidden" name="action" value="delete_task"><input type="hidden" name="index" value="<?=$i?>"><button class="btn btn-danger btn-sm" type="submit"><?=gettext('Delete')?></button></form></td></tr><?php endforeach; ?>
</tbody></table><hr><form method="post"><input type="hidden" name="action" value="add_task"><div class="row g-2"><div class="col-md-2"><input class="form-control" name="name" required placeholder="Task name"></div><div class="col-md-4"><input class="form-control" name="command" required placeholder="/usr/local/bin/example --safe-flag"></div><?php foreach(['minute'=>'Minute','hour'=>'Hour','mday'=>'Day','month'=>'Month','wday'=>'Weekday'] as $field=>$label): ?><div class="col"><input class="form-control" name="<?=$field?>" required value="*" title="<?=$label?>"></div><?php endforeach; ?></div><div class="form-check mt-2"><input class="form-check-input" type="checkbox" name="enabled" id="enabled" checked><label class="form-check-label" for="enabled"><?=gettext('Enabled')?></label></div><button class="btn btn-primary mt-2" type="submit"><?=gettext('Add task')?></button></form></div></div>
<div class="card"><div class="card-header"><h2 class="h5 mb-0"><?=gettext('Service watchdog')?></h2></div><div class="card-body"><div class="d-flex flex-wrap gap-2 mb-3"><?php foreach($watchdog as $i=>$entry): ?><form method="post"><input type="hidden" name="action" value="delete_watchdog"><input type="hidden" name="index" value="<?=$i?>"><button class="btn btn-outline-secondary btn-sm" type="submit"><?=htmlspecialchars($entry['service'])?> ×</button></form><?php endforeach; ?></div><form method="post" class="row g-2"><input type="hidden" name="action" value="add_watchdog"><div class="col-md-5"><input class="form-control" name="service" required placeholder="Registered service name"></div><div class="col"><button class="btn btn-primary" type="submit"><?=gettext('Monitor service')?></button></div></form></div></div>
<?php include('foot.inc'); ?>
