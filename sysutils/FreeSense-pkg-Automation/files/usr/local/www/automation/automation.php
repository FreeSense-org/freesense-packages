<?php
##|+PRIV
##|*IDENT=page-services-automation
##|*NAME=Services: Automation
##|*DESCR=Manage scheduled tasks and service watchdog rules.
##|*MATCH=automation/automation.php*
##|-PRIV
require_once('guiconfig.inc');
require_once('service-utils.inc');
require_once('/usr/local/pkg/automation/automation.inc');

$pgtitle = [gettext('Services'), gettext('Automation')];
$pglinks = ['', '@self'];
$input_errors = [];
$savemsg = '';
$tasks = automation_get_list('tasks');
$watchdog = automation_get_list('watchdog');

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
		automation_set_list('tasks', $tasks);
		automation_set_list('watchdog', $watchdog);
		write_config(gettext('Updated FreeSense automation settings.'));
		automation_sync();
		$savemsg = gettext('The automation settings have been saved.');
	}
}

/* Plain-language reading of the common cron shapes; anything else shows the raw fields only. */
$describe_schedule = function (array $t) {
	$f = [];
	foreach (['minute', 'hour', 'mday', 'month', 'wday'] as $k) {
		$f[$k] = (string)($t[$k] ?? '*');
	}
	$days = [gettext('Sunday'), gettext('Monday'), gettext('Tuesday'), gettext('Wednesday'), gettext('Thursday'), gettext('Friday'), gettext('Saturday'), gettext('Sunday')];
	$num = fn($v) => ctype_digit($v);
	if ($f['mday'] !== '*' || $f['month'] !== '*') {
		return '';
	}
	if ($f['minute'] === '*' && $f['hour'] === '*' && $f['wday'] === '*') {
		return gettext('Every minute');
	}
	if (preg_match('#^\*/([0-9]+)$#', $f['minute'], $m) && $f['hour'] === '*' && $f['wday'] === '*') {
		return sprintf(gettext('Every %d minutes'), $m[1]);
	}
	if ($num($f['minute']) && $f['hour'] === '*' && $f['wday'] === '*') {
		return sprintf(gettext('Hourly at :%02d'), $f['minute']);
	}
	if ($num($f['minute']) && preg_match('#^\*/([0-9]+)$#', $f['hour'], $m) && $f['wday'] === '*') {
		return sprintf(gettext('Every %1$d hours at :%2$02d'), $m[1], $f['minute']);
	}
	if ($num($f['minute']) && $num($f['hour']) && (int)$f['hour'] < 24) {
		$time = sprintf('%02d:%02d', $f['hour'], $f['minute']);
		if ($f['wday'] === '*') {
			return sprintf(gettext('Daily at %s'), $time);
		}
		if ($num($f['wday']) && (int)$f['wday'] <= 7) {
			return sprintf(gettext('%1$s at %2$s'), $days[(int)$f['wday']], $time);
		}
		if ($f['wday'] === '1-5') {
			return sprintf(gettext('Weekdays at %s'), $time);
		}
	}
	return '';
};

/* Registered services, for the watchdog suggestions and descriptions. */
$services = [];
foreach (get_services() as $svc) {
	if (!empty($svc['name']) && preg_match('/^[A-Za-z0-9_.-]{1,64}$/D', $svc['name'])) {
		$services[$svc['name']] = $svc['description'] ?? '';
	}
}
ksort($services);

$enabled_count = count(array_filter($tasks, fn($t) => ($t['enabled'] ?? '') === 'on'));
$watch_rows = [];
$stopped_count = 0;
foreach ($watchdog as $i => $entry) {
	$name = (string)($entry['service'] ?? '');
	$known = array_key_exists($name, $services);
	$running = $known && is_service_running($name);
	if ($known && !$running) {
		$stopped_count++;
	}
	$watch_rows[$i] = ['name' => $name, 'known' => $known, 'running' => $running, 'descr' => $services[$name] ?? ''];
}

/* After a failed save, reopen the modal the user was filling in, with what was posted. */
$posted_action = ($_SERVER['REQUEST_METHOD'] === 'POST' && $input_errors) ? ($_POST['action'] ?? '') : '';
$reopen_task = null;
if ($posted_action === 'add_task') {
	$reopen_task = ['enabled' => isset($_POST['enabled'])];
	foreach (['name', 'command', 'minute', 'hour', 'mday', 'month', 'wday'] as $k) {
		$reopen_task[$k] = (string)($_POST[$k] ?? '');
	}
}
$reopen_watch = ($posted_action === 'add_watchdog') ? ['service' => (string)($_POST['service'] ?? '')] : null;

fs_page_action(gettext('Add task'), '#', 'fa-plus', 'primary', ['data-fs-modal' => '#automation-task']);
fs_page_action(gettext('Watch service'), '#', 'fa-heart-pulse', 'secondary', ['data-fs-modal' => '#automation-watch']);

include('head.inc');
if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}
print_callout(gettext('Automation commands run as root. Only add commands from trusted, absolute paths.'), 'warning');
?>
<style>
.fs-auto-sub { display: block; font-size: var(--fs-fs-xs); color: var(--fs-text-muted); }
.fs-auto-cmd { word-break: break-all; }
.fs-auto-cron { white-space: nowrap; }
.fs-auto-schedule { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: .5rem; }
.fs-auto-schedule label { font-size: var(--fs-fs-xs); color: var(--fs-text-muted); margin-bottom: .2rem; }
</style>

<div class="fs-tiles">
<?php
fs_tile(gettext('Scheduled tasks'), count($tasks));
fs_tile(gettext('Enabled'), $enabled_count, null, (count($tasks) - $enabled_count) ? sprintf(gettext('%d disabled'), count($tasks) - $enabled_count) : null);
fs_tile(gettext('Watched services'), count($watchdog), null, gettext('Checked every 5 minutes'));
if (!empty($watchdog)) {
	fs_tile(gettext('Stopped now'), $stopped_count, $stopped_count ? 'down' : null, gettext('Restarted on the next check'));
}
?>
</div>

<div class="panel panel-default fs-table" data-fs-table="automation-tasks">
<?php fs_table_toolbar([
	'title' => gettext('Scheduled tasks'),
	'search' => (count($tasks) > 5) ? gettext('Search tasks…') : false,
	'noun' => gettext('tasks'),
	'noun_one' => gettext('task'),
	'filters' => (count($tasks) > 5) ? ['state' => [gettext('All states'), 'enabled' => gettext('Enabled'), 'disabled' => gettext('Disabled')]] : [],
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th class="fs-col-status"><?=gettext('Status')?></th>
					<th data-fs-search><?=gettext('Task')?></th>
					<th data-fs-search><?=gettext('Schedule')?></th>
					<th data-fs-search><?=gettext('Command')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($tasks as $i => $task):
	$on = ($task['enabled'] ?? '') === 'on';
	$cron = "{$task['minute']} {$task['hour']} {$task['mday']} {$task['month']} {$task['wday']}";
	$human = $describe_schedule($task);
?>
				<tr data-fs-filter-state="<?=$on ? 'enabled' : 'disabled'?>"<?=$on ? '' : ' class="fs-row-disabled"'?>>
					<td><?=$on ? fs_badge('enabled') : fs_badge('disabled')?></td>
					<td><strong><?=htmlspecialchars($task['name'])?></strong></td>
					<td data-value="<?=htmlspecialchars($cron)?>">
						<span class="fs-mono fs-auto-cron"><?=htmlspecialchars($cron)?></span>
<?php if ($human !== ''): ?>
						<span class="fs-auto-sub"><?=htmlspecialchars($human)?></span>
<?php endif; ?>
					</td>
					<td class="fs-mono fs-auto-cmd"><?=htmlspecialchars($task['command'])?></td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['delete', 'automation.php?action=delete_task&index=' . (int)$i, (string)$task['name'], ['thing' => gettext('task'),
						    'detail' => gettext('Its cron entry is removed right away.')]],
					])?></td>
				</tr>
<?php endforeach; ?>
<?php if (empty($tasks)) {
	fs_empty_row(5, gettext('No scheduled tasks yet.'));
} ?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer fs-muted"><?=gettext('Schedules use cron fields: minute, hour, day of month, month and weekday (0 or 7 = Sunday).')?></div>
</div>

<div class="panel panel-default fs-table" data-fs-table="automation-watchdog">
<?php fs_table_toolbar([
	'title' => gettext('Service watchdog'),
	'search' => false,
	'noun' => gettext('services'),
	'noun_one' => gettext('service'),
]); ?>
	<div class="panel-body table-responsive">
		<table class="table table-hover" data-sortable>
			<thead>
				<tr>
					<th class="fs-col-status"><?=gettext('Status')?></th>
					<th><?=gettext('Service')?></th>
					<th><?=gettext('Description')?></th>
					<th class="fs-col-actions"><span class="visually-hidden"><?=gettext('Actions')?></span></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($watch_rows as $i => $w): ?>
				<tr>
					<td><?=!$w['known'] ? fs_badge('unknown', gettext('Not found'), gettext('No registered service has this name')) : ($w['running'] ? fs_badge('up', gettext('Running')) : fs_badge('down', gettext('Stopped')))?></td>
					<td class="fs-mono"><?=htmlspecialchars($w['name'])?></td>
					<td><?=($w['descr'] !== '') ? htmlspecialchars($w['descr']) : '<span class="fs-muted">—</span>'?></td>
					<td class="fs-col-actions"><?=fs_row_actions([
						['delete', 'automation.php?action=delete_watchdog&index=' . (int)$i, $w['name'], ['thing' => gettext('watchdog for'),
						    'detail' => gettext('The service is no longer restarted automatically.')]],
					])?></td>
				</tr>
<?php endforeach; ?>
<?php if (empty($watchdog)) {
	fs_empty_row(4, gettext('No services are watched.'));
} ?>
			</tbody>
		</table>
	</div>
	<div class="panel-footer fs-muted"><?=gettext('Every 5 minutes, a watched service that is not running is restarted and a warning is logged.')?></div>
</div>

<?php
fs_modal_form_begin('automation-task', gettext('Add task'), '', ['action' => 'add_task'], $reopen_task);
?>
	<div class="mb-3">
		<label class="form-label" for="automation-name"><?=gettext('Task name')?></label>
		<input class="form-control" id="automation-name" name="name" required>
	</div>
	<div class="mb-3">
		<label class="form-label" for="automation-command"><?=gettext('Command')?></label>
		<input class="form-control fs-mono" id="automation-command" name="command" required placeholder="/usr/local/bin/example --safe-flag">
		<div class="form-text"><?=gettext('An absolute path under /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin or /usr/local/pkg. No shell operators.')?></div>
	</div>
	<fieldset class="mb-3">
		<legend class="form-label fs-6"><?=gettext('Schedule')?></legend>
		<div class="fs-auto-schedule">
<?php foreach (['minute' => gettext('Minute'), 'hour' => gettext('Hour'), 'mday' => gettext('Day'), 'month' => gettext('Month'), 'wday' => gettext('Weekday')] as $field => $label): ?>
			<div>
				<label class="form-label" for="automation-<?=$field?>"><?=htmlspecialchars($label)?></label>
				<input class="form-control fs-mono" id="automation-<?=$field?>" name="<?=$field?>" required value="*" title="<?=htmlspecialchars($label)?>">
			</div>
<?php endforeach; ?>
		</div>
		<div class="form-text"><?=gettext('Each field takes *, */5, 1-5 or 1,15. Example: 30 2 * * * runs daily at 02:30.')?></div>
	</fieldset>
	<div class="form-check">
		<input class="form-check-input" type="checkbox" name="enabled" id="enabled" checked>
		<label class="form-check-label" for="enabled"><?=gettext('Enabled')?></label>
	</div>
<?php
fs_modal_form_end(gettext('Add task'), '', '', 'fa-plus');

fs_modal_form_begin('automation-watch', gettext('Watch service'), '', ['action' => 'add_watchdog'], $reopen_watch);
?>
	<div class="mb-3">
		<label class="form-label" for="automation-service"><?=gettext('Service name')?></label>
		<input class="form-control fs-mono" id="automation-service" name="service" required list="automation-services" placeholder="<?=gettext('Registered service name')?>" autocomplete="off">
		<datalist id="automation-services">
<?php foreach ($services as $name => $descr): ?>
			<option value="<?=htmlspecialchars($name)?>"><?=htmlspecialchars($descr)?></option>
<?php endforeach; ?>
		</datalist>
		<div class="form-text"><?=gettext('The name as listed under Status > Services, e.g. unbound or ntpd.')?></div>
	</div>
<?php
fs_modal_form_end(gettext('Watch service'), '', '', 'fa-heart-pulse');

include('foot.inc');
?>
