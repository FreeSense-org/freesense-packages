<?php
##|+PRIV
##|*IDENT=page-diagnostics-network-tools
##|*NAME=Diagnostics: Network Tools
##|*DESCR=Allow access to the FreeSense network diagnostics suite.
##|*MATCH=diagnostics/network_tools.php*
##|-PRIV

require_once('guiconfig.inc');

$pgtitle = [gettext('Diagnostics'), gettext('Network Tools')];
$pglinks = ['', '@self'];
$input_errors = [];
$output = '';
$exit_code = null;

$tool = $_POST['tool'] ?? 'mtr';
$target = trim($_POST['target'] ?? '');
$port = (int)($_POST['port'] ?? 5201);
$interface = trim($_POST['interface'] ?? '');

function diagnostics_valid_target($target) {
	return filter_var($target, FILTER_VALIDATE_IP) !== false ||
	    preg_match('/^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/D', $target);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['run'])) {
	if (!diagnostics_valid_target($target)) {
		$input_errors[] = gettext('Enter a valid IP address or DNS hostname.');
	}
	if ($port < 1 || $port > 65535) {
		$input_errors[] = gettext('The port must be between 1 and 65535.');
	}

	$commands = [
		'mtr' => ['/usr/local/sbin/mtr', ['--report', '--report-cycles', '5', '--', $target]],
		'nmap' => ['/usr/local/bin/nmap', ['-Pn', '--top-ports', '100', '--', $target]],
		'iperf3' => ['/usr/local/bin/iperf3', ['--client', $target, '--port', (string)$port, '--time', '5']],
	];
	if ($tool === 'arping') {
		if (!preg_match('/^[A-Za-z0-9_.:-]{1,32}$/D', $interface)) {
			$input_errors[] = gettext('Select or enter a valid interface name for ARP probing.');
		} else {
			$commands['arping'] = ['/usr/local/sbin/arping', ['-c', '5', '-i', $interface, '--', $target]];
		}
	}
	if (!isset($commands[$tool])) {
		$input_errors[] = gettext('Unknown diagnostic tool.');
	}

	if (!$input_errors) {
		[$binary, $arguments] = $commands[$tool];
		$command = escapeshellcmd($binary);
		foreach ($arguments as $argument) {
			$command .= ' ' . escapeshellarg($argument);
		}
		$lines = [];
		exec($command . ' 2>&1', $lines, $exit_code);
		$output = implode("\n", array_slice($lines, 0, 2000));
	}
}

include('head.inc');
if ($input_errors) {
	print_input_errors($input_errors);
}
?>
<div class="card mb-3">
	<div class="card-header"><h2 class="h5 mb-0"><?=gettext('Run a diagnostic')?></h2></div>
	<div class="card-body">
		<form method="post">
			<div class="row g-3">
				<div class="col-md-3"><label class="form-label" for="tool"><?=gettext('Tool')?></label><select class="form-select" id="tool" name="tool">
				<?php foreach (['mtr'=>'Route and loss (MTR)','nmap'=>'Top ports (Nmap)','iperf3'=>'Throughput client (iperf3)','arping'=>'Local ARP probe'] as $value=>$label): ?>
				<option value="<?=$value?>" <?=$tool === $value ? 'selected' : ''?>><?=htmlspecialchars(gettext($label))?></option><?php endforeach; ?>
				</select></div>
				<div class="col-md-4"><label class="form-label" for="target"><?=gettext('Target')?></label><input class="form-control" id="target" name="target" required value="<?=htmlspecialchars($target)?>"></div>
				<div class="col-md-2"><label class="form-label" for="port"><?=gettext('iperf3 port')?></label><input class="form-control" type="number" min="1" max="65535" id="port" name="port" value="<?=$port?>"></div>
				<div class="col-md-3"><label class="form-label" for="interface"><?=gettext('ARP interface')?></label><input class="form-control" id="interface" name="interface" value="<?=htmlspecialchars($interface)?>" placeholder="em0"></div>
			</div>
			<button class="btn btn-primary mt-3" type="submit" name="run" value="1"><i class="fa-solid fa-play me-1"></i><?=gettext('Run')?></button>
		</form>
	</div>
</div>
<?php if ($exit_code !== null): ?>
<div class="card"><div class="card-header d-flex justify-content-between"><h2 class="h5 mb-0"><?=gettext('Result')?></h2><span class="badge <?=$exit_code === 0 ? 'text-bg-success' : 'text-bg-danger'?>"><?=gettext('Exit')?> <?=$exit_code?></span></div>
<div class="card-body"><pre class="mb-0" style="max-height:40rem;overflow:auto"><?=htmlspecialchars($output)?></pre></div></div>
<?php endif; include('foot.inc'); ?>
