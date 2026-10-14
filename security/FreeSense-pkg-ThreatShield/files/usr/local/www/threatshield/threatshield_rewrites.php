<?php
/*
 * threatshield_rewrites.php
 * FreeSense Threat Shield - rewrites moved to DNS rules; kept for bookmarks
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

##|+PRIV
##|*IDENT=page-services-threatshield
##|*NAME=Services: Threat Shield Rewrites
##|*DESCR=Configure custom DNS rewrites and local host overrides
##|*MATCH=threatshield/threatshield_rewrites.php*
##|-PRIV

require_once('guiconfig.inc');

header('Location: threatshield_rules.php?view=rewrites', true, 301);
exit;
