<?php
/* A router for "php -S": records every request body in the file named by the SINK_FILE environment variable (alert delivery tests). */
file_put_contents((string)getenv('SINK_FILE'), file_get_contents('php://input') . "\n", FILE_APPEND | LOCK_EX);
http_response_code(200);
echo 'ok';
