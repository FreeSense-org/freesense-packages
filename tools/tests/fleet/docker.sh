#!/bin/sh
# Runs the Fleet controller tests (and the PHP lint) in the php:8.5-cli image, as
# CI does. No local PHP is needed.
# Run from anywhere: sh tools/tests/fleet/docker.sh <path to the freesense checkout>
# MSYS_NO_PATHCONV keeps Git Bash on Windows from rewriting the container paths.

src=${1:?usage: docker.sh <path to the freesense checkout>}
repo=$(cd "$(dirname "$0")/../../.." && pwd)
export MSYS_NO_PATHCONV=1
docker run --rm -v "$repo:/work/pkgs:ro" -v "$src:/work/freesense:ro" -w /work/pkgs php:8.5-cli sh -c '
	sh tools/tests/php-lint.sh &&
	php -d error_reporting=E_ALL tools/tests/fleet/run.php /work/freesense'
