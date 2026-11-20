#!/bin/sh
# Syntax-checks every PHP file of the repository with the php on PATH (CI and
# local runs use the php:8.5-cli image): *.php and *.inc, plus the extensionless
# scripts under usr/local/sbin that start with a PHP shebang (the Fleet cron and
# runner scripts, for example). Prints each failing file and exits 1 if any fail.
# Run from the repository root: sh tools/tests/php-lint.sh

fail=0
list=$(mktemp)
find . -type f \( -name '*.php' -o -name '*.inc' \) ! -path './freesense-src/*' ! -path './.git/*' > "$list"
find . -type f -path '*/usr/local/sbin/*' ! -name '*.*' ! -path './freesense-src/*' ! -path './.git/*' |
	while read -r f; do
		if head -n 1 "$f" | grep -q '^#!.*php'; then
			echo "$f"
		fi
	done >> "$list"
count=0
while read -r f; do
	count=$((count + 1))
	if ! out=$(php -l "$f" 2>&1); then
		echo "$out"
		fail=1
	fi
done < "$list"
rm -f "$list"
echo "php-lint: $count files checked with $(php -r 'echo PHP_VERSION;')"
exit "$fail"
