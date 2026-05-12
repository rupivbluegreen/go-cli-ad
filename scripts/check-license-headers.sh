#!/usr/bin/env bash
set -euo pipefail
fail=0
while IFS= read -r f; do
  if ! head -n 14 "$f" | grep -q "Licensed under the Apache License, Version 2.0"; then
    echo "missing license header: $f" >&2
    fail=1
  fi
done < <(find ftsgw -name '*.go' -not -path '*/vendor/*')
exit "$fail"
