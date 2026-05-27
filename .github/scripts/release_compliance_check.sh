#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

fail() {
  echo "release-compliance: $1" >&2
  exit 1
}

required_docs=(
  "README.md"
  "docs/ARCHITECTURAL_GUIDE.md"
  "docs/USER_GUIDE.md"
  "docs/VERIFICATION_GUIDE.md"
)

for path in "${required_docs[@]}"; do
  [ -f "$path" ] || fail "missing required doc: $path"
done

grep -RIn --include='*.md' 'file:///' . && fail "found forbidden file:/// links in markdown"

grep -q '^APP_VERSION_NAME=' gradle.properties || fail "missing APP_VERSION_NAME in gradle.properties"
grep -q '^APP_BASE_VERSION_CODE=' gradle.properties || fail "missing APP_BASE_VERSION_CODE in gradle.properties"

grep -q "findProperty('APP_VERSION_NAME')" app/build.gradle || fail "app/build.gradle must resolve APP_VERSION_NAME from gradle.properties"
grep -q "findProperty('APP_BASE_VERSION_CODE')" app/build.gradle || fail "app/build.gradle must resolve APP_BASE_VERSION_CODE from gradle.properties"

echo "release-compliance: OK"

