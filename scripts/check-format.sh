#!/usr/bin/env bash
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Find code files.
CODE_FILES=()
while IFS=  read -r -d $'\0'; do
  CODE_FILES+=("$REPLY")
done < <(find . -not \( -path '*/target' -prune \) -and -name '*.rs' -print0)

# Find markdown files.
MD_FILES=()
while IFS=  read -r -d $'\0'; do
  MD_FILES+=("$REPLY")
done < <(find . -not \( -path '*/target' -prune \) -and -not \( -path '*/wycheproof' -prune \) -and -name '*.md' -print0)

# Check that source files have the Apache License header.
# Automatically skips generated files.
check_license() {
  local path="$1"

  if head -1 "$path" | grep -iq -e 'generated' -e '::prost::message'; then
    return 0
  fi

  if echo "$path" | grep -q "/proto/"; then
    return 0
  fi

  # Look for "Apache License" on the file header
  if ! head -10 "$path" | grep -q 'Apache License'; then
    # Format: $path:$line:$message
    echo "$path:1:license header not found"
    return 1
  fi
  return 0
}

# Check that any TODO markers in files have associated issue numbers
check_todo() {
  local path="$1"
  local result
  result=$(grep --with-filename --line-number TODO "$path" | grep --invert-match --regexp='TODO(#[0-9][0-9]*)')
  if [[ -n $result ]]; then
    echo "TODO marker without issue number:"
    echo "$result"
    return 1
  fi
  return 0
}

# Check that any calls that might panic have a comment noting why they're safe
check_panic() {
  local path="$1"
  if [[ $path =~ "test" || $path =~ "examples/" || $path =~ "rinkey/" || $path =~ "benches/" ]]; then
    return 0
  fi
  for needle in "panic!(" "unwrap(" "expect(" "unwrap_err(" "expect_err(" "unwrap_none(" "expect_none(" "unreachable!"; do
    local result
    result=$(grep --with-filename --line-number "$needle" "$path" | grep --invert-match --regexp='safe:'| grep --invert-match --regexp=':[0-9]*://')
    if [[ -n $result ]]; then
      echo "Un-annotated panic code:"
      echo "$result"
      return 1
    fi
  done
  return 0
}

errcount=0
for f in "${CODE_FILES[@]}"; do
  check_license "$f"
  errcount=$((errcount + $?))
  check_todo "$f"
  errcount=$((errcount + $?))
  check_panic "$f"
  errcount=$((errcount + $?))
done

EMBEDMD="$(go env GOPATH)/bin/embedmd"
if [[ ! -x "$EMBEDMD" ]]; then
  go install github.com/campoy/embedmd@97c13d6
fi
for f in "${MD_FILES[@]}"; do
  "$EMBEDMD" -d "$f"
  errcount=$((errcount + $?))
  check_todo "$f"
  errcount=$((errcount + $?))
  mdl "$f"
  errcount=$((errcount + $?))
done

if [ $errcount -gt 0 ]; then
  echo "$errcount errors detected"
  exit 1
fi
