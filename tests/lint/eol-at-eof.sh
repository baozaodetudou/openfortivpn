#!/usr/bin/env bash
# Copyright (c) 2015 Adrien Vergé

rc=0

for file in "$@"; do
  # Empty placeholders and binary assets have no text-line ending to check.
  if [ ! -s "$file" ] || ! grep -Iq '' "$file"; then
    continue
  fi

  if [ "$(sed -n '$p' "$file")" = "" ]; then
    echo "$file: too many newlines at end of file" >&2
    rc=1
  fi

  if [ "$(tail -c 1 "$file")" != "" ]; then
    echo "$file: no newline at end of file" >&2
    rc=1
  fi
done

exit $rc
