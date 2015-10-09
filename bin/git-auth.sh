#!/bin/bash
_source_if_exists() {
  if [ -e "$1" ]; then
    . "$1"
  fi
}
_source_if_exists /etc/profile
_source_if_exists /etc/bashrc
_source_if_exists "~/.bashrc"
_source_if_exists "~/.bash_profile"
DIRNAME=$(dirname ${BASH_SOURCE})
export PYTHONPATH="$DIRNAME/..":$PYTHONPATH
python3 "$DIRNAME/git-auth.py" $*
