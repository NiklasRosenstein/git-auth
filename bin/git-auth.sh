#!/bin/bash
source /etc/profile
source /etc/bashrc
if [ -e "~/.bashrc" ]; then
  source "~/.bashrc"
fi
if [ -e "~/.bash_profile" ]; then
  source "~/.bash_profile"
fi
DIRNAME=$(dirname ${BASH_SOURCE})
export PYTHONPATH="$DIRNAME/..":$PYTHONPATH
python3 "$DIRNAME/git-auth.py" $*
