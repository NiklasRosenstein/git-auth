#!/bin/bash
source /etc/profile
source /etc/bashrc
if [ -e "~/.bashrc" ]; then
  source "~/.bashrc"
fi
if [ -e "~/.bash_profile" ]; then
  source "~/.bash_profile"
fi
python3 "$(dirname ${BASH_SOURCE})/git-auth.py" $*
