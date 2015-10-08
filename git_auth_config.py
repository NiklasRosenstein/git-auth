# -*- mode: python; tab-width: 2; coding: utf8 -*-
# git_auth configuration file

import os
import git_auth

git_auth_bin = os.path.join(os.path.dirname(__file__), 'bin', 'git-auth.sh')
repository_root = os.path.expanduser('~/repos')
access_controller = git_auth.SimpleAccessController(root_user='niklas')
ssh_key_manager = git_auth.OpenSSHKeyManager()
host_name = 'my_git_server'
