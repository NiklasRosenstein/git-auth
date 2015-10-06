# -*- mode: python; tab-width: 2; coding: utf8 -*-
# git_auth configuration file

import os
import git_auth

repository_root = os.path.expanduser('~/repos')
access_controller = git_auth.SimpleAccessController()
host_name = 'my_git_server'
