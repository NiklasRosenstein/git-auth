# -*- mode: python; tab-width: 2; coding: utf8 -*-
# git_auth configuration file

import os
import git_auth

repository_root = os.path.expanduser('~/repos')
access_control = git_auth.SimpleAccessControl(has_root=True)
