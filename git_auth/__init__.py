# -*- mode: python; tab-width: 2; coding: utf8 -*-
#
# Copyright (C) 2015 Niklas Rosenstein
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
''' A Git authentication layer based on SSH.
Visit https://github.com/NiklasRosenstein/git-auth.py. '''

__author__ = 'Niklas Rosenstein <rosensteinniklas(at)gmail.com>'
__version__ = '0.9.0'

import sys
if sys.version_info[0] != 3:
  raise EnvironmentError('git-auth requires Python3')

import os
import collections
import shlex
import traceback

from . import util
from .auth import AccessController, SimpleAccessController
from .auth import ACCESS_READ, ACCESS_WRITE, ACCESS_MANAGE
from .auth import LEVEL_USER, LEVEL_SHELLUSER, LEVEL_ADMIN, LEVEL_ROOT
from .ssh import SSHKeyManager, OpenSSHKeyManager


class GitAuthSession(object):
  ''' This is the central authentication and repository management class. '''

  Command = collections.namedtuple('Command', 'func required_level')
  commands = {}

  def __init__(self, user, config=None):
    super().__init__()
    if config is None:
      import git_auth_config as config
    self.user = config.access_controller.get_user_info(self, user)
    self.config = config

  def check_command(self, command_name):
    ''' Checks if *command_name* is an existing command and if the
    current user is allowed to execute that command. If everything is
    ok, the `GitAuthSession.Command` object is returned, otherwise None. '''

    try:
      command_info = self.commands[command_name]
    except KeyError:
      print("unknown command:", command_name, file=sys.stderr)
      return None
    if self.user.level < command_info.required_level:
      # Don't give non-privileged users an idea.
      print("unknown command:", command_name, file=sys.stderr)
      return None
    return command_info

  def command(self, command):
    ''' Execute the specified command list. The first element in the
    list is used as the command name and dispatched by the default
    commands and the additional commands in the configuration. The
    exit code of the command is returned. '''

    command_info = self.check_command(command[0])
    if not command_info:
      return 255
    try:
      return command_info.func(self, command[1:])
    except SystemExit as exc:
      return exc.code
    except Exception as exc:
      traceback.print_exc()
    return 255

  def cmdloop(self, intro='git-auth$ '):
    ''' Enters the interactive shell. '''

    header = "git-auth v{0} - Copyright (C) 2015 {1}"
    print(header.format(__version__, __author__))
    print("Welcome back, {0}!".format(self.user.name))

    while True:
      command = shlex.split(input(intro))
      if command:
        if command[0] == 'exit':
          break
        elif command[0] == '?':
          command[0] = 'help'
        self.command(command)

    return 0

  def repo2path(self, repo_name):
    ''' Converts a relative repository name to an absolute path on the
    filesystem based on the repository root directory as specified in
    the configuration. '''

    if os.name == 'nt':
      repo_name = repo_name.replace('/', '\\')

    if not repo_name.endswith('.git'):
      repo_name += '.git'
    path = os.path.join(self.config.repository_root, repo_name)
    path = os.path.normpath(path)
    return path

  def path2repo(self, path):
    ''' Converts the specified absolute path to a relative repository
    name. The original path can be obtained with `repo2path()`. The
    path is returned even if the repository does not exist. The `.git`
    suffix is removed from the path. None will be returned if the
    path does not end with `.git` or is not inside the repository
    root directory. '''

    if not path.endswith('.git'):
      return None
    path = os.path.normpath(path[:-4])
    relpath = util.relpath(path, self.config.repository_root)
    if not relpath:
      return None

    if os.name == 'nt':
      relpath = relpath.replace('\\', '/')
    return relpath

  def get_access_info(self, path):
    ''' Wrapper for the `AccessController.get_access_info()` function
    that uses this session and the current user name. Returns a bit
    field with the access privileges of the current user to *path*. '''

    controller = self.config.access_controller
    return controller.get_access_info(self, self.user.name, path)

  def repositories(self):
    ''' Iterate over all repositories. Yields tuples in the form of
    `(repo_name, path)`. '''

    if not os.path.isdir(self.config.repository_root):
      return
    for dirpath, dirs, files in os.walk(self.config.repository_root):
      for dirname in dirs:
        if dirname != '.git' and dirname.endswith('.git'):
          repo_path = os.path.join(dirpath, dirname)
          repo_name = self.path2repo(repo_path)
          yield (repo_name, repo_path)


def command(name, required_level=LEVEL_SHELLUSER):
  ''' Decorator for a function to be registered as a command for the
  git_auth shell. The *name* is the name of the command. The decorated
  function is added to the `GitAuthSession.commands` dictionary.

  A command that does not require permission can also be executed by
  users that have no shell accesss. This is only used for `git-upload-pack`
  and `git-receive-pack`. '''

  def decorator(func):
    GitAuthSession.commands[name] = GitAuthSession.Command(
      func, required_level)

  return decorator


from . import commands
