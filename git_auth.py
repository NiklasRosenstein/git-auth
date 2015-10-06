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
'''
`git_auth` - a Git authentication layer alternative
===================================================
'''

import os
import sys
import argparse
import collections
import errno
import itertools
import shlex
import subprocess
import textwrap
import traceback
import re

__author__ = 'Niklas Rosenstein <rosensteinniklas(at)gmail.com>'
__version__ = '0.9.0'

ACCESS_READ = 1 << 0
ACCESS_WRITE = 1 << 1


def get_subpath(path, parent):
  relpath = os.path.relpath(path, parent)
  if relpath == os.curdir or relpath.startswith(os.pardir):
    return None
  return relpath


def is_subpath(path, parent):
  return bool(get_subpath(path, parent))


# == Git Auth Layer ===========================================================
# =============================================================================

User = collections.namedtuple('User', 'name home manage')


class AccessControl(object):
  ''' Base class to manage access control. '''

  class UnknownUser(Exception):
    pass

  def get_user(self, auth, user_name):
    ''' Retrieve user information.

    Returns:
      User: Information about the requested user.
    Raises:
      UnknownUser: If the specified user doesn't exist (also if the user
        name contains invalid characters).
    '''
    raise NotImplementedError

  def access_info(self, auth, user_name, path):
    ''' Return a bitfield indicating the access permissions of the
    user to the specified absolute *path* on the local filesystem. '''
    raise NotImplementedError


class SimpleAccessControl(AccessControl):
  ''' This simple implementation of the `AccessControl` interface
  allows all registered users to manage their home directory via SSH. '''

  def __init__(self, has_root=False):
    super().__init__()
    self.has_root = has_root

  def get_user(self, auth, user_name):
    if not re.match('[A-z0-9\-_]', user_name):
      raise self.UnknownUser(user_name)
    if self.has_root and user_name == 'root':
      return User(user_name, '/', True)
    return User(user_name, '/' + user_name, True)

  def access_info(self, auth, user_name, path):
    if self.has_root and user_name == 'root':
      if is_subpath(path, auth.config.repository_root):
        return ACCESS_READ | ACCESS_WRITE

    home = os.path.join(auth.config.repository_root, user_name)
    if is_subpath(path, home):
      return ACCESS_READ | ACCESS_WRITE
    return 0


class GitAuth(object):
  ''' This is the central authentication and repository management class. '''

  def __init__(self, user, config=None):
    super().__init__()
    if config is None:
      import git_auth_config as config
    self.user = config.access_control.get_user(self, user)
    self.config = config

  def command(self, command):
    ''' Execute the specified command list. The first element in the
    list is used as the command name and dispatched by the default
    commands and the additional commands in the configuration. The
    exit code of the command is returned. '''

    fname = 'command_' + command[0]
    command_func = None
    if fname in globals():
      command_func = globals()[fname]
    if hasattr(self.config, fname):
      command_func = getattr(self.config, fname)
    if not callable(command_func):
      print("unknown command:", command[0], file=sys.stderr)
    else:
      try:
        return command_func(self, command[1:])
      except SystemExit as exc:
        return exc.code
    return 255

  def commands(self):
    ''' Returns a dictionary of all available commands mapping the name
    to the command function that implements it. '''

    commands = {}
    chain = vars(self.config).items(), globals().items()
    for key, value in itertools.chain(*chain):
      if callable(value) and key.startswith('command_'):
        name = key[8:]
        commands[name] = value

    return commands

  def cmdloop(self, intro='git-auth$ '):
    ''' Enters the interactive shell. '''

    header = "git-auth v{0} - Copyright (C) 2015 {1}"
    print(header.format(__version__, __author__))

    while True:
      command = shlex.split(input(intro))
      if command:
        if command[0] == 'exit':
          break
        elif command[0] == '?':
          command[0] = 'help'
        self.command(command)

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
    relpath = get_subpath(path, self.config.repository_root)
    if not relpath:
      return None

    if os.name == 'nt':
      relpath = relpath.replace('\\', '/')
    return relpath

  def check_access(self, path, mode):
    ''' Returns True if the current user has access in the specified
    *mode* to *path*, False if not. '''

    if mode not in 'rw':
      raise ValueError('invalid mode {!r}'.format(mode))
    info = self.config.access_control.access_info(self, self.user.name, path)
    if mode == 'w':
      return info & ACCESS_WRITE
    elif mode == 'r':
      return info & ACCESS_READ or info & ACCESS_WRITE


# == Command Functions ========================================================
# =============================================================================

def command_repo(auth, args):
  ''' Manage repositories. '''

  parser = argparse.ArgumentParser(prog='repo')
  subparser = parser.add_subparsers(dest='cmd')
  create_p = subparser.add_parser('create')
  create_p.add_argument('name')
  rename_p = subparser.add_parser('rename')
  rename_p.add_argument('old')
  rename_p.add_argument('new')
  delete_p = subparser.add_parser('delete')
  delete_p.add_argument('repo')
  args = parser.parse_args(args)

  if not args.cmd:
    parser.print_usage()
    return 0

  if args.cmd == 'create':
    path = auth.repo2path(args.name)
    if not auth.check_access(path, 'w'):
      print("error: write permission to {!r} denied".format(args.name))
      return errno.EPERM

    # Make sure that none of the parent directories is a repository.
    if any(x.endswith('.git') for x in path.split(os.sep)[:-1]):
      print("error: can not create repository inside repository")
      return errno.EPERM

    if os.path.exists(path):
      print("error: repository {!r} already exists.".format(args.name))
      return errno.EEXIST

    res = subprocess.call(['git', 'init', '--bare', path])
    if res != 0:
      print("error: repository could not be created.")
    return res
  elif args.cmd == 'rename':
    old_path = auth.repo2path(args.old)
    new_path = auth.repo2path(args.new)
    if not auth.check_access(old_path, 'w'):
      print("error: write permission to {!r} denied".format(args.old))
      return errno.EPERM
    if not auth.check_access(new_path, 'w'):
      print("error: write permission to {!r} denied".format(args.new))
      return errno.EPERM

    # Make sure that none of the parent directories is a repository.
    if any(x.endswith('.git') for x in new_path.split(os.sep)[:-1]):
      print("error: can not create repository inside repository")
      return errno.EPERM

    if not os.path.exists(old_path):
      print("error: repository {!r} does not exist".format(args.old))
      return errno.ENOENT
    if os.path.exists(new_path):
      print("error: repository {!r} already exists.".format(args.new))
      return errno.EEXIST

    try:
      os.rename(old_path, new_path)
    except (OSError, IOError) as exc:
      print("error:", exc)
      return exc.errno
    return 0

  print("error: command not handled.")
  return 255


def command_help(auth, args):
  ''' Show this help. '''

  print("Available commands:")
  print()
  for key, func in sorted(auth.commands().items(), key=lambda x: x[0]):
    print(key)
    if func.__doc__:
      for line in textwrap.wrap(textwrap.dedent(func.__doc__)):
        print("  ", line, sep='')


# == Main =====================================================================
# =============================================================================

def get_argument_parser():
  parser = argparse.ArgumentParser(description='''
    git_auth v{0} - Copyright (C) 2015 Niklas Rosenstein''')
  parser.add_argument('user')
  parser.add_argument('command', nargs='...')
  return parser


def main():
  parser = get_argument_parser()
  args = parser.parse_args()
  auth = GitAuth(args.user)

  if not args.command:
    ssh_command = os.environ.pop('SSH_ORIGINAL_COMMAND', None)
    if ssh_command:
      args.command = shlex.split(ssh_command)

  if args.command:
    if args.command[0] in ('git-receive-pack', 'git-upload-pack'):
      return subprocess.call(args.command)

  # Users without manage privileges can't go past this line.
  if not auth.user.manage:
    print("You are not privileged for SSH Access.")
    return errno.EPERM

  if args.command:
    return auth.command(args.command)

  auth.cmdloop()
  return 0
