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
import shutil
import subprocess
import textwrap
import traceback
import re

__author__ = 'Niklas Rosenstein <rosensteinniklas(at)gmail.com>'
__version__ = '0.9.0'

ACCESS_READ = 1 << 0
ACCESS_WRITE = 1 << 1
ACCESS_MANAGE = 1 << 2


def get_subpath(path, parent):
  relpath = os.path.relpath(path, parent)
  if relpath == os.curdir or relpath.startswith(os.pardir):
    return None
  return relpath


def is_subpath(path, parent):
  return bool(get_subpath(path, parent))


def confirm(question):
  ''' Asks the specified *question* and requests the user to reply with
  yes or no. Returns True if yes was replied, False if no. Will ask the
  question again if an invalid reply was given. '''

  while True:
    reply = input(question + ' [y/n] ').strip().lower()
    if reply in ('yes', 'y'):
      return True
    elif reply in ('no', 'n'):
      return False
    else:
      print("Please reply with yes/y or no/n.")


# == Git Auth Layer ===========================================================
# =============================================================================

class AccessController(object):
  ''' This interface describes the controller to manage access to Git
  repositories. '''

  User = collections.namedtuple('User', 'name home shell_access')

  class UnknownUser(Exception): pass

  def get_user_info(self, session, user_name):
    ''' Return user information for the specified *user_name* or raise
    `AccessController.UnknownUser` if the user does not exist. '''

    raise self.UnknownUser(user_name)

  def get_access_info(self, session, user_name, path):
    ''' Return a bit mask that indicates the access privileges of the
    user with the specified *user_name* to the *path*. The *path* would
    usually be a sub path of the `repository_root` in the configuration. '''

    raise NotImplementedError


class SimpleAccessController(AccessController):
  ''' This simple implementation of the `AccessController` interface
  allows all registered users to manage their home directory via SSH. '''

  def __init__(self, has_root=False):
    super().__init__()
    self.has_root = has_root

  def get_user_info(self, session, user_name):
    if not re.match('[A-z0-9\-_]', user_name):
      raise self.UnknownUser(user_name)
    if self.has_root and user_name == 'root':
      return self.User(user_name, '/', True)
    return self.User(user_name, '/' + user_name, True)

  def get_access_info(self, session, user_name, path):
    if self.has_root and user_name == 'root':
      if is_subpath(path, session.config.repository_root):
        return ACCESS_READ | ACCESS_WRITE | ACCESS_MANAGE

    home = os.path.join(session.config.repository_root, user_name)
    if is_subpath(path, home):
      return ACCESS_READ | ACCESS_WRITE | ACCESS_MANAGE
    return 0


class GitAuthSession(object):
  ''' This is the central authentication and repository management class. '''

  def __init__(self, user, config=None):
    super().__init__()
    if config is None:
      import git_auth_config as config
    self.user = config.access_controller.get_user_info(self, user)
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
      except Exception as exc:
        traceback.print_exc()
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


# == Command Functions ========================================================
# =============================================================================

def _check_repo(session, repo_name, access_mask, check='exists'):
  ''' Helper function that converts the repository name to the full
  path, makes sure it exists and checks if the user has access to
  the repository with the specified access mask. Returns the path
  to the repository or raises `SystemExit` with the appropriate
  exit code. '''

  path = session.repo2path(repo_name)
  if not session.get_access_info(path) & access_mask:
    if access_mask & ACCESS_MANAGE:
      mode = 'manage'
    elif access_mask & ACCESS_WRITE:
      mode = 'write'
    elif access_mask & ACCESS_READ:
      mode = 'read'
    else:
      mode = '<invalid access mask>'
    print("error: {0} permission to {!r} denied".format(mode, repo_name))
    raise SystemExit(errno.EPERM)
  if check == 'exists':
    if not os.path.exists(path):
      print("error: repository {!r} does not exist".format(repo_name))
      raise SystemExit(errno.ENOENT)
    if not os.path.isdir(path):
      print("fatal error: repository {!r} is not a directory".format(args.repo))
      raise SystemExit(errno.ENOENT)  # XXX: better exit code?
  elif check == 'not-exists':
    if os.path.exists(path):
      print("error: repository {!r} already exists".format(repo_name))
      raise SystemExit(errno.EEXIST)
  elif check:
    raise ValueError("invalid check value: {!r}".format(check))
  return path


def command_repo(session, args):
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
  delete_p.add_argument('-f', '--force', action='store_true')
  describe_p = subparser.add_parser('describe')
  describe_p.add_argument('repo')
  describe_p.add_argument('description', nargs='?')
  list_p = subparser.add_parser('list')
  args = parser.parse_args(args)

  if not args.cmd:
    parser.print_usage()
    return 0

  if args.cmd == 'create':
    path = _check_repo(session, args.name, ACCESS_MANAGE, 'not-exists')

    # Make sure that none of the parent directories is a repository.
    if any(x.endswith('.git') for x in path.split(os.sep)[:-1]):
      print("error: can not create repository inside repository")
      return errno.EPERM

    res = subprocess.call(['git', 'init', '--bare', path])
    if res != 0:
      print("error: repository could not be created.")
    return res
  elif args.cmd == 'rename':
    old_path = _check_repo(session, args.old, ACCESS_MANAGE, 'exists')
    new_path = _check_repo(session, args.new, ACCESS_MANAGE, 'not-exists')

    # Make sure that none of the parent directories is a repository.
    if any(x.endswith('.git') for x in new_path.split(os.sep)[:-1]):
      print("error: can not create repository inside repository")
      return errno.EPERM

    try:
      # Make sure the parent of the new target directory exists.
      parent = os.path.dirname(new_path)
      if not os.path.exists(parent):
        os.makedirs(parent)
      os.rename(old_path, new_path)
    except (OSError, IOError) as exc:
      print("error:", exc)
      return exc.errno
    return 0
  elif args.cmd == 'delete':
    path = _check_repo(session, args.repo, ACCESS_MANAGE, 'exists')
    if not args.force:
      if not confirm('do you really want to delete this repository?'):
        return 0
    print("deleting repository {!r}...".format(args.repo), end=' ')
    try:
      shutil.rmtree(path)
    except (OSError, IOError) as exc:
      print("error.")
      print(exc)
      return exc.errno
    else:
      print("done.")
    return 0
  elif args.cmd == 'describe':
    path = _check_repo(session, args.repo, ACCESS_MANAGE, 'exists')
    descfile = os.path.join(path, 'description')
    if args.description:
      with open(descfile, 'w') as fp:
        fp.write(args.description)
    else:
      with open(descfile, 'r') as fp:
        print(fp.read().rstrip())
    return 0
  elif args.cmd == 'list':
    for repo_name, path in session.repositories():
      info = session.get_access_info(path)
      flags = list('---')
      if info & ACCESS_READ:
        flags[0] = 'r'
      if info & ACCESS_WRITE:
        flags[1] = 'w'
      if info & ACCESS_MANAGE:
        flags[2] = 'm'
      if info:
        print(''.join(flags), ': ', repo_name, sep='')
    return 0

  print("error: command not handled.")
  return 255


def command_help(session, args):
  ''' Show this help. '''

  print("Available commands:")
  print()
  for key, func in sorted(session.commands().items(), key=lambda x: x[0]):
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
  session = GitAuthSession(args.user)

  if not args.command:
    ssh_command = os.environ.pop('SSH_ORIGINAL_COMMAND', None)
    if ssh_command:
      args.command = shlex.split(ssh_command)

  if args.command:
    if args.command[0] in ('git-receive-pack', 'git-upload-pack'):
      return subprocess.call(args.command)

  # Users without manage privileges can't go past this line.
  if not session.user.shell_access:
    print("You are not privileged for SSH Access.")
    return errno.EPERM

  if args.command:
    return session.command(args.command)

  session.cmdloop()
  return 0
