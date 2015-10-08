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
import json
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
LEVEL_USER = 100
LEVEL_SHELLUSER = 200
LEVEL_ADMIN = 300
LEVEL_ROOT = 400


def printerr(*args, **kwargs):
  kwargs.setdefault('file', sys.stderr)
  print(*args, **kwargs)


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


def check_repo(session, repo_name, access_mask, check='exists'):
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
    printerr("error: {} permission to {!r} denied".format(mode, repo_name))
    raise SystemExit(errno.EPERM)
  if check == 'exists':
    if not os.path.exists(path):
      printerr("error: repository {!r} does not exist".format(repo_name))
      raise SystemExit(errno.ENOENT)
    if not os.path.isdir(path):
      printerr("fatal error: repository {!r} is not a directory".format(args.repo))
      raise SystemExit(errno.ENOENT)  # XXX: better exit code?
  elif check == 'not-exists':
    if os.path.exists(path):
      printerr("error: repository {!r} already exists".format(repo_name))
      raise SystemExit(errno.EEXIST)
  elif check:
    raise ValueError("invalid check value: {!r}".format(check))
  return path


def parse_webhooks(filename):
  ''' Parses a file containing webhook URLs and returns a dictionary. '''

  # XXX: Callers should catch ValueErrors

  if not os.path.isfile(filename):
    return {}
  result = {}
  with open(filename, 'r') as fp:
    return json.load(fp)


def write_webhooks(filename, hooks):
  ''' Writes a dictionary containing webhook URLs to the specified file. '''

  # XXX: Validate hooks parameter

  with open(filename, 'w') as fp:
    json.dump(hooks, fp, indent=1)


def invoke_webhook(url, data):
  ''' Invokes the webhook at the specified URL with the JSON *data*. '''

  # XXX: Implement invoke_webhook()
  raise NotImplementedError("invoke_webhook() not implemented")


# == Git Auth Layer ===========================================================
# =============================================================================

class AccessController(object):
  ''' This interface describes the controller to manage access to Git
  repositories. '''

  User = collections.namedtuple('User', 'name home level')

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
  allows all registered users to manage their home directory via SSH.

  Arguments:
    global_read (bool): True by default. If enabled, any user is allowed
      to read from any repository.
    root_user (str): The name of the root user or None if there should be
      no user with root privileges. Only the root user can arbitrarily
      modify the SSH authorized keys from the shell.
    user_name (int): The default user level, defaults to `LEVEL_SHELLUSER`.
  '''

  def __init__(self, global_read=True, root_user='root',
      user_level=LEVEL_SHELLUSER):
    super().__init__()
    self.root_user = root_user
    self.user_level = user_level

  def get_user_info(self, session, user_name):
    if not re.match('[A-z0-9\-_]', user_name):
      raise self.UnknownUser(user_name)
    if self.root_user and self.root_user == user_name:
      return self.User(user_name, '/', LEVEL_ROOT)
    return self.User(user_name, '/' + user_name, self.user_level)

  def get_access_info(self, session, user_name, path):
    if self.root_user and self.root_user == user_name:
      if is_subpath(path, session.config.repository_root):
        return ACCESS_READ | ACCESS_WRITE | ACCESS_MANAGE

    home = os.path.join(session.config.repository_root, user_name)
    if is_subpath(path, home):
      return ACCESS_READ | ACCESS_WRITE | ACCESS_MANAGE
    return 0


class SSHKeyManager(object):
  ''' This class defines the interface for objects that implement
  managing the SSH keys of the local SSH server (eg. OpenSSH, BitVise). '''

  pass


class OpenSSHKeyManager(SSHKeyManager):
  ''' This class implements managing the OpenSSH `authorized_keys` file. '''

  pass

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
      printerr("unknown command:", command_name)
      return None
    if self.user.level < command_info.required_level:
      # Don't give non-privileged users an idea.
      printerr("unknown command:", command_name)
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


# == Command Functions ========================================================
# =============================================================================

@command('repo')
def _command_repo(session, args):
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
  list_p.add_argument('-d', '--describe', action='store_true')
  hook_install_p = subparser.add_parser('install-hook')
  hook_install_p.add_argument('repo')
  hook_install_p.add_argument('name')
  hook_install_p.add_argument('url')
  hook_list_p = subparser.add_parser('list-hooks')
  hook_list_p.add_argument('repo')
  hook_remove_p = subparser.add_parser('remove-hook')
  hook_remove_p.add_argument('repo')
  hook_remove_p.add_argument('name')
  args = parser.parse_args(args)

  if not args.cmd:
    parser.print_usage()
    return 0

  if args.cmd == 'create':
    path = check_repo(session, args.name, ACCESS_MANAGE, 'not-exists')

    # Make sure that none of the parent directories is a repository.
    if any(x.endswith('.git') for x in path.split(os.sep)[:-1]):
      printerr("error: can not create repository inside repository")
      return errno.EPERM

    res = subprocess.call(['git', 'init', '--bare', path])
    if res != 0:
      printerr("error: repository could not be created.")
    return res
  elif args.cmd == 'rename':
    old_path = check_repo(session, args.old, ACCESS_MANAGE, 'exists')
    new_path = check_repo(session, args.new, ACCESS_MANAGE, 'not-exists')

    # Make sure that none of the parent directories is a repository.
    if any(x.endswith('.git') for x in new_path.split(os.sep)[:-1]):
      printerr("error: can not create repository inside repository")
      return errno.EPERM

    try:
      # Make sure the parent of the new target directory exists.
      parent = os.path.dirname(new_path)
      if not os.path.exists(parent):
        os.makedirs(parent)
      os.rename(old_path, new_path)
    except (OSError, IOError) as exc:
      printerr("error:", exc)
      return exc.errno
    return 0
  elif args.cmd == 'delete':
    path = check_repo(session, args.repo, ACCESS_MANAGE, 'exists')
    if not args.force:
      if not confirm('do you really want to delete this repository?'):
        return 0

    print("deleting repository {!r}...".format(args.repo), end=' ')
    try:
      shutil.rmtree(path)
    except (OSError, IOError) as exc:
      print("error.")
      printerr(exc)
      return exc.errno
    else:
      print("done.")
    return 0
  elif args.cmd == 'describe':
    path = check_repo(session, args.repo, ACCESS_MANAGE, 'exists')
    descfile = os.path.join(path, 'description')
    if args.description:
      with open(descfile, 'w') as fp:
        fp.write(args.description)
    else:
      with open(descfile, 'r') as fp:
        print(fp.read().rstrip())
    return 0
  elif args.cmd == 'install-hook':
    # XXX: Validate hook name?
    # XXX: Validate URL scheme?
    path = check_repo(session, args.repo, ACCESS_MANAGE, 'exists')
    hooksfile = os.path.join(path, 'webhooks')
    hooks = parse_webhooks(hooksfile)
    if args.name in hooks:
      printerr("error: webhook name {!r} occupied".format(args.name))
      return errno.EEXIST
    hooks[args.name] = args.url
    write_webhooks(hooksfile, hooks)
    return 0
  elif args.cmd == 'list-hooks':
    path = check_repo(session, args.repo, ACCESS_MANAGE, 'exists')
    hooksfile = os.path.join(path, 'webhooks')
    hooks = parse_webhooks(hooksfile)
    for name, url in sorted(hooks.items(), key=lambda x: x[0]):
      print("{0}: {1}".format(name, url))
    return 0
  elif args.cmd == 'remove-hook':
    path = check_repo(session, args.repo, ACCESS_MANAGE, 'exists')
    hooksfile = os.path.join(path, 'webhooks')
    hooks = parse_webhooks(hooksfile)
    if args.name not in hooks:
      printerr("error: webhook {!r} does not exist".format(args.name))
      return errno.ENOENT
    del hooks[args.name]
    write_webhooks(hooksfile, hooks)
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
        if args.describe:
          with open(os.path.join(path, 'description'), 'r') as fp:
            for line in textwrap.wrap(fp.read().rstrip()):
              print('  ', line, sep='')
    return 0

  printerr("error: command {!r} not handled".format(args.cmd))
  return 255


@command('help')
def _command_help(session, args):
  ''' Show this help. '''

  print("Available commands:")
  print()
  for key, cmd in sorted(session.commands.items(), key=lambda x: x[0]):
    if session.user.level < cmd.required_level:
      continue
    print(key)
    if cmd.func.__doc__:
      for line in textwrap.wrap(textwrap.dedent(cmd.func.__doc__)):
        print("  ", line, sep='')


@command('git-upload-pack', required_level=LEVEL_USER)
def _command_git_upload_pack(session, args):
  parser = argparse.ArgumentParser(prog='git-upload-pack')
  parser.add_argument('repo')
  args = parser.parse_args(args)
  path = check_repo(session, args.repo, ACCESS_READ, 'exists')
  return subprocess.call(['git-upload-pack', path])


@command('git-receive-pack', required_level=LEVEL_USER)
def _command_git_upload_pack(session, args):
  parser = argparse.ArgumentParser(prog='git-receive-pack')
  parser.add_argument('repo')
  args = parser.parse_args(args)
  path = check_repo(session, args.repo, ACCESS_WRITE, 'exists')
  res = subprocess.call(['git-receive-pack', path])
  hooksfile = os.path.join(path, 'webhooks')
  hooks = parse_webhooks(hooksfile)
  if not res and hooks:
    printerr('info: invoking webhooks')
    data = {'host': session.config.host_name,
      'repo': args.repo, 'event': 'receive-pack'}
    for name, url in hooks.items():
      printerr('info:  ', name, end='... ')
      try:
        invoke_webhook(url, data)
      except Exception as exc:  # XXX: Catch the right exception for connection and communication errors
        printerr('error. ({0})'.format(exc))
      else:
        printerr('success.')
  return res


@command('shell', required_level=LEVEL_ROOT)
def _command_shell(session, args):
  ''' Root users can use this command to enter the interactive shell. '''

  # XXX: What if the user doesn't use Bash? Is it still "-l" to log in?
  # XXX: Windows doesn't use the SHELL env variable.
  return subprocess.call([os.environ['SHELL'], '-l'])


@command('ssh-key', required_level=LEVEL_SHELLUSER)
def _command_ssh_key(session, args):
  level = session.user.level

  parser = argparse.ArgumentParser(prog='ssh-key')
  if level >= LEVEL_ROOT:
    parser.add_argument('-u', '--user')
  subparsers = parser.add_subparsers(dest='cmd')
  add_p = subparsers.add_parser('add')
  add_p.add_argument('name')
  add_p.add_argument('pub_key', nargs='?')
  list_p = subparsers.add_parser('list')
  del_p = subparsers.add_parser('del')
  del_p.add_argument('name')
  del_p.add_argument('-f', '--force', action='store_true')
  if level >= LEVEL_ROOT:
    update_p = subparsers.add_parser('update')

  args = parser.parse_args(args)
  if not args.cmd:
    parser.print_usage()
    return

  if level < LEVEL_ROOT:
    args.user = session.user.name

  manager = getattr(session.config, 'ssh_key_manager')
  if not manager:
    printerr("error: no ssh_key_manager configured")
    return errno.ENOPKG  # XXX: Better error code?
  if not isinstance(manager, SSHKeyManager):
    printerr("error: invalid ssh_key_manager configuration")
    return 255

  printerr("error: command not implemented")


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

  # If a command is directory exexuted, make sure the user has the
  # right privilege level.
  if args.command:
    if not session.check_command(args.command[0]):
      return 255
    return session.command(args.command)
  else:
    if session.user.level < LEVEL_SHELLUSER:
      printerr("error: you have are not privileged for shell access")
      return errno.EPERM
    return session.cmdloop()
