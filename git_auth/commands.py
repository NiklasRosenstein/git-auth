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

import os
import sys
import argparse
import errno
import shutil
import subprocess
import textwrap

from . import command, util
from .auth import ACCESS_READ, ACCESS_WRITE, ACCESS_MANAGE
from .auth import LEVEL_USER, LEVEL_SHELLUSER, LEVEL_ADMIN, LEVEL_ROOT
from .hooks import parse_webhooks, write_webhooks, invoke_webhook


def printerr(*args, **kwargs):
  kwargs.setdefault('file', sys.stderr)
  print(*args, **kwargs)


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
      if not util.confirm('do you really want to delete this repository?'):
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
  ''' Manage SSH keys. '''

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
