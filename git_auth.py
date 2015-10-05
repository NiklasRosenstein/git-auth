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

User = collections.namedtuple('User', 'name home manage')


class AccessControl(object):
  ''' Base class to manage access control. '''

  class UnknownUser(Exception):
    pass

  def get_user(self, user_name):
    ''' Retrieve user information.

    Returns:
      User: Information about the requested user.
    Raises:
      UnknownUser: If the specified user doesn't exist (also if the user
        name contains invalid characters).
    '''
    raise NotImplementedError


class SimpleAccessControl(AccessControl):
  ''' This simple implementation of the `AccessControl` interface
  allows all registered users to manage their home directory via SSH. '''

  def get_user(self, user_name):
    if not re.match('[A-z0-9\-_]', user_name):
      raise self.UnknownUser(user_name)
    return User(user_name, '/' + user_name, True)


class GitAuth(object):
  ''' This is the central authentication and repository management class. '''

  def __init__(self, user, config=None):
    super().__init__()
    if config is None:
      import git_auth_config as config
    self.user = config.access_control.get_user(user)
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


# == Command Functions ========================================================
# =============================================================================

def command_repo(auth, args):
  ''' Manage repositories. '''

  print("command repo not implemented.")
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
