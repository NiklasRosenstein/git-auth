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
import shlex

from . import GitAuthSession, auth


def get_argument_parser():
  parser = argparse.ArgumentParser(description='''
    git_auth v{0} - Copyright (C) 2015 Niklas Rosenstein''')
  parser.add_argument('user')
  parser.add_argument('command', nargs='...')
  return parser


def main():
  parser = get_argument_parser()
  args = parser.parse_args()
  try:
    session = GitAuthSession(args.user)
  except auth.UnknownUser as exc:
    print('error: unknown user {!r}'.format(str(exc)), file=sys.stderr)
    return errno.EPERM

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
    if session.user.level < auth.LEVEL_SHELLUSER:
      print("error: you have are not privileged for shell access", file=sys.stderr)
      return errno.EPERM
    return session.cmdloop()
