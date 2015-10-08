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
import collections
import re
from . import util

ACCESS_READ = 1 << 0
ACCESS_WRITE = 1 << 1
ACCESS_MANAGE = 1 << 2

LEVEL_USER = 100
LEVEL_SHELLUSER = 200
LEVEL_ADMIN = 300
LEVEL_ROOT = 400

User = collections.namedtuple('User', 'name home level')


class UnknownUser(Exception):
  pass


class AccessController(object):
  ''' This interface describes the controller to manage access to Git
  repositories. '''


  def get_user_info(self, session, user_name):
    ''' Return user information for the specified *user_name* or raise
    `UnknownUser` if the user does not exist. '''

    raise UnknownUser(user_name)

  def get_access_info(self, session, user_name, path):
    ''' Return a bit mask that indicates the access privileges of the
    user with the specified *user_name* to the *path*. The *path* would
    usually be a sub path of the `repository_root` in the configuration. '''

    raise NotImplementedError


class SimpleAccessController(AccessController):
  ''' This simple implementation of the `AccessController` interface
  allows all registered users to manage their home directory via SSH.

  Arguments:
    global_access (int): The global access privilege mask for all users.
      Defaults to `ACCESS_READ`, allowing all users to read from all
      repositories.
    root_user (str): The name of the root user or None if there should be
      no user with root privileges. Only the root user can arbitrarily
      modify the SSH authorized keys from the shell.
    user_name (int): The default user level, defaults to `LEVEL_SHELLUSER`.
  '''

  def __init__(self, global_access=ACCESS_READ, root_user='root',
      user_level=LEVEL_SHELLUSER):
    super().__init__()
    self.global_access = global_access
    self.root_user = root_user
    self.user_level = user_level

  def get_user_info(self, session, user_name):
    if not re.match('^[A-Za-z0-9\-_]+$', user_name):
      raise UnknownUser(user_name)
    if self.root_user and self.root_user == user_name:
      return User(user_name, '/', LEVEL_ROOT)
    return User(user_name, '/' + user_name, self.user_level)

  def get_access_info(self, session, user_name, path):
    if not util.issubpath(path, session.config.repository_root):
      return 0

    if self.root_user and self.root_user == user_name:
      return ACCESS_READ | ACCESS_WRITE | ACCESS_MANAGE

    home = os.path.join(session.config.repository_root, user_name)
    if util.issubpath(path, home):
      return ACCESS_READ | ACCESS_WRITE | ACCESS_MANAGE
    else:
      return self.global_access
