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


def relpath(path, parent):
  ''' Returs *path* relative to *parent* or None if it is not a subpath
  of *parent*. You can also use `issubpath()` if you only want to check
  if a path is a subpath of another. '''

  relpath = os.path.relpath(path, parent)
  if relpath == os.curdir or relpath.startswith(os.pardir):
    return None
  return relpath


def issubpath(path, parent):
  ''' Returns True if *path* is a true subpath of *parent*, False if not. '''
  return bool(relpath(path, parent))


def confirm(question):
  ''' Ask *question* and requests the user to reply with yes or no via
  stdin. Returns True if yes was replied, False if no. Will aks until
  a valid reply was entered. '''

  while True:
    reply = input(question + ' [y/n] ').strip().lower()
    if reply in ('yes', 'y'):
      return True
    elif reply in ('no', 'n'):
      return False
    else:
      print("Please reply with yes/y or no/n.")

