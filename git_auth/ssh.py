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
import io
import itertools
import re


def tokenize(line):
  ''' Convert *line* into a list of tokens. Supports double-quotes and
  (unchecked) backslash escapes. '''

  DEFAULT, QUOTE, ESCAPE = 0, 1, 2

  tokens = []
  current = ''
  state = DEFAULT

  for char in line:
    if state == DEFAULT:
      if char in " \t":
        tokens.append(current)
        current = ''
      else:
        current += char
        if char == '"':
          state = QUOTE
    elif state == QUOTE:
      current += char
      if char == '"':
        state = DEFAULT
      elif char == '\\':
        old_state = state
        state = ESCAPE
    elif state == ESCAPE:
      current += char
      state = old_state

  if current:
    tokens.append(current)
  return tokens


def parse_authorized_key(line):
  ''' Parse a line of an OpenSSH `authorized_keys` file and return a
  `PublicKey` object or None if the line is empty. `ValueError` is
  raised when the line is invalid. '''

  if not getattr(parse_authorized_key, 'init', False):
    ssh_keytypes = frozenset(['ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
      'ecdsa-sha2-nistp521', 'ssh-ed25519', 'ssh-dss', 'ssh-rsa'])
    ssh_options = frozenset(['cert-authority', 'command', 'environment',
      'no-agent-forwarding', 'no-port-forwarding', 'no-pty', 'no-user-rc',
      'no-X11-forwarding', 'permitopen', 'principals', 'tunnel'])
    parse_authorized_key.keytypes = ssh_keytypes
    parse_authorized_key.options = ssh_options
    parse_authorized_key.init = True
  else:
    ssh_keytypes = parse_authorized_key.keytypes
    ssh_options = parse_authorized_key.options

  line = line.rstrip()
  if not line or line.startswith('#'):
    return None

  tokens = tokenize(line)
  assert tokens

  OPTIONS, BLOB, COMMENT = 0, 1, 2

  iterator = itertools.chain(tokens, itertools.repeat(None))
  state = OPTIONS
  options = {}
  keytype = None
  blob = None
  comment = ''

  while True:
    token = next(iterator)
    if token is None:
      break
    if state == OPTIONS:
      if token in ssh_keytypes:
        state = BLOB
        keytype = token
      else:
        if '=' in token:
          key, _, value = token.partition('=')
        else:
          key = token
          value = True
        if key not in ssh_options:
          raise ValueError('invalid option {!r}'.format(key))
        options[key] = value
    elif state == BLOB:
      if not token.startswith('AAAA'):
        'invalid blob starts with {!r}'
        raise ValueError(message.format(token[:5] + '...'))
      blob = token
      state = COMMENT
    elif state == COMMENT:
      comment += token

  if not keytype:
    raise ValueError('no SSH algorithm parsed')
  if not blob:
    raise ValueError('no SSH blob parsed')

  return PublicKey(options, keytype, blob, comment)


class PublicKey(collections.namedtuple('PublicKey', 'options type blob comment')):

  def __str__(self):
    parts = []
    for key, value in self.options.items():
      parts.append(key + '=' + value)
    parts.append(self.type)
    parts.append(self.blob)
    parts.append(self.comment)
    return ' '.join(parts)


class SSHKeyManager(object):
  ''' This class defines the interface for objects that implement
  managing the SSH keys of the local SSH server (eg. OpenSSH, BitVise). '''

  KeyInfo = collections.namedtuple('KeyInfo', 'user title type blob comment')

  def add_key(self, user_name, key_title, key_type, blob):
    raise NotImplementedError

  def iter_keys(self, user_name):
    raise NotImplementedError

  def del_key(self, user_name, key_title):
    raise NotImplementedError


class OpenSSHKeyManager(SSHKeyManager):
  ''' This class implements managing the OpenSSH `authorized_keys` file. '''

  def __init__(self, git_auth_bin, auth_keys_path=None):
    super().__init__()
    if not auth_keys_path:
      auth_keys_path = os.path.expanduser('~/.ssh/authorized_keys')
    self.git_auth_bin = git_auth_bin
    self.auth_keys_path = auth_keys_path

    if not os.path.isfile(self.git_auth_bin):
      raise IOError('git_auth_bin does not exist', self.git_auth_bin)

  @staticmethod
  def _keyinfo(key):
    comment, _, key_user_name = key.comment.rpartition('#')
    comment, _, key_title = comment.rpartition('#')
    if not key_user_name or not key_title:
      return None
    return SSHKeyManager.KeyInfo(
      key_user_name, key_title, key.type, key.blob, comment)

  def add_key(self, user_name, key_title, key_type, blob, comment=''):
    if not re.match('^\w+$', key_title):
      raise ValueError('invalid key title {!r}'.format(key_title))
    for key in self.iter_keys(user_name):
      if key.title == key_title:
        message = 'SSH key with title {!r} already exists'
        raise ValueError(message.format(key_title))
    with open(self.auth_keys_path, 'a') as fp:
      command = '{} "{}"'.format(self.git_auth_bin, user_name)
      command = command.replace('\\', '\\\\')
      command = command.replace('"', '\\"')
      options = {'command': '"{}"'.format(command)}
      comment = comment + '#' + key_title + '#' + user_name
      key = PublicKey(options, key_type, blob, comment)
      fp.write(str(key))
      fp.write('\n')

  def iter_keys(self, user_name):
    if not os.path.isfile(self.auth_keys_path):
      return
    with open(self.auth_keys_path, 'r') as fp:
      for line in fp:
        try:
          key = parse_authorized_key(line)
          if not key:
            raise ValueError
        except ValueError as exc:
          print(exc)
          continue

        info = self._keyinfo(key)
        if not info:
          print("didn't get keyinfo for", key)
        if not user_name or info.user == user_name:
          yield info

  def del_key(self, user_name, key_title):
    if not os.path.isfile(self.auth_keys_path):
      raise ValueError('key {!r} not found'.format(key_title))
    key_found = False
    new_content = io.StringIO()
    with open(self.auth_keys_path, 'r') as fp:
      for line in fp:
        try:
          key = parse_authorized_key(line)
          if not key:
            raise ValueError
        except ValueError as exc:
          new_content.write(line)
          continue

        info = self._keyinfo(key)
        if info.user == user_name and info.title == key_title:
          if key_found:
            message = 'multiple occurences key {!r} found'
            raise ValueError(message.format(key_title))
          key_found = True
        else:
          new_content.write(line)
    if not key_found:
      raise ValueError('key {!r} not found'.format(key_title))
    with open(self.auth_keys_path, 'w') as fp:
      fp.write(new_content.getvalue())
