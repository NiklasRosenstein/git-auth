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
import itertools

PublicKey = collections.namedtuple('PublicKey', 'options type blob comment')


def tokenize(line):
  ''' Convert *line* into a list of tokens. Supports double-quotes and
  (unchecked) backslash escapes. '''

  DEFAULT, QUOTE, ESCAPE = 0, 1, 2

  tokens = []
  current = ''
  state = DEFAULT

  for char in line:
    old_state = state
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

  if not getattr(parse_authorized_keys, 'init'):
    keytypes = frozenset(['ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
      'ecdsa-sha2-nistp521', 'ssh-ed25519', 'ssh-dss', 'ssh-rsa'])
    options = frozenset(['cert-authority', 'command', 'environment',
      'no-agent-forwarding', 'no-port-forwarding', 'no-pty', 'no-user-rc',
      'no-X11-forwarding', 'permitopen', 'principals', 'tunnel'])
    parse_authorized_keys.keytypes = keytypes
    parse_authorized_keys.options = options
  else:
    keytypes = parse_authorized_keys.keytypes
    options = parse_authorized_keys.options

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
      if token in OpenSSHKeyManager.keytypes:
        state = BLOB
        keytype = token
      else:
        if '=' in token:
          key, _, value = token.partition('=')
        else:
          key = token
          value = True
        if key not in OpenSSHKeyManager.options:
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

  return PublicKey(options, keytype, blob, comment)


class SSHKeyManager(object):
  ''' This class defines the interface for objects that implement
  managing the SSH keys of the local SSH server (eg. OpenSSH, BitVise). '''

  pass


class OpenSSHKeyManager(SSHKeyManager):
  ''' This class implements managing the OpenSSH `authorized_keys` file. '''

  def __init__(self, auth_keys_path=None):
    super().__init__()
    if not auth_keys_path:
      auth_keys_path = os.path.expanduser('~/.ssh/authorized_keys')
    self.auth_keys_path = auth_keys_path
