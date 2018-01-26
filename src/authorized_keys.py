" Read and write OpenSSH authorized_keys files. "

import os


class AuthKey:
  """
  Represents the information of a line in the OpenSSH authorized_keys file.
  """

  ssh_algorithms = frozenset([
    'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp521',
    'ssh-ed25519',
    'ssh-dss',
    'ssh-rsa'
  ])
  ssh_options = frozenset([
    'cert-authority',
    'command',
    'environment',
    'no-agent-forwarding',
    'no-port-forwarding',
    'no-pty',
    'no-user-rc',
    'no-X11-forwarding',
    'permitopen',
    'principals',
    'tunnel'
  ])

  @staticmethod
  def _tokenize(line):
    """
    Generator that splits a line from an authorized_keys file into tokens.
    """

    DEFAULT, QUOTE, ESCAPE = 0, 1, 2
    current = ''
    state = DEFAULT
    for char in line:
      if state == DEFAULT:
        if char in " \t,":
          yield current
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
      yield current

  @classmethod
  def parse(cls, line):
    """
    Parses a line from an authorized_keys file and returns a #AuthKey object.
    If the line is empty, #None is returned. If the syntax is invalid, a
    #ValueError is raised.
    """

    line = line.rstrip()
    if not line or line.startswith('#'):
      return None

    OPTIONS, BLOB, COMMENT = 0, 1, 2
    state = OPTIONS
    options = {}
    algorithm = None
    blob = None
    comment = ''

    tokens = cls._tokenize(line)
    while True:
      try: token = next(tokens)
      except StopIteration: break
      if state == OPTIONS:
        if token in cls.ssh_algorithms:
          state = BLOB
          algorithm = token
        else:
          if '=' in token:
            key, _, value = token.partition('=')
          else:
            key = token
            value = ''
          if key not in cls.ssh_options:
            raise ValueError('unknown option {!r}'.format(key))
          if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
          value = value.replace('\\"', '"') # TODO: Catch double escapes like \\'
          options[key] = value
      elif state == BLOB:
        if not token.startswith('AAAA'):
          msg = 'invalid blob starts with {!r}'
          raise ValueError(msg.format(token[:5] + '...'))
        blob = token
        state = COMMENT
      elif state == COMMENT:
        comment += token

    if not algorithm:
      raise ValueError('no algorithm parsed')
    if not blob:
      raise ValueError('no blob parsed')

    return cls(options, algorithm, blob, comment)

  def __init__(self, options, algorithm, blob, comment):
    self.options = options
    self.algorithm = algorithm
    self.blob = blob
    self.comment = comment

  def __repr__(self):
    return 'AuthKey(options={!r}, algorithm={!r}, blob={!r}, comment={!r})'\
      .format(self.options, self.algorithm, self.blob, self.comment)

  def __str__(self):
    parts = []
    for key, value in self.options.items():
      value = value.replace('"', '\\"')
      if ' ' in value:
        value = '"' + value + '"'
      if value:
        value = key + '=' + value
      else:
        value = key
      if parts: parts[0] += ',' + value
      else: parts.append(value)
    parts.append(self.algorithm)
    parts.append(self.blob)
    parts.append(self.comment)
    return ' '.join(parts)


class KeyManager:
  """
  Represents the data in an OpenSSH authorized_keys file.
  """

  def __init__(self, filename):
    self.filename = filename
    self._changed = False
    self._last_read = None
    self._keys = []
    self.read()

  def __iter__(self):
    """
    Iterates over all valid keys.
    """

    for key in self._keys:
      if isinstance(key, AuthKey):
        yield key

  def read(self, force=False):
    """
    Reads the file -- noop if the file does not exist. If *force* is not set
    and the file hasn't change since the last time it was read (determined by
    the file's modification time), it will not be read again.
    """

    do_read = (force or self._last_read is None)
    if not do_read:
      try:
        mtime = os.path.getmtime(self.filename)
      except FileNotFoundError:
        mtime = None
      do_read = (mtime is None or mtime != self._last_read)
    if not do_read:
      return
    self._keys = []
    if not os.path.isfile(self.filename):
      return
    with open(self.filename) as fp:
      for line in fp:
        try:
          self._keys.append(AuthKey.parse(line))
        except ValueError as e:
          self._keys.append(line.strip())

  def write(self, force=False):
    """
    Writes the contents of this object back to the authorized_keys file. If
    *force* is not set and no keys have been added to or removed from the
    manager, nothing will be written.
    """

    if not force and not self._changed:
      return
    with open(self.filename, 'w') as fp:
      for key in self._keys:
        fp.write(str(key))
        fp.write('\n')
    self._changed = False
    self._last_read = os.path.getmtime(self.filename)

  def flush(self):
    self._keys = []
    self._changed = True
    self._last_read = None

  def add(self, key):
    if not isinstance(key, (str, AuthKey)):
      raise TypeError('expected str or AuthKey, got {}'.format(type(key).__name__))
    self._keys.append(key)
    self._changed = True

  def remove(self, key):
    self._keys.remove(key)
    self._changed = True
