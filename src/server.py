" The Git-auth server. "

import concurrent.futures
import json
import nodepy
import re
import shlex
import socket
import struct
import threading
import traceback
import {AuthKey, KeyManager} from './authorized_keys'

class GitAuth:
  """
  The Git-auth server and management class.

  # Parameters
  handler_class (AuthHandler): The implementation of an authentication handler.
  authorized_keys_file (str): Path to an SSH authorized_keys file.
  auth_socket (str): Path to the Git-auth socket.
  prefix (str): Directory where repositories are stored.
  """

  def __init__(self, handler_class, authorized_keys_file, auth_socket,
                     prefix, ssh_key_flags=None):
    self.handler = handler_class(self)
    self.keys = KeyManager(authorized_keys_file)
    self.auth_socket = auth_socket
    self.prefix = prefix
    self.ssh_key_flags = 'no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty'.split(',')
    self._thread = None
    self._socket = None
    self._stop_event = threading.Event()

  def get_ssh_auth_command(self, username):
    if not re.match('^[A-z0-9_]+$', username):
      raise ValueError('invalid username: {!r}'.format(username))
    filename = str(require.resolve('./client.py').filename)
    command = nodepy.runtime.exec_args + [filename]
    command.append('--username={}'.format(username))
    return ' '.join(shlex.quote(x) for x in command)

  def add_key(self, username, public_key, flags=None):
    if flags is None:
      flags = self.ssh_key_flags
    if isinstance(flags, str):
      flags = flags.split(',') if ',' in flags else flags.split(' ')
    key = AuthKey.parse(public_key)
    key.options['command'] = self.get_ssh_auth_command(username)
    key.options.update({k: '' for k in flags})
    self.keys.add(key)

  def start(self):
    """
    Starts the authentication server. Raises a #RuntimeError if the server is
    already running. Use #shutdown() to stop the server.
    """

    if self._thread and self._thread.is_alive():
      raise RuntimeError('server thread is already/still running')
    self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self._socket.bind(self.auth_socket)
    self._socket.listen(5)
    self._stop_event.clear()
    self._thread = threading.Thread(target=self._server_loop)
    self._thread.start()

  def shutdown(self, wait=True):
    """
    Shuts down the server thread.
    """

    self._stop_event.set()
    if self._socket:
      temp = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
      temp.connect(self.auth_socket)
      temp.close()
    if self._thread and wait:
      self._thread.join()

  def _server_loop(self):
    workers = concurrent.futures.ThreadPoolExecutor(max_workers=5)
    while not self._stop_event.is_set():
      conn, addr = self._socket.accept()
      workers.submit(self._handle_request, conn)

  def _handle_request(self, conn):
    def send_response(data):
      data = json.dumps(data).encode('utf8')
      conn.send(struct.pack('I', len(data)))
      conn.send(data)
    try:
      data = conn.recv(4)
      if not data: return  # probably a notification connection
      nbytes = struct.unpack('I', data)[0]
      try:
        data = json.loads(conn.recv(nbytes).decode('utf8'))
      except json.JSONDecodeError:
        send_response({'error': 'InvalidDataReceived'})
        return
      if 'username' not in data or not isinstance(data['username'], str) or \
          'repository' not in data or not isinstance(data['repository'], str) or \
          'tags' not in data or not isinstance(data['tags'], list) or \
          'command' not in data or not isinstance(data['command'], str):
        send_response({'error': 'InvalidRequest'})
        return
      perm = self.handler.get_permissions(data['username'], data['repository'], data['tags'])
      send_response({'error': None, 'permissions': perm.value})
    except:
      traceback.print_exc()
    finally:
      conn.close()
