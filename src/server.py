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
import auth from './auth'
import {AuthKey, KeyManager} from './authorized_keys'
import {StructSocketIO} from './socketio'

class catch_and_print:

  def __enter__(self):
    pass

  def __exit__(self, *a):
    if a[0] is not None:
      traceback.print_exc()
    return True


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

  def start(self, in_thread=True):
    """
    Starts the authentication server. Raises a #RuntimeError if the server is
    already running. Use #shutdown() to stop the server.
    """

    if self._thread and self._thread.is_alive() or self._socket:
      raise RuntimeError('server thread is already/still running')
    self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self._socket.bind(self.auth_socket)
    self._socket.listen(5)
    self._stop_event.clear()
    if in_thread:
      self._thread = threading.Thread(target=self._server_loop)
      self._thread.start()
    else:
      self._server_loop()

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
      def worker():
        try:
          self._handle_connection(StructSocketIO(conn))
        except:
          traceback.print_exc()
        finally:
          conn.close()
      workers.submit(worker)
    self._socket.close()
    self._socket = None

  def _handle_connection(self, conn):
    try:
      data = conn.readjson(allow_empty=True)
      if data is None:
        return  # Likely a notification when the server is supposed to stop.
    except json.JSONDecodeError:
      conn.writejson({'error': 'InvalidDataReceived'})
      return

    # TODO: Allow asynchronous writing to the response buffer, so that
    #       subsequent Read requests can actually return a portion of
    #       the data that is to come and the authentication process does
    #       not need to be blocking.

    agent = data.get('agent')
    request = data.get('request')
    args = data.get('args', {})
    if not isinstance(agent, str) or not isinstance(request, str) or \
        not isinstance(args, dict):
      conn.writejson({'error': 'InvalidRequest'})
      return

    response = {'request': request}
    if request == 'AuthorizeSSHCommand':
      obj = auth.AuthorizeSSHCommand(args['key-id'], args['username'],
        args['command'])
      obj = self.handler.authorize_ssh_command(obj)
      response['response'] = 'Allow' if obj.allowed else 'Deny'
      response['args'] = {}
      if obj.allowed:
        response['args'].update({
          "command": obj.command,
          "env": obj.env
        })

    elif request == 'GitPreReceive':
      obj = auth.GitPreReceive(args['key-id'], args['username'],
        args['repository'], args['refs'])
      obj = self.handler.git_pre_receive(obj)
      response['response'] = 'Allow' if obj.allowed else 'Deny'

    elif request == 'GitUpdate':
      obj = auth.GitUpdate(args['key-id'], args['username'],
        args['repository'], args['refname'], args['sha1-old'],
        args['sha1-new'], args['type'])
      obj = self.handler.git_update(obj)
      response['response'] = 'Allow' if obj.allowed else 'Deny'

    elif request == 'GitPostReceive':
      obj = auth.GitPostReceive(args['key-id'], args['username'],
        args['repository'], args['refs'])
      obj = self.handler.git_post_receive(obj)
      response['response'] = 'Allow' if obj.allowed else 'Deny'

    else:
      conn.writejson({'error': 'InvalidRequest'})
      return

    message = obj.buffer.getvalue()
    if message:
      response.setdefault('args', {})
      response['args']['message'] = message
    conn.writejson(response)
