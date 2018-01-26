
import argparse
import json
import os
import shlex
import socket
import struct
import subprocess
import sys
import {StructSocketIO} from './socketio'

parser = argparse.ArgumentParser(prog='git-auth-client', description='''
  The Git-auth client that is used in the OpenSSH authorized_keys file
  and Git hooks to communicate with the authentication server. Returns
  a non-zero exit status if the action is not authorized.

  For non-SSH authentications, the `GITAUTH_USERNAME` and `GITAUTH_KEYID`
  environment variables must be set. These are automatically set when using
  the --type ssh authentication type.
''')
parser.add_argument('server', nargs='?', help='The filename of the Git-auth socket.')
parser.add_argument('--agent', help='The user agent that issues the request.')
parser.add_argument('--type', choices={'ssh', 'pre-receive', 'update', 'post-receive'})
parser.add_argument('--username', help='The name of the user whose action is to be authenticated. Defaults to GITAUTH_USERNAME')
parser.add_argument('--key-id', help='The ID of the SSH key that the user is using.')
parser.add_argument('refname', nargs='?')
parser.add_argument('sha1_old', nargs='?')
parser.add_argument('sha1_new', nargs='?')


def main(argv=None):
  args = parser.parse_args(argv)
  if not args.username:
    args.username = os.environ.get('GITAUTH_USERNAME')
    if not args.username:
      parser.error('option --username is required')
      return 1
  if not args.key_id:
    args.key_id = os.environ.get('GITAUTH_KEYID')
    if not args.key_id:
      parser.error('option --key-id is required')
      return 1

  if args.type == 'ssh':
    command = os.environ.get('SSH_ORIGINAL_COMMAND')
    if not command:
      print('error: SSH_ORIGINAL_COMMAND is not set.')
      return 1
    request = {
      'agent': args.agent or 'OpenSSH-AuthorizedKeys',
      'request': 'AuthorizeSSHCommand',
      'args': {
        'command': command,
        'key-id': args.key_id,
        'username': args.username
      }
    }
  elif args.type in ('pre-receive', 'post-receive'):
    # TODO: repository, refs
    request = {
      'agent': args.agent or 'GitHook',
      'request': 'GitPreReceive' if args.type == 'pre-receive' else 'GitPostReceive',
      'args': {
        'repository': repository,
        'refs': refs
      }
    }
  elif args.type == 'update':
    if not args.refname or not args.sha1_old or not args.sha1_new:
      parser.error('--type update requires refname, sha1_old and sha1_new arguments')
    if args.sha1_new == '0'*40:
      type = 'delete'
    else:
      type = subprocess.check_output(['git', 'cat-file', '-t', args.sha1_new]).decode().strip()
    request = {
      'agent': args.agent or 'GitHook',
      'request': 'GitUpdate',
      'args': {
        'key-id': args.key_id,
        'username': args.username,
        'repository': repository,
        'sha1-old': args.sha1_old,
        'sha1-new': args.sha1_new,
        'type': type
      }
    }
  else:
    parser.error('invalid --type')

  sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  sock.connect(args.server)
  sock = StructSocketIO(sock)
  sock.writejson(request)
  response = sock.readjson()

  message = response.get('args', {}).get('message')
  if message:
    print(message)
  if response['response'] != 'Allow':
    return 1

  if args.type == 'ssh':
    response.setdefault('args', {})
    command = shlex.split(response['args'].get('command', command))
    os.environ.update(response['args'].get('env', {}))
    cwd = response['args'].get('cwd') or os.getcwd()
    del os.environ['SSH_ORIGINAL_COMMAND']
    os.environ['GITAUTH_USERNAME'] = args.username
    os.environ['GITAUTH_KEYID'] = args.key_id
    return subprocess.call(command, cwd=cwd)

  return 0


if require.main == module:
  sys.exit(main())
