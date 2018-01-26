
import argparse
import json
import os
import socket
import struct
import sys

parser = argparse.ArgumentParser(prog='git-auth-client')
parser.add_argument('server', nargs='?')
parser.add_argument('--username')
parser.add_argument('--tags')
parser.add_argument('--test', action='store_true')


def main(argv=None):
  args = parser.parse_args(argv)
  if args.test:
    import {PermitAllHandler} from './auth'
    import {GitAuth} from './server'
    os.makedirs('test', exist_ok=True)
    args.server = args.server or 'test/auth.sock'
    server = GitAuth(
      handler_class = PermitAllHandler,
      authorized_keys_file='test/authorized_keys.test.txt',
      auth_socket = args.server,
      prefix = 'test/repos'
    )
    server.keys.flush()
    server.add_key('JohnSmith', 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC54h9MD7anBH2bbpSM9cDWPB4uGyHMewU87qpXULJ+y2Nlb/s9CGGrlnhKXwrRTfq71IYDloVIauZn+DgfloFGOjKXMjNO1wYPsB66hdOOhRzOALq8l4OAI8ppxamJ8cJfx7ZU4i9MOFzsjidEgFJZ7RbjxB91/eStXjFm2eiScd6kOT/suwSbpOGhr4tUaCabA9RSVzJvNyyeVgiTsbT4H0oWTqrTVGPs3PNWPLhq3P4qwISGKO4u3iynMSnCppsUlozg93fsPFNkpbwsbgMp5I+rnmdGH3wlLaOxBpwUO56iEodsDvKu//y1Bh8Re/NL/pJjijQm5mSGboFlHmQ/ niklas@niklas-PC')
    server.keys.write()
    with open(server.keys.filename) as fp:
      print(fp.read())
    print('Starting test server ...')
    server.start()

  if not args.username:
    parser.error('--username is required')
    return 0

  command = os.environ.get('SSH_ORIGINAL_COMMAND')
  request = json.dumps({
    'username': args.username,
    'tags': args.tags.split(',' if ',' in args.tags else ' ') if args.tags else [],
    'command': command or '',
    'repository': 'NotAClue'
  }).encode('utf8')
  sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  sock.connect(args.server)
  sock.send(struct.pack('I', len(request)))
  sock.send(request)
  nbytes = struct.unpack('I', sock.recv(4))[0]
  response = json.loads(sock.recv(nbytes).decode('utf8'))
  print(response)

  if args.test:
    print('Shutting down test server ...')
    server.shutdown()


if require.main == module:
  sys.exit(main())
