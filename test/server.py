
import {AuthHandler, GitAuth} from '@NiklasRosenstein/git-auth'

server = GitAuth(
  handler_class = AuthHandler,
  authorized_keys_file = 'authorized_keys',
  auth_socket = 'auth.sock',
  prefix = 'repos'
)
server.start(in_thread=False)
