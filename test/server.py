
import shlex
import {AuthHandler, GitAuth} from '@NiklasRosenstein/git-auth'

class MyAuthHandler(AuthHandler):

  def authorize_ssh_command(self, request):
    command = shlex.split(request.command)
    if len(command) >= 2 and command[0] in ('git-receive-pack', 'git-upload-pack'):
      repository = command[1]
      if repository.startswith(request.username + '/'):
        return request.allow(command='bash -c :')  # noop
    request.print("You don't have access to this repository.")
    return request.deny()

server = GitAuth(
  handler_class = MyAuthHandler,
  authorized_keys_file = 'authorized_keys',
  auth_socket = 'auth.sock',
  prefix = 'repos'
)
server.start(in_thread=False)
