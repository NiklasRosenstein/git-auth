
import enum
import io


class _Request:

  def __init__(self, key_id, username):
    self.buffer = io.StringIO()
    self.key_id = key_id
    self.username = username
    self.allowed = False

  def print(self, *objects, **kwargs):
    kwargs['file'] = self.buffer
    print(*objects, **kwargs)

  def allow(self):
    self.allowed = True
    return self

  def deny(self):
    self.allowed = False
    return self


class AuthorizeSSHCommand(_Request):

  def __init__(self, key_id, username, command):
    super().__init__(key_id, username)
    self.command = command
    self.env = {}

  def allow(self, command=None, env=None):
    self.allowed = True
    if command is not None:
      self.command = command
    if env is not None:
      self.env.update(env)
    return self


class GitPreReceive(_Request):

  def __init__(self, key_id, username, repository, refs):
    super().__init__(key_id, username)
    self.repository = repository
    self.refs = refs


class GitUpdate(_Request):

  def __init__(self, key_id, username, repository, refname, sha1_old, sha2_new, type):
    super().__init__(key_id, username)
    self.repository = repository
    self.refname = refname
    self.sha1_old = sha1_old
    self.sha2_old = sha2_old
    self.type = type


class GitPostReceive(GitPreReceive):
  pass


class AuthHandler:
  """
  Interface for authentication handlers.
  """

  def __init__(self, auth_instance):
    self.auth_instance = auth_instance

  def authorize_ssh_command(self, request):
    """
    Invoked when an SSH connection is established and OpenSSH invokes the
    Git-auth client via the `authorized_keys` file's command option. The
    *request* is an #AuthorizeSSHCommand object. Use it's `allow()` or
    `deny()` method for the return-value.
    """

    request.print('Hello, World!')
    return request.allow()

  def git_pre_receive(self, request):
    """
    Invoked from a Git `pre-receive` hook.
    """

    return request.allow()

  def git_update(self, request):
    """
    Invoked from a Git `update` hook.
    """

    return request.allow()
