## git-auth

Git-auth is an OpenSSH user-authentication layer for Git servers with
fine-grain permission control for Python 3 + Node.py. It uses a socket
file to communicate between the SSH process and the Git-auth server.

### Example

Creating a custom authentication handler and starting the Git-auth server:

```python
import {GitAuth, AuthHandler, Permissions} from '@NiklasRosenstein/git-auth'

class MyAuthHandler(AuthHandler):

  def get_permissions(self, user, repository, key):
    if repository.startswith(user + '/'):
      return Permissions.owner
    return Permissions.read

auth_server = GitAuth(
  handler_class = MyAuthHandler,
  authorized_keys_file = '/home/git/.ssh/authorized_keys',
  auth_socket = '/home/git/.ssh/git-auth.sock',
  prefix = '/home/git'
)
auth_server.start()
```

Adding keys to the OpenSSH `authorized_keys` file:

```python
auth_server.authorized_keys.add(
  public_key = 'ssh-rsa AAAB3Nz...',
  username = 'JohnSmith'
)
auth_server.authorized_keys.write()
```

Listing keys for a user:

```python
for entry in auth_server.authorized_keys.by_user('JohnSmith'):
  print(entry.public_key.comment)
```

Make sure to stop the server when your application exits:

```python
auth_server.stop()
```
