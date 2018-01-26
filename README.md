## git-auth

Git-auth is an OpenSSH user-authentication layer for Git servers with
fine-grain permission control for Python 3 + Node.py. It uses a socket
file to communicate between the SSH process and the Git-auth server.

### Example

Creating a custom authentication handler and starting the Git-auth server:

```python
import shlex
import {GitAuth, AuthHandler, Permissions} from '@NiklasRosenstein/git-auth'

class MyAuthHandler(AuthHandler):

  def authorize_ssh_command(self, request):
    command = shlex.split(request.command)
    if len(command) >= 2 and command[0] in ('git-receive-pack', 'git-upload-pack'):
      repository = command[1]
      if repository.startswith(user + '/'):
        return request.allow()
    request.print("You don't have access to this repository.")
    return request.deny()

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

### Auth Server API

The authentication server uses a JSON-based TCP communication protocol which
operates on a strict Request-Response schema. A single connection may perform
multiple requests by sending the next after the response to the previous
request has been received.

Every communication between the server and the client follows this
protocol:

    [ ------------------------------------------------------- ]
    [ 4 bytes unsigned integer network byte order payload size]
    [          n bytes JSON payload encoded as UTF8           ]
    [ ------------------------------------------------------- ]

#### AuthorizeSSHCommand

This request is invoked via the OpenSSH `authorized_keys` file to verify
that the user has access to the command that is supposed to be executed.
This request will invoke the `AuthHandler.authorize_ssh_command()` method.

```json
{
  "agent": "OpenSSH-AuthorizedKeys",
  "request": "AuthorizeSSHCommand",
  "args": {
    "command": "git-receive-pack JohnSmith/somerepo.git",
    "key-id": "d3b07384d113edec49eaa6238ad5ff00",
    "username": "JohnSmith"
  }
}
```

Possible response:

```json
{
  "request": "AuthorizeSSHCommand",
  "response": "Allow",
  "args": {
    "command": "git-receive-pack JohnSmith/somerepo.git",
    "cwd": null,
    "env": {}
  }
}
```

If the access is denied, the `"response"` will be `"Deny"` and the
`"command"` field will be set to `null`.

#### GitPreReceive

This requres is invoked via a repositories' `pre-receive` hook and is used to
access `AuthHandler.git_pre_receive()`.

```json
{
  "agent": "GitHook",
  "request": "GitPreReceive",
  "args": {
    "key-id": "d3b07384d113edec49eaa6238ad5ff00",
    "username": "JohnSmith",
    "repository": "/home/git/JohnSmit/somerepo.git",
    "refs": [
      "refs/heads/master",
      "refs/tags/v1.0.0"
    ]
  }
}
```

Possible response:

```json
{
  "request": "GitPreReceive",
  "response": "Allow",
  "args": {
    "message": ""
  }
}
```

#### GitUpdate

This request is invoked via a repositories' `update` hook and is used to
access `AuthHandler.git_update()`.

```json
{
  "agent": "GitHook",
  "request": "GitUpdate",
  "args": {
    "key-id": "d3b07384d113edec49eaa6238ad5ff00",
    "username": "JohnSmith",
    "repository": "/home/git/JohnSmit/somerepo.git",
    "refname": "refs/tags/v1.0.0",
    "sha1-old": "0000000000000000000000000000000000000001",
    "sha1-new": "0000000000000000000000000000000000000000",
    "type": "delete"
  }
}
```

Possible response (depending on the behaviour of your `AuthHandler`):

```json
{
  "request": "GitUpdate",
  "response": "Deny",
  "args": {
    "message": "Can not delete refs/tags/v1.0.0"
  }
}
```

#### GitPostReceive

This request is invoked via a repositories' `post-receive` hook and is used
to access `AuthHandler.git_post_receive()`.

```json
{
  "agent": "GitHook",
  "request": "GitPostReceive",
  "args": {
    "key-id": "d3b07384d113edec49eaa6238ad5ff00",
    "username": "JohnSmith",
    "repository": "/home/git/JohnSmit/somerepo.git",
    "refs": [
      "refs/heads/master",
      "refs/tags/v1.0.0"
    ]
  }
}
```

### Error Responses

```json
{
  "error": "ErrorType"
}
```

Possible error types:

* `InvalidDataReceived`
* `InvalidRequest`
