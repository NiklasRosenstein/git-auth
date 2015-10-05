# `git_auth` - a Git authentication layer alternative

__Features__

- Fine grain access control
- Repository management via the command line
- Support for webhooks

__Configuration__

git_auth is configured with the `git_auth_config.py` Python script. The
access control can be customized to an arbitrary extent, but usually it
is enough to grant or prevent access to certain directories for a user.

    import os
    import git_auth

    repository_root = os.path.expanduser('~/repos')
    access_control = git_auth.SimpleAccessControl()

    def command_hello(auth, args):
      print("Hello,", args[0])

__Manage Repositories__

A user with managing privilieges can connect via SSH and use the integrated
limited shell to create new, rename or delete repositories. The following
commands are available:

    repo create <name>
      Create a new Git repository. Any number of sub directories are allowed
      as long as none of the parent sub directories contain a `.git` directory.

    repo rename <old> <new>
      Rename a repository. The repository name restrictions of the `repo
      create` command apply.

    repo delete <repo>
      Delete the specified repository.

    repo show [<filter>]
      Show a list of all repositories that the user can read, write or
      manage depending on the specified filter. The filter defaults to "all".
      Valid values are "read", "write", "manage" and "all".

    repo webhook install <repo> <url>
      Install a webhook for the specified repository. The specified URL
      will be sent a HTTP POST request with information about what 
      happened to the repository (eg. updated, deleted, renamed).

    repo webhook show <repo>
      Show a list of webhooks installed for the specified repository.

    repo webhook remove <repo> <url>
      Remo a webhook URL from the specified repository.
