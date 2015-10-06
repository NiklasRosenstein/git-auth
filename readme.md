# `git_auth` - a Git authentication layer alternative

__Features__

- Configure read, write and manage access to repositories
- Repository management via the command line
- Simple webhook support

__Future Plans__

- [ ] Ability to restrict access to branches of a repository
- [ ] Detailed information for webhooks (using Git update hook)

__Configuration__

git_auth is configured with the `git_auth_config.py` Python script. The
access control can be customized to an arbitrary extent, but usually it
is enough to grant or prevent access to certain directories for a user.

    import os
    import git_auth

    repository_root = os.path.expanduser('~/repos')
    access_controller = git_auth.SimpleAccessControl()
    host_name = "my_git_server"

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

    repo describe <repo> [<description>]
      Show or set the description of the specified repository.

    repo list
      Show a list of all repositories that the user can read from or
      write to.

    repo install-hook <repo> <name> <url>
      Install a webhook for the specified repository. The specified URL
      will be sent a HTTP POST request with information about what 
      happened to the repository (eg. updated, deleted, renamed).

    repo list-hooks <repo>
      Show a list of webhooks installed for the specified repository.

    repo remove-hook <repo> <name>
      Remo a webhook from the specified repository.

__Webhooks__

Webhooks are currently only implemented by sending an POST notification to
registered URLs when `git-receive-pack` was called. The data that is sent to
the server is in JSON format:

    {
      "host": "<configured host_name>",
      "repo": "<repository name>",
      "event": "receive-pack",
    }

It is planned to provide more detailed information for web hooks (eg. the
old and new commit hash) by leveraging the Git "update" repository hook.
