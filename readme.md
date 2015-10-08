# `git_auth` - a Git authentication layer alternative

__Features__

- Configure read, write and manage access to repositories
- Repository management via the command line
- Simple webhook support

__Future Plans__

- [ ] Ability to restrict access to branches of a repository
- [ ] Detailed information for webhooks (using Git update hook)
- [ ] Manage OpenSSH keys from the command-line

__Configuration__

git_auth is configured with the `git_auth_config.py` Python script. The
access control can be customized to an arbitrary extent, but usually it
is enough to grant or prevent access to certain directories for a user.

    import os
    import git_auth

    git_auth_bin = os.path.join(os.path.dirname(__file__), 'bin', 'git-auth.sh')
    repository_root = os.path.expanduser('~/repos')
    access_controller = git_auth.SimpleAccessController()
    ssh_key_manager = git_auth.OpenSSHKeyManager()
    host_name = 'my_git_server'

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

    repo delete <repo> [-f/--force]
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

__Other Shell Commands__

    shell
      Users with root access can enter the interactive shell using this
      command.

    ssh-key [-u/--user <user>]
      Command to operate on SSH keys. The `ssh_key_manager` must be
      configured in `git_auth_config`. Currently, only OpenSSH is
      supported. This command does nothing on its own.
      Root users can use the -u/--user option to change the user that
      the ssh-key is added to/deleted from (depending on the subcommand).

    ssh-key add <name> [<pub_key>]
      Add a SSH public key for the current user account. Users with root
      access are able to add an SSH key for a specific user account by
      passing the -u/--user option. If the <pub_key> is not specified,
      the key is read from stdin.

    ssh-key list
      List all installed SSH keys. Users with root access may use the
      -u/--user option to view the public SSH keys of another user.

    ssh-key del <name> [-f/--force]
      Delete the SSH key with the specified <name>. Users with root
      access can delete SSH keys of other users. If -f/--force is
      passed, you will not be asked for confirmation to delete the key.

    ssh-key update
      Root users can use this command to update all SSH keys to use
      the correct git-auth command. This should be called when the
      installation path of git-auth changes.

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
