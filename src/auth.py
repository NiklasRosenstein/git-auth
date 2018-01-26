
import enum


class AuthHandler:
  """
  Interface for authentication handlers.
  """

  def __init__(self, auth_instance):
    self.auth_instance = auth_instance

  def get_permissions(self, user, repository, tags):
    """
    Return the permissions for the *user* and *repository*. The *tags* is a
    list of strings that were attached to the key. Returns a #Permissions
    enum value.
    """

    raise NotImplementedError


class PermitAllHandler(AuthHandler):

  def get_permissions(self, user, repository, tags):
    return Permissions.owner


class Permissions(enum.Enum):
  read = 'read'
  write = 'write'
  admin = 'admin'
  owner = 'owner'
