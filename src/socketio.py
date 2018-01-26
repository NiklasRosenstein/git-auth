" Simple TCP communication protocol. "

import json
import struct
import socket


class SocketIO:

  def __init__(self, sock):
    self._sock = sock
    self._closed = False

  def __enter__(self):
    return self

  def __exit__(self, *a):
    self.close()

  def readable(self):
    return True

  def writable(self):
    return True

  def seekable(self):
    return False

  def closed(self):
    return self._closed

  def close(self):
    if not self._closed:
      self._sock.close()
      self._closed = True

  def read(self, n):
    return self._sock.recv(n)

  def write(self, data):
    return self._sock.send(data)


class StructSocketIO(SocketIO):

  def reads(self, fmt, allow_empty=False):
    size = struct.calcsize(fmt)
    data = self.read(size)
    if len(data) == 0 and allow_empty:
      return None
    if len(data) != size:
      raise InsufficientDataReceived(size, len(data))
    return struct.unpack(fmt, data)

  def writes(self, fmt, *args):
    size = struct.calcsize(fmt)
    written = self.write(struct.pack(fmt, *args))
    if size != written:
      raise IncompleteTransmission(size, written)
    return written

  def readbuf(self, allow_empty=False):
    res = self.reads('!I', allow_empty=allow_empty)
    if res is None:
      return None
    return self.read(res[0])

  def writebuf(self, buf):
    header = self.writes('!I', len(buf))
    written = self.write(buf)
    if written != len(buf):
      raise IncompleteTransmission(len(buf), written)
    return header + written

  def readjson(self, encoding='utf8', allow_empty=False):
    data = self.readbuf(allow_empty=allow_empty)
    if data is None:
      return None
    return json.loads(data.decode(encoding))

  def writejson(self, data, encoding='utf8'):
    return self.writebuf(json.dumps(data).encode(encoding))


class InsufficientDataReceived(IOError):

  def __init__(self, expected, received):
    self.expected = expected
    self.received = received

  def __str__(self):
    return 'expected {!r}, received {!r}'.format(self.expected, self.received)


class IncompleteTransmission(IOError):

  def __init__(self, expected, transfered):
    self.expected = expected
    self.transfered = transfered

  def __str__(self):
    return 'expected {!r}, transfered {!r}'.format(self.expected, self.transfered)
