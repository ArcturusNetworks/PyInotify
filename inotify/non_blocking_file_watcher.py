import inotify.calls
import inotify.constants
import os
import struct
import collections
import io

_HEADER_STRUCT_FORMAT = 'iIII'
_STRUCT_HEADER_LENGTH = struct.calcsize(_HEADER_STRUCT_FORMAT)
_INOTIFY_EVENT = collections.namedtuple(
                    '_INOTIFY_EVENT',
                    [
                        'wd',
                        'mask',
                        'cookie',
                        'len',
                    ])

class NonBlockingFileWatcher:
    """
    brief: Provides access to the linux inotify api.
    default functionality:
        By Default, this class will monitor the file listed by filePath for 
        events where another process finished making meaningful edits to the file
    On Destruction:
        This class handles destructing the internal file descriptor when
        all references to the instance are dropped
    """
    def __init__(self, filePath, mask=inotify.constants.IN_CLOSE_WRITE) -> None:
        self.__inotify_fd = inotify.calls.inotify_init1(inotify.constants.IN_NONBLOCK)
        inotify.calls.inotify_add_watch(self.__inotify_fd, filePath.encode('utf8'), mask)
        pass

    def __del__(self):
        os.close(self.__inotify_fd)

    def checkForEvents(self) -> bool:
        # Try to read on the non-blocking file
        try:
            b = os.read(self.__inotify_fd, 1024)
        except io.BlockingIOError:
            return False
        if not b: return False # NO CHANGES

        length = len(b)

        if length < _STRUCT_HEADER_LENGTH:
            return False

        # We have, at least, a whole-header in the buffer.

        peek_slice = b[:_STRUCT_HEADER_LENGTH]

        header_raw = struct.unpack(
                        _HEADER_STRUCT_FORMAT,
                        peek_slice)
        header = _INOTIFY_EVENT(*header_raw)

        event_length = (_STRUCT_HEADER_LENGTH + header.len)
        if length < event_length:
            return False
        return True

