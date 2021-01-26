import socket
from . import errors
import struct
from typing import Union
from copy import deepcopy


class BaseField(object):
    def __init__(self, value: Union[str, int], fmt: str = None):
        if type(self) == BaseField:
            raise RuntimeError(f"{self.__class__.__name__} Creation isn't allowed")  # noqa : E501
        elif fmt is None:
            raise errors.InvalidFieldError("Missing bytes format string.")
        elif not isinstance(fmt, (int, bytes, str)):
            msg = f"Expecting {fmt!r} as int, str, or bytes, not "
            msg += f"{type(fmt).__name__}"
            raise errors.InvalidFieldError(msg)
        if type(fmt) == bytes:
            fmt = fmt.decode()
        if not fmt.isalpha() and not (fmt[0].isdigit() and fmt[1:].isalpha()):
            msg = f"Invalid format characters in {fmt!r}"
            raise errors.InvalidFieldError(msg)
        self.fmt = '!' + fmt
        self.original = value
        self.value = None

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return repr(self.original)

    def __bytes__(self):
        if self.value is None:
            self.value = struct.pack(self.fmt, self.original)
        return self.value

    def __copy__(self):
        pass

    def __deepcopy__(self, memo={}):
        id_self = id(self)
        if memo is not None:
            _copy = memo.get(id_self)
        else:
            _copy = None
        if _copy is None:
            _copy = deepcopy(self.original)
        return _copy


class IPv4Field(BaseField):
    __slots__ = ("ip",)

    def __init__(self, value: str, fmt: str = '4s'):
        if fmt != '4s':
            msg = f"IPv4 IP Field requires 4s, not {fmt!r}"
            raise errors.InvalidFieldError(msg)
        super().__init__(value, fmt)
        try:
            self.ip = socket.gethostbyname(self.original)
        except socket.gaierror:
            msg = f"{self.original} is an invalid hostname."
            raise errors.InvalidFieldError(msg) from None
        self.value = socket.inet_aton(self.ip)


class CharField(BaseField):
    def __init__(self, value: Union[str, int], fmt: str = 'B'):
        super().__init__(value, fmt)


class ShortField(BaseField):
    def __init__(self, value: Union[str, int], fmt: str = 'H'):
        super().__init__(value, fmt)


class LongField(BaseField):
    def __init__(self, value: Union[str, int], fmt: str = 'L'):
        super().__init__(value, fmt)
