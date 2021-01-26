class BasePacketError(ValueError):
    """Base Packet Error"""
    def __init__(self, msg=None):
        if msg:
            if isinstance(msg, str):
                pass
            elif isinstance(msg, bytes):
                msg = msg.decode()
            else:
                try:
                    if isinstance(msg[0], str):
                        msg = '\n'.join(i for i in msg)
                    elif isinstance(msg[0], bytes):
                        msg = b'\n'.join(i for i in msg).decode()
                    else:
                        msg = repr(msg)
                except TypeError:
                    msg = repr(msg)
        else:
            msg = "Packet Error occurred."
        super().__init__(msg)


class PacketOrderError(BasePacketError):
    """Error in Order of Packets"""
    def __init__(self, msg=None):
        if msg is None:
            msg = "A Packet Ordering Error has occurred."
        super().__init__(msg)


class InvalidPacketError(BasePacketError):
    """Invalid Packet"""
    def __init__(self, msg=None):
        if msg is None:
            msg = "Invalid Packet Error."
        super().__init__(msg)


class InvalidPacketAdditionError(InvalidPacketError, TypeError):
    """Invalid Packet Data"""
    def __init__(self, msg=None):
        if msg is None:
            msg = "Invalid Data Type was attempted to be combined to Packet."
        super().__init__(msg)


class InvalidFieldError(InvalidPacketError):
    """Invalid Packet Field"""
    def __init__(self, msg=None):
        if msg is None:
            msg = "Invalid Packet Field."
        super().__init__(msg)
