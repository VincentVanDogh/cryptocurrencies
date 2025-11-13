import ipaddress

from src.message.msgexceptions import ErrorInvalidFormat

"""
host
host_formated == host for hostname and ipv4
"""
class Peer:
    def __init__(self, host_str, port:int):
        self.port = port
        self.host_formated = ''
        self.host = ''

        # todo: validate host_str and populate properties
        try:
            # Try IPv4
            ip = ipaddress.ip_address(host_str)
            if ip.version != 4:
                raise ErrorInvalidFormat("Only IPv4 supported")
            self.host = str(ip)
            self.host_formated = self.host
        except ErrorInvalidFormat | ValueError:
            # Not an IP, so treat as hostname
            if not (3 <= len(host_str) <= 50):
                raise ErrorInvalidFormat(f"Invalid hostname length: {host_str}")
            if not any(c.isalpha() for c in host_str):
                raise ErrorInvalidFormat(f"Hostname missing letters: {host_str}")
            if "." not in host_str[1:-1]:
                raise ErrorInvalidFormat(f"Invalid hostname format: {host_str}")
            self.host = host_str.lower()
            self.host_formated = self.host
            raise ErrorInvalidFormat

    def __str__(self) -> str:
        return f"{self.host_formated}:{self.port}"

    def __eq__(self, o: object) -> bool:
        return isinstance(o, Peer) and self.host == o.host \
            and self.port == o.port

    def __hash__(self) -> int:
        return (self.port, self.host).__hash__()

    def __repr__(self) -> str:
        return f"Peer: {self}"
