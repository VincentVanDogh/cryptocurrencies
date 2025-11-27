import pytest
from Peer import Peer
from message.msgexceptions import ErrorInvalidFormat

def test_valid_ipv4():
    p = Peer("192.168.1.5", 8333)
    print(p)
    assert p.host == "192.168.1.5"
    assert str(p) == "192.168.1.5:8333"

def test_valid_hostname():
    p = Peer("node.example.com", 5000)
    print(p)
    assert p.host == "node.example.com"
    assert str(p) == "node.example.com:5000"

def test_invalid_hostname_no_dot():
    try:
        Peer("localhost", 8000)
    except ErrorInvalidFormat:
        print("Caught expected ErrorInvalidFormat for localhost")
    else:
        raise AssertionError("Expected ErrorInvalidFormat for localhost")

def test_invalid_ipv4():
    try:
        Peer("999.10.0.1", 1234)
    except ErrorInvalidFormat:
        print("Caught expected ErrorInvalidFormat for invalid IPv4")
    else:
        raise AssertionError("Expected ErrorInvalidFormat for invalid IPv4")


if __name__ == "__main__":
    test_valid_ipv4()
    test_valid_hostname()
    test_invalid_hostname_no_dot()
    test_invalid_ipv4()
    print("✅ All tests passed!")
