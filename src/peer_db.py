from Peer import Peer
from typing import Iterable, Set
import csv
import ipaddress
from src.message.msgexceptions import ErrorInvalidFormat

PEER_DB_FILE = "peers.csv"
MAX_PEERS = 30

def is_valid_peer(peer: Peer) -> bool:
    # check if a Peer has valid host and port
    host = peer.host
    port = peer.port
    if port < 1 or port > 65535:
        return False

    # IPv4 check
    try:
        ipaddress.IPv4Address(host)
        # Reject private IPs
        if ipaddress.IPv4Address(host).is_private:
            return False
        return True
    except ValueError:
        # DNS validation
        if not (3 <= len(host) <= 50):
            return False
        if not any(c.isalpha() for c in host):
            return False
        if host[0] == '.' or host[-1] == '.' or '.' not in host[1:-1]:
            return False
        if not all(c.isalnum() or c in ".-_" for c in host):
            return False
        return True


def store_peer(peer: Peer, existing_peers: Iterable[Peer] = None):
    # append to file
    peers_set = set(existing_peers or [])
    if len(peers_set) >= MAX_PEERS or not is_valid_peer(peer):
        return
    if peer in peers_set:
        return

    # Append to CSV
    with open(PEER_DB_FILE, mode="a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([peer.host, peer.port])


def load_peers() -> Set[Peer]:
    # read from file
    peers = set()
    try:
        with open(PEER_DB_FILE, mode="r", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) != 2:
                    continue
                host, port_str = row
                try:
                    port = int(port_str)
                    peer = Peer(host, port)
                    if is_valid_peer(peer):
                        peers.add(peer)
                except (ValueError, ErrorInvalidFormat):
                    continue
    except FileNotFoundError:
        pass
    return peers

def remove_peer(peer: Peer):
    peers = load_peers()
    if peer in peers:
        peers.remove(peer)
        # Rewrite the file
        with open(PEER_DB_FILE, mode="w", newline="") as f:
            writer = csv.writer(f)
            for p in peers:
                writer.writerow([p.host, p.port])
