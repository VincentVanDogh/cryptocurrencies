import unittest
import os
from Peer import Peer
from peers import Peers  # import Peers class from peer.py
import peer_db

class TestPeers(unittest.TestCase):

    def setUp(self):
        # remove any existing files
        if os.path.exists("peers.json"):
            os.remove("peers.json")
        if os.path.exists("peers.csv"):
            os.remove("peers.csv")
        self.peers = Peers()

    def test_add_and_remove_peer(self):
        p = Peer("127.0.0.1", 18018)
        self.peers.addPeer(p)
        self.assertIn(p, self.peers.getPeers())

        self.peers.removePeer(p)
        self.assertNotIn(p, self.peers.getPeers())

    def test_save_and_reload_peers(self):
        p1 = Peer("127.0.0.1", 18018)
        p2 = Peer("example.com", 18018)
        self.peers.addPeer(p1)
        self.peers.addPeer(p2)
        self.peers.save()

        # reload
        new_peers = Peers()
        self.assertIn(p1, new_peers.getPeers())
        self.assertIn(p2, new_peers.getPeers())

    def test_peer_db_store_and_load(self):
        p = Peer("8.8.8.8", 18018)
        peer_db.store_peer(p)
        loaded = peer_db.load_peers()
        self.assertIn(p, loaded)

    def test_peer_db_remove_peer(self):
        p = Peer("example.com", 18018)
        peer_db.store_peer(p)
        peer_db.remove_peer(p)
        loaded = peer_db.load_peers()
        self.assertNotIn(p, loaded)

if __name__ == "__main__":
    unittest.main()
