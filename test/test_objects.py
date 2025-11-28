import unittest
import copy
from objects import (
    validate_transaction,
    verify_transaction,
    ErrorInvalidFormat,
    ErrorUnknownObject,
)

class TestTransactions(unittest.TestCase):

    def setUp(self):
        # Minimal valid normal transaction
        self.tx1 = {
            "type": "transaction",
            "inputs": [
                {
                    "outpoint": {"txid": "a"*64, "index": 0},
                    "sig": "b"*128
                }
            ],
            "outputs": [
                {"pubkey": "c"*64, "value": 1000}
            ]
        }

        # Minimal valid coinbase transaction
        self.coinbase_tx = {
            "type": "transaction",
            "height": 1,
            "outputs": [
                {"pubkey": "d"*64, "value": 50_000_000_000_000}
            ]
        }

    def test_valid_transaction_syntax(self):
        # validate normal transaction
        with self.assertRaises(ErrorUnknownObject):
            validate_transaction(self.tx1)  # tx1 has unknown input, so semantic fails

    def test_valid_coinbase_transaction(self):
        # coinbase tx should pass syntax
        try:
            validate_transaction(self.coinbase_tx)
        except ErrorInvalidFormat:
            self.fail("Coinbase transaction failed syntax validation")

    def test_verify_transaction_unknown_input(self):
        # simulate semantic verification with missing input tx
        input_txs = {}  # empty dict = unknown input
        with self.assertRaises(ErrorUnknownObject):
            verify_transaction(self.tx1, input_txs)

    def test_verify_transaction_duplicate_input(self):
        tx_copy = copy.deepcopy(self.tx1)
        # duplicate input
        tx_copy['inputs'].append(copy.deepcopy(tx_copy['inputs'][0]))
        input_txs = {"a"*64: {"type": "transaction", "outputs": [{"pubkey": "c"*64, "value": 1000}]}}
        with self.assertRaises(Exception):
            verify_transaction(tx_copy, input_txs)

if __name__ == '__main__':
    unittest.main()
