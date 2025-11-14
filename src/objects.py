from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

import copy
import hashlib
import json
import re

import constants as const

# perform syntactic checks. returns true iff check succeeded
OBJECTID_REGEX = re.compile(r"^[0-9a-f]{64}$")
def validate_objectid(objid_str):
    return bool(OBJECTID_REGEX.match(objid_str))

PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_pubkey(pubkey_str):
    return bool(PUBKEY_REGEX.match(pubkey_str))

SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")
def validate_signature(sig_str):
    return bool(SIGNATURE_REGEX.match(sig_str))

NONCE_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_nonce(nonce_str):
    return bool(NONCE_REGEX.match(nonce_str))

TARGET_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_target(target_str):
    return bool(TARGET_REGEX.match(target_str))

def validate_transaction_input(in_dict, object_db):
    for txin in in_dict.get("inputs", []):
        txid = txin.get("txid")
        index = txin.get("index")
        sig = txin.get("signature")

        if not (txid and index is not None and sig):
            return False, "Missing input fields"

        if not object_db.has_object(txid):
            return False, "UNKNOWN_OBJECT"

        prev_tx = object_db.get_object(txid)
        outputs = prev_tx.get("outputs", [])
        if index < 0 or index >= len(outputs):
            return False, "Invalid outpoint"

        # Verify signature
        pubkey_hex = outputs[index]["pubkey"]
        if not validate_pubkey(pubkey_hex):
            return False, "Invalid pubkey"

        message = canonicalize(prev_tx).decode()  # message signed
        try:
            pubkey_bytes = bytes.fromhex(pubkey_hex)
            sig_bytes = bytes.fromhex(sig)
            Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(sig_bytes, message)
        except InvalidSignature:
            return False, "Invalid signature"

    return True, None

def validate_transaction_output(out_dict):
    for out in out_dict.get("outputs", []):
        pubkey = out.get("pubkey")
        value = out.get("value")
        if not validate_pubkey(pubkey):
            return False
        if not isinstance(value, int) or value < 0:
            return False
    return True

def validate_transaction(trans_dict):
    if not isinstance(trans_dict, dict):
        return False
    if "id" not in trans_dict or "inputs" not in trans_dict or "outputs" not in trans_dict:
        return False
    return True

def validate_transaction_balance(tx_dict, object_db):
    """
    Weak law of conservation: sum(inputs) >= sum(outputs)
    """
    if len(tx_dict.get("inputs", [])) == 0:
        # Coinbase transaction
        return True

    total_in = 0
    for txin in tx_dict.get("inputs", []):
        txid = txin["txid"]
        index = txin["index"]
        prev_tx = object_db.get_object(txid)
        total_in += prev_tx["outputs"][index]["value"]

    total_out = sum(out["value"] for out in tx_dict.get("outputs", []))
    return total_in >= total_out

def validate_transaction_full(tx_dict, object_db):
    if tx_dict.get("type") != "transaction":
        return False, "INVALID_FORMAT"

    if not validate_transaction_output(tx_dict):
        return False, "INVALID_FORMAT"

    valid_inputs, err = validate_transaction_input(tx_dict, object_db)
    if not valid_inputs:
        return False, err

    if not validate_transaction_balance(tx_dict, object_db):
        return False, "INVALID_BALANCE"

    return True, None


def validate_block(block_dict):
    # todo
    return True

def validate_object(obj_dict):
    if "type" not in obj_dict:
        return False
    obj_type = obj_dict["type"]
    if obj_type == "transaction":
        return validate_transaction(obj_dict)
    elif obj_type == "block":
        return validate_block(obj_dict)
    else:
        # unsupported object type
        return False

def get_objid(obj_dict):
    canonical_bytes = canonicalize(obj_dict)
    h = hashlib.blake2s()
    h.update(canonical_bytes)
    return h.hexdigest()

# perform semantic checks

# verify the signature sig in tx_dict using pubkey
def verify_tx_signature(tx_dict, sig, pubkey):
    try:
        pubkey_obj = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey))
        pubkey_obj.verify(bytes.fromhex(sig), canonicalize(tx_dict))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False

class TXVerifyException(Exception):
    pass

def verify_transaction(tx_dict, input_txs):
    pass # todo 

class BlockVerifyException(Exception):
    pass

# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, utxo):
    # todo
    return 0

# verify that a block is valid in the current chain state, using known transactions txs
def verify_block(block, prev_block, prev_utxo, prev_height, txs):
    # todo
    return 0

class ObjectDB:
    """Stores known objects persistently."""
    def __init__(self, filename="objects.json"):
        self.filename = filename
        try:
            with open(filename, "r") as f:
                self.db = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.db = {}

    def add_object(self, obj_dict):
        objid = get_objid(obj_dict)
        if objid in self.db:
            return False
        self.db[objid] = obj_dict
        self._persist()
        return True

    def has_object(self, objid):
        return objid in self.db

    def get_object(self, objid):
        return self.db.get(objid, None)

    def _persist(self):
        with open(self.filename, "w") as f:
            json.dump(self.db, f, indent=2)