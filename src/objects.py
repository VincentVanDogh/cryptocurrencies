from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

from message.msgexceptions import *

import copy
import hashlib
import json
import re

import constants as const

# perform syntactic checks. returns true iff check succeeded
OBJECTID_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_objectid(objid_str):
    if not isinstance(objid_str, str):
        return False
    return OBJECTID_REGEX.match(objid_str)

PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_pubkey(pubkey_str):
    if not isinstance(pubkey_str, str):
        return False
    return PUBKEY_REGEX.match(pubkey_str)

SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")
def validate_signature(sig_str):
    if not isinstance(sig_str, str):
        return False
    return SIGNATURE_REGEX.match(sig_str)

NONCE_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_nonce(nonce_str):
    if not isinstance(nonce_str, str):
        return False
    return NONCE_REGEX.match(nonce_str)

TARGET_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_target(target_str):
    if not isinstance(target_str, str):
        return False
    return TARGET_REGEX.match(target_str)

# syntactic checks
def validate_transaction_input(in_dict):
    if not isinstance(in_dict, dict):
        raise ErrorInvalidFormat("Not a dictionary!")

    if 'sig' not in in_dict:
        raise ErrorInvalidFormat("sig not set!")
    if not isinstance(in_dict['sig'], str):
        raise ErrorInvalidFormat("sig not a string!")
    if not validate_signature(in_dict['sig']):
        raise ErrorInvalidFormat("sig not syntactically valid!")

    if 'outpoint' not in in_dict:
        raise ErrorInvalidFormat("outpoint not set!")
    if not isinstance(in_dict['outpoint'], dict):
        raise ErrorInvalidFormat("outpoint not a dictionary!")

    outpoint = in_dict['outpoint']
    if 'txid' not in outpoint:
        raise ErrorInvalidFormat("txid not set!")
    if not isinstance(outpoint['txid'], str):
        raise ErrorInvalidFormat("txid not a string!")
    if not validate_objectid(outpoint['txid']):
        raise ErrorInvalidFormat("txid not a valid objectid!")
    if 'index' not in outpoint:
        raise ErrorInvalidFormat("index not set!")
    if not isinstance(outpoint['index'], int):
        raise ErrorInvalidFormat("index not an integer!")
    if outpoint['index'] < 0:
        raise ErrorInvalidFormat("negative index!")
    if len(set(outpoint.keys()) - set(['txid', 'index'])) != 0:
        raise ErrorInvalidFormat("Additional keys present in outpoint!")

    if len(set(in_dict.keys()) - set(['sig', 'outpoint'])) != 0:
        raise ErrorInvalidFormat("Additional keys present!")

    return True # syntax check done

# syntactic checks
def validate_transaction_output(out_dict):
    if not isinstance(out_dict, dict):
        raise ErrorInvalidFormat("Not a dictionary!")

    if 'pubkey' not in out_dict:
        raise ErrorInvalidFormat("pubkey not set!")
    if not isinstance(out_dict['pubkey'], str):
        raise ErrorInvalidFormat("pubkey not a string!")
    if not validate_pubkey(out_dict['pubkey']):
        raise ErrorInvalidFormat("pubkey not syntactically valid!")

    if 'value' not in out_dict:
        raise ErrorInvalidFormat("value not set!")
    if not isinstance(out_dict['value'], int):
        raise ErrorInvalidFormat("value not an integer!")
    if out_dict['value'] < 0:
        raise ErrorInvalidFormat("negative value!")

    if len(set(out_dict.keys()) - set(['pubkey', 'value'])) != 0:
        raise ErrorInvalidFormat("Additional keys present!")

    return True # syntax check done

# syntactic checks
def validate_transaction(trans_dict):
    if not isinstance(trans_dict, dict):
        raise ErrorInvalidFormat("Transaction object invalid: Not a dictionary!") # assert: false

    if 'type' not in trans_dict:
        raise ErrorInvalidFormat("Transaction object invalid: Type not set") # assert: false
    if not isinstance(trans_dict['type'], str):
        raise ErrorInvalidFormat("Transaction object invalid: Type not a string") # assert: false
    if not trans_dict['type'] == 'transaction':
        raise ErrorInvalidFormat("Transaction object invalid: Type not 'transaction'") # assert: false

    if 'outputs' not in trans_dict:
        raise ErrorInvalidFormat("Transaction object invalid: No outputs key set")
    if not isinstance(trans_dict['outputs'], list):
        raise ErrorInvalidFormat("Transaction object invalid: Outputs key not a list")

    index = 0
    for output in trans_dict['outputs']:
        try:
            validate_transaction_output(output)
        except ErrorInvalidFormat as e:
            raise ErrorInvalidFormat(f"Transaction object invalid: Output at index {index} invalid: {e.message}")
        index += 1

    # check for coinbase transaction
    if 'height' in trans_dict:
        # this is a coinbase transaction
        if not isinstance(trans_dict['height'], int):
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Height not an integer")
        if trans_dict['height'] < 0:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Negative height")

        if len(trans_dict['outputs']) > 1:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: More than one output set")

        if len(set(trans_dict.keys()) - set(['type', 'height', 'outputs'])) != 0:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Additional keys present")
        return

    # this is a normal transaction
    if not 'inputs' in trans_dict:
        raise ErrorInvalidFormat("Normal transaction object invalid: Inputs not set")

    if not isinstance(trans_dict['inputs'], list):
        raise ErrorInvalidFormat("Normal transaction object invalid: Inputs not a list")
    for input in trans_dict['inputs']:
        try:
            validate_transaction_input(input)
        except ErrorInvalidFormat as e:
            raise ErrorInvalidFormat(f"Normal transaction object invalid: Input at index {index} invalid: {e.message}")
        index += 1
    if len(trans_dict['inputs']) == 0:
        raise ErrorInvalidFormat(f"Normal transaction object invalid: No input set")

    if len(set(trans_dict.keys()) - set(['type', 'inputs', 'outputs'])) != 0:
        raise ErrorInvalidFormat(f"Normal transaction object invalid: Additional key present")

    return True # syntax check done


# syntactic checks
def validate_block(block_dict):
    # Implement syntactic checks for block structure
    if not isinstance(block_dict, dict):
        raise ErrorInvalidFormat("Block invalid: Not a dictionary!")

    if 'type' not in block_dict:
        raise ErrorInvalidFormat("Block invalid: Type not set!")
    if not isinstance(block_dict['type'], str):
        raise ErrorInvalidFormat("Block invalid: Type not a string")
    if block_dict['type'] != 'block':
        raise ErrorInvalidFormat("Block invalid: type not 'block'")

    # required fields
    required = ['T', 'created', 'miner', 'nonce', 'txids', 'type']
    for k in required:
        if k not in block_dict:
            raise ErrorInvalidFormat(f"Block invalid: {k} missing")

    if not isinstance(block_dict['T'], str) or not validate_target(block_dict['T']):
        raise ErrorInvalidFormat("Block invalid: T invalid")
    if not isinstance(block_dict['created'], int):
        raise ErrorInvalidFormat("Block invalid: created not int")
    if not isinstance(block_dict['miner'], str):
        raise ErrorInvalidFormat("Block invalid: miner not str")
    if not isinstance(block_dict['nonce'], str) or not validate_nonce(block_dict['nonce']):
        raise ErrorInvalidFormat("Block invalid: nonce invalid")
    if not isinstance(block_dict['txids'], list):
        raise ErrorInvalidFormat("Block invalid: txids not a list")
    for txid in block_dict['txids']:
        if not isinstance(txid, str) or not validate_objectid(txid):
            raise ErrorInvalidFormat("Block invalid: txid in txids invalid")

    # previd may be None or a valid objectid
    if 'previd' in block_dict and block_dict['previd'] is not None:
        if not validate_objectid(block_dict['previd']):
            raise ErrorInvalidFormat("Block invalid: previd invalid")

    return True

# syntactic checks
def validate_object(obj_dict):
    if not isinstance(obj_dict, dict):
        raise ErrorInvalidFormat("Object invalid: Not a dictionary!")

    if 'type' not in obj_dict:
        raise ErrorInvalidFormat("Object invalid: Type not set!")
    if not isinstance(obj_dict['type'], str):
        raise ErrorInvalidFormat("Object invalid: Type not a string")

    obj_type = obj_dict['type']
    if obj_type == 'transaction':
        return validate_transaction(obj_dict)
    elif obj_type == 'block':
        return validate_block(obj_dict)

    raise ErrorInvalidFormat("Object invalid: Unknown object type")

def expand_object(obj_str):
    return json.loads(obj_str)

def get_objid(obj_dict):
    return hashlib.blake2s(canonicalize(obj_dict)).hexdigest()

# perform semantic checks

# verify the signature sig in tx_dict using pubkey
def verify_tx_signature(tx_dict, sig, pubkey):
    tx_local = copy.deepcopy(tx_dict)

    for i in tx_local['inputs']:
        i['sig'] = None

    pubkey_obj = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey))
    sig_bytes = bytes.fromhex(sig)

    try:
        pubkey_obj.verify(sig_bytes, canonicalize(tx_local))
    except InvalidSignature:
        return False

    return True

class TXVerifyException(Exception):
    pass

# semantic checks
# assert: tx_dict is syntactically valid
def verify_transaction(tx_dict, input_txs):
    # coinbase transaction
    if 'height' in tx_dict:
        return # assume all syntactically valid coinbase transactions are valid

    # regular transaction
    insum = 0 # sum of input values
    in_dict = dict()
    for i in tx_dict['inputs']:
        ptxid = i['outpoint']['txid']
        ptxidx = i['outpoint']['index']

        if ptxid in in_dict:
            if ptxidx in in_dict[ptxid]:
                raise ErrorInvalidTxConservation(f"The same input ({ptxid}, {ptxidx}) was used multiple times in this transaction")
            else:
                in_dict[ptxid].add(ptxidx)
        else:
            in_dict[ptxid] = {ptxidx}

        if ptxid not in input_txs:
            raise ErrorUnknownObject(f"Transaction {ptxid} not known")

        ptx_dict = input_txs[ptxid]

        # just to be sure
        if ptx_dict['type'] != 'transaction':
            raise ErrorInvalidFormat("Previous TX '{}' is not a transaction!".format(ptxid))

        if ptxidx >= len(ptx_dict['outputs']):
            raise ErrorInvalidTxOutpoint("Invalid output index in previous TX '{}'!".format(ptxid))

        output = ptx_dict['outputs'][ptxidx]
        if not verify_tx_signature(tx_dict, i['sig'], output['pubkey']):
            raise ErrorInvalidTxSignature("Invalid signature from previous TX '{}'!".format(ptxid))

        insum = insum + output['value']

    if insum < sum([o['value'] for o in tx_dict['outputs']]):
        raise ErrorInvalidTxConservation("Sum of inputs < sum of outputs!")

class BlockVerifyException(Exception):
    pass

# apply tx to utxo
# utxo: dict mapping (txid, index) -> value
# returns mining fee (int)
def update_utxo_and_calculate_fee(tx, utxo):
    # coinbase transaction: 'height' present
    if 'height' in tx:
        # coinbase: add its outputs, fee is 0 (fee accounted separately)
        for idx, out in enumerate(tx['outputs']):
            utxo[(get_objid(tx), idx)] = out['value']
        return 0

    # regular tx: compute sum of input values, remove spent UTXOs, add outputs
    insum = 0
    for inp in tx['inputs']:
        ptxid = inp['outpoint']['txid']
        ptxidx = inp['outpoint']['index']
        key = (ptxid, ptxidx)
        if key not in utxo:
            raise ErrorInvalidTxOutpoint(f"Spending non-existing or already spent output {key}")
        insum += utxo[key]

    outs_sum = sum(o['value'] for o in tx['outputs'])
    if insum < outs_sum:
        raise ErrorInvalidTxConservation("Sum of inputs < sum of outputs!")

    # consume inputs
    for inp in tx['inputs']:
        ptxid = inp['outpoint']['txid']
        ptxidx = inp['outpoint']['index']
        key = (ptxid, ptxidx)
        # remove spent output
        del utxo[key]

    # add outputs
    txid = get_objid(tx)
    for idx, out in enumerate(tx['outputs']):
        utxo[(txid, idx)] = out['value']

    fee = insum - outs_sum
    return fee

# verify that a block is valid in the current chain state, using known transactions txs
# - block: block dict
# - prev_block: previous block dict or None
# - prev_utxo: dict mapping (txid, index) -> value (snapshot after prev_block)
# - prev_height: height of prev_block (int) or None
# - txs: dict mapping txid -> transaction dicts that are known locally (from DB)
# Returns: new_utxo dict mapping (txid, index) -> value on success
def verify_block(block, prev_block, prev_utxo, prev_height, txs):
    # syntactic checks first
    validate_block(block)

    # 1) Target must be the network target
    if block['T'] != const.BLOCK_TARGET:
        raise ErrorInvalidFormat("Block target does not match required target")

    # 2) Proof-of-work: use SHA256(canonicalize(block)) <= T
    pow_hash = hashlib.sha256(canonicalize(block)).hexdigest()
    if int(pow_hash, 16) > int(block['T'], 16):
        raise ErrorInvalidFormat("Invalid proof-of-work for block")

    # 3) Parent existence: prev_block argument indicates if parent known
    if block.get('previd') is not None:
        if prev_block is None:
            # caller must handle sending UNKNOWN_OBJECT and pending logic
            raise ErrorUnknownObject(f"Missing parent block {block.get('previd')}")

    # 4) Ensure we have all transactions in this block (txs param should hold them)
    for txid in block['txids']:
        if txid not in txs:
            raise ErrorUnknownObject(f"Missing transaction {txid}")

    # 5) Now validate transactions sequentially and update UTXO
    # Make a working copy of prev_utxo
    working_utxo = copy.deepcopy(prev_utxo) if prev_utxo is not None else {}

    # Prepare a mapping of txid -> txdict for transactions that are "available" for signature checks.
    # Start with txs (transactions from DB) and add processed transactions from this block as we go.
    available_txs = dict(txs)  # shallow copy

    coinbase_count = 0
    coinbase_txid = None

    total_fees = 0

    for idx, txid in enumerate(block['txids']):
        tx = txs[txid]

        # Check syntactic validity of transaction
        try:
            validate_transaction(tx)
        except ErrorInvalidFormat as e:
            raise e

        # detect coinbase
        is_coinbase = 'height' in tx

        if is_coinbase:
            coinbase_count += 1
            if coinbase_count > 1:
                raise ErrorInvalidFormat("More than one coinbase transaction in block")
            if idx != 0:
                raise ErrorInvalidFormat("Coinbase transaction must be at index 0 in txids")
            coinbase_txid = txid

        # build input_txs mapping for verify_transaction: all referenced txids must be present in available_txs
        # (available_txs already contains txs from DB and previously processed txs in the block)
        input_txs = {}
        # Collect referenced txids
        if not is_coinbase:
            for inp in tx['inputs']:
                ptxid = inp['outpoint']['txid']
                if ptxid not in available_txs:
                    # Missing referenced transaction for signature verification
                    raise ErrorUnknownObject(f"Missing referenced transaction {ptxid}")
                input_txs[ptxid] = available_txs[ptxid]

            # perform semantic checks (signature, double usage within tx, conservation)
            verify_transaction(tx, input_txs)

        # Ensure coinbase is not spent within same block: if any later tx refers to coinbase txid -> reject
        if is_coinbase:
            # add coinbase to available_txs (so later txs could reference it, but specification forbids it)
            available_txs[txid] = tx
            # Apply coinbase to utxo (no fee)
            # But per spec, coinbase cannot be spent in same block; we'll check when processing later transactions
            # Add outputs
            for out_idx, out in enumerate(tx['outputs']):
                working_utxo[(txid, out_idx)] = out['value']
            # fee = 0 for coinbase (we track fees from non-coinbase txs)
        else:
            # For regular txs: check UTXO inputs exist in working_utxo
            # update_utxo_and_calculate_fee will raise an exception if outpoint not present
            fee = update_utxo_and_calculate_fee(tx, working_utxo)
            total_fees += fee
            # add to available txs (so future txs in same block can spend its outputs)
            available_txs[txid] = tx

        # After adding tx to available_txs, ensure that no transaction earlier in the block attempted to spend coinbase
        if coinbase_txid is not None and idx > 0:
            # Check inputs of this tx (if any) do not reference coinbase_txid
            if 'inputs' in tx:
                for inp in tx['inputs']:
                    if inp['outpoint']['txid'] == coinbase_txid:
                        raise ErrorInvalidFormat("Coinbase transaction spent within same block (not allowed)")

    # 6) Validate coinbase output constraint: coinbase output <= sum(fees) + BLOCK_REWARD
    if coinbase_count == 1:
        # coinbase is tx at index 0
        cbtx = txs[block['txids'][0]]
        cb_value = cbtx['outputs'][0]['value']
        max_allowed = total_fees + const.BLOCK_REWARD
        if cb_value > max_allowed:
            raise ErrorInvalidFormat("Coinbase output exceeds fees + block reward")

    # If all checks passed, return the new utxo set
    return working_utxo
