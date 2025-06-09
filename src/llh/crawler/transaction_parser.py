"""
Transaction parser module for extracting ECDSA signatures from Bitcoin transactions.
Enhanced to support all major Bitcoin transaction types including SegWit.
"""

import logging
import hashlib
from typing import List, Optional, Tuple, Dict, Any

from bitcoin.core import b2x, CTransaction, CTxOut, CTxIn
from bitcoin.core.script import CScript, SignatureHash, SIGHASH_ALL, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_EQUAL, OP_0
from bitcoin.core.key import CPubKey

from ..database.models import Signature

# We will need ecdsa to parse DER-encoded signatures
try:
    from ecdsa.util import sigdecode_der
    from ecdsa.curves import SECP256k1
except ImportError:
    # This should be installed with pyproject.toml
    # If not, it will fail at runtime
    pass


logger = logging.getLogger(__name__)

class TransactionParser:
    """Parser for extracting ECDSA signatures from Bitcoin transactions."""

    def __init__(self):
        """Initialize the transaction parser."""
        self.stats = {
            'processed': 0,
            'p2pkh': 0,
            'p2sh': 0,
            'p2wpkh': 0,
            'p2wsh': 0,
            'p2sh_wrapped_segwit': 0,
            'multisig': 0,
            'p2tr': 0,  # Taproot
            'unknown': 0,
            'signatures_extracted': 0,
            'witness_sigs_extracted': 0,
            'errors': 0,
            'skipped_coinbase': 0,
            'skipped_no_witness': 0
        }

    def _is_p2pkh(self, script: CScript) -> bool:
        """Check if script is Pay-to-Public-Key-Hash (P2PKH)."""
        # P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        try:
            return (len(script) == 25 and
                    script[0] == OP_DUP and
                    script[1] == OP_HASH160 and
                    script[2] == 20 and  # Push 20 bytes
                    script[23] == OP_EQUALVERIFY and
                    script[24] == OP_CHECKSIG)
        except (IndexError, TypeError):
            return False

    def _is_p2sh(self, script: CScript) -> bool:
        """Check if script is Pay-to-Script-Hash (P2SH)."""
        try:
            return script.is_p2sh()
        except AttributeError:
            # Fallback manual check: OP_HASH160 <20 bytes> OP_EQUAL
            try:
                return (len(script) == 23 and
                        script[0] == OP_HASH160 and
                        script[1] == 20 and
                        script[22] == OP_EQUAL)
            except (IndexError, TypeError):
                return False

    def _is_p2wpkh_native(self, script: CScript) -> bool:
        """Check if script is native SegWit P2WPKH."""
        try:
            return script.is_witness_v0_keyhash()
        except AttributeError:
            # Fallback manual check: OP_0 <20 bytes>
            try:
                return (len(script) == 22 and
                        script[0] == OP_0 and
                        script[1] == 20)
            except (IndexError, TypeError):
                return False

    def _is_p2wsh_native(self, script: CScript) -> bool:
        """Check if script is native SegWit P2WSH."""
        try:
            return script.is_witness_v0_scripthash()
        except AttributeError:
            # Fallback manual check: OP_0 <32 bytes>
            try:
                return (len(script) == 34 and
                        script[0] == OP_0 and
                        script[1] == 32)
            except (IndexError, TypeError):
                return False

    def _is_p2tr(self, script: CScript) -> bool:
        """Check if script is Taproot (P2TR)."""
        # P2TR: OP_1 <32 bytes>
        try:
            return (len(script) == 34 and
                    script[0] == 0x51 and  # OP_1
                    script[1] == 32)
        except (IndexError, TypeError):
            return False

    def _is_multisig(self, script: CScript) -> bool:
        """Check if script is multisig (M-of-N)."""
        try:
            if len(script) < 4:
                return False
            # Multisig format: OP_M <pubkey1> <pubkey2> ... OP_N OP_CHECKMULTISIG
            # OP_1 through OP_16 are 0x51 through 0x60
            first_op = script[0]
            if first_op < 0x51 or first_op > 0x60:  # Not OP_1 to OP_16
                return False
            
            # Check if it ends with OP_CHECKMULTISIG (0xae)
            if script[-1] != 0xae:
                return False
            
            # Check second to last byte for N (number of required signatures)
            second_last = script[-2]
            if second_last < 0x51 or second_last > 0x60:
                return False
            
            return True
        except (IndexError, TypeError):
            return False

    def _get_script_type(self, script: CScript) -> str:
        """Determine the script type."""
        if self._is_p2pkh(script):
            return "P2PKH"
        elif self._is_p2sh(script):
            return "P2SH"
        elif self._is_p2wpkh_native(script):
            return "P2WPKH"
        elif self._is_p2wsh_native(script):
            return "P2WSH"
        elif self._is_p2tr(script):
            return "P2TR"
        elif self._is_multisig(script):
            return "MULTISIG"
        else:
            return "UNKNOWN"

    def _extract_pubkey_from_script(self, script_sig: CScript, script_type: str, 
                                  witness_data: Optional[List[bytes]] = None) -> Optional[CPubKey]:
        """Extract public key from scriptSig or witness data based on script type."""
        try:
            if script_type == "P2PKH":
                # P2PKH: <signature> <pubkey>
                ops = list(script_sig.raw_iter())
                if ops and len(ops) >= 2:
                    # raw_iter() can return tuples (opcode, data) or just data
                    pubkey_op = ops[1]
                    pubkey_bytes = None
                    
                    if isinstance(pubkey_op, tuple) and len(pubkey_op) >= 2:
                        pubkey_bytes = pubkey_op[1]  # data part of the tuple
                    elif isinstance(pubkey_op, bytes):
                        pubkey_bytes = pubkey_op  # direct bytes
                    elif isinstance(pubkey_op, int) and len(ops) >= 3:
                        # Skip opcodes that are just integers, try next element
                        next_op = ops[2]
                        if isinstance(next_op, tuple) and len(next_op) >= 2:
                            pubkey_bytes = next_op[1]
                        elif isinstance(next_op, bytes):
                            pubkey_bytes = next_op
                    
                    if isinstance(pubkey_bytes, bytes) and len(pubkey_bytes) in [33, 65]:
                        return CPubKey(pubkey_bytes)
            
            elif script_type == "P2SH":
                # For P2SH, try to extract from redeem script
                ops = list(script_sig.raw_iter())
                if ops:
                    # Last element should be redeem script
                    last_op = ops[-1]
                    redeem_script_bytes = None
                    
                    if isinstance(last_op, tuple) and len(last_op) >= 2:
                        redeem_script_bytes = last_op[1]
                    elif isinstance(last_op, bytes):
                        redeem_script_bytes = last_op
                    elif isinstance(last_op, int) and len(ops) >= 2:
                        # Check previous element
                        prev_op = ops[-2]
                        if isinstance(prev_op, tuple) and len(prev_op) >= 2:
                            redeem_script_bytes = prev_op[1]
                        elif isinstance(prev_op, bytes):
                            redeem_script_bytes = prev_op
                    
                    if isinstance(redeem_script_bytes, bytes):
                        redeem_script = CScript(redeem_script_bytes)
                        
                        if redeem_script.is_witness_v0_keyhash():
                            # P2SH-wrapped P2WPKH - look in witness data
                            if witness_data and len(witness_data) >= 2:
                                pubkey_bytes = witness_data[1]  # witness: <signature> <pubkey>
                                if len(pubkey_bytes) in [33, 65]:
                                    # logger.debug(f"P2SH P2WPKH extracted pubkey: {len(pubkey_bytes)} bytes")
                                    return CPubKey(pubkey_bytes)
                            else:
                                logger.debug(f"P2SH P2WPKH but insufficient witness data: {len(witness_data) if witness_data else 0}")
                        elif redeem_script.is_witness_v0_scripthash():
                            # P2SH-wrapped P2WSH - complex, depends on witness script
                            if witness_data and len(witness_data) >= 2:
                                # Last item is witness script, check if it reveals pubkeys
                                witness_script = witness_data[-1]
                                witness_script_obj = CScript(witness_script)
                                witness_script_type = self._get_script_type(witness_script_obj)
                                
                                if witness_script_type == "P2PKH" and len(witness_data) >= 3:
                                    # P2WSH with P2PKH-like witness script
                                    pubkey_bytes = witness_data[-2]  # Second to last
                                    if len(pubkey_bytes) in [33, 65]:
                                        logger.debug(f"P2SH P2WSH extracted pubkey: {len(pubkey_bytes)} bytes")
                                        return CPubKey(pubkey_bytes)
                                else:
                                    logger.debug(f"P2SH P2WSH witness script type: {witness_script_type}")
                            else:
                                logger.debug(f"P2SH P2WSH but insufficient witness data: {len(witness_data) if witness_data else 0}")
                        else:
                            # Regular P2SH (non-SegWit)
                            redeem_type = self._get_script_type(redeem_script)
                            
                            if redeem_type == "P2PKH":
                                # P2SH-wrapped P2PKH: ... <sig> <pubkey> <redeemScript>
                                if len(ops) >= 3:
                                    pubkey_op = ops[-2]  # Second to last is pubkey
                                    if isinstance(pubkey_op, tuple) and len(pubkey_op) >= 2:
                                        pubkey_bytes = pubkey_op[1]
                                        if isinstance(pubkey_bytes, bytes) and len(pubkey_bytes) in [33, 65]:
                                            return CPubKey(pubkey_bytes)
            
            elif script_type == "P2WPKH":
                # Native SegWit P2WPKH - pubkey is in witness data
                if witness_data and len(witness_data) >= 2:
                    pubkey_bytes = witness_data[1]  # witness: <signature> <pubkey>
                    if len(pubkey_bytes) in [33, 65]:
                        return CPubKey(pubkey_bytes)
            
            elif script_type == "P2WSH":
                # Native SegWit P2WSH - complex, depends on witness script
                if witness_data and len(witness_data) >= 2:
                    # Last item is witness script, previous items are stack elements
                    witness_script = witness_data[-1]
                    witness_script_obj = CScript(witness_script)
                    witness_script_type = self._get_script_type(witness_script_obj)
                    
                    if witness_script_type == "P2PKH" and len(witness_data) >= 3:
                        # P2WSH with P2PKH-like witness script
                        pubkey_bytes = witness_data[-2]  # Second to last
                        if len(pubkey_bytes) in [33, 65]:
                            return CPubKey(pubkey_bytes)
            
            elif script_type == "P2TR":
                # Taproot - complex key tweaking, skip for now
                logger.debug("Taproot detected, skipping (complex key derivation)")
                return None
            
            elif script_type == "MULTISIG":
                # For multisig, we could extract multiple pubkeys but it's complex
                # Skip for now as lattice attacks typically target single signatures
                logger.debug("Multisig transaction detected, skipping")
                return None
                
        except Exception as e:
            logger.debug(f"Error extracting pubkey from {script_type}: {e}")
        
        return None

    def _extract_signature_from_script(self, script_sig: CScript, script_type: str,
                                     witness_data: Optional[List[bytes]] = None) -> Optional[Tuple[int, int]]:
        """Extract r, s values from DER-encoded signature in scriptSig or witness data."""
        try:
            if script_type == "P2PKH":
                # P2PKH: <signature> <pubkey>
                ops = list(script_sig.raw_iter())
                if ops and len(ops) >= 1:
                    # raw_iter() can return tuples (opcode, data) or just data
                    op = ops[0]
                    sig_with_hashtype = None
                    
                    if isinstance(op, tuple) and len(op) >= 2:
                        sig_with_hashtype = op[1]  # data part of the tuple
                    elif isinstance(op, bytes):
                        sig_with_hashtype = op  # direct bytes
                    elif isinstance(op, int):
                        # Skip opcodes that are just integers
                        if len(ops) >= 2:
                            op2 = ops[1]
                            if isinstance(op2, tuple) and len(op2) >= 2:
                                sig_with_hashtype = op2[1]
                            elif isinstance(op2, bytes):
                                sig_with_hashtype = op2
                    
                    if isinstance(sig_with_hashtype, bytes) and len(sig_with_hashtype) > 6:
                        return self._parse_der_signature(sig_with_hashtype)
            
            elif script_type == "P2SH":
                # Check if it's P2SH-wrapped SegWit first
                ops = list(script_sig.raw_iter())
                if ops:
                    # Get the last operation which should be the redeem script
                    last_op = ops[-1]
                    redeem_script_bytes = None
                    
                    if isinstance(last_op, tuple) and len(last_op) >= 2:
                        redeem_script_bytes = last_op[1]
                    elif isinstance(last_op, bytes):
                        redeem_script_bytes = last_op
                    elif isinstance(last_op, int) and len(ops) >= 2:
                        # Check previous element
                        prev_op = ops[-2]
                        if isinstance(prev_op, tuple) and len(prev_op) >= 2:
                            redeem_script_bytes = prev_op[1]
                        elif isinstance(prev_op, bytes):
                            redeem_script_bytes = prev_op
                    
                    if isinstance(redeem_script_bytes, bytes):
                        redeem_script = CScript(redeem_script_bytes)
                        if redeem_script.is_witness_v0_keyhash():
                            # P2SH-wrapped P2WPKH - signature is first item in witness data
                            if witness_data and len(witness_data) >= 1:
                                sig_with_hashtype = witness_data[0]
                                # logger.debug(f"P2SH P2WPKH witness data: len={len(witness_data)}, sig_len={len(sig_with_hashtype) if sig_with_hashtype else 0}")
                                return self._parse_der_signature(sig_with_hashtype)
                            else:
                                logger.debug(f"P2SH P2WPKH but no witness data: witness_data={witness_data}")
                        elif redeem_script.is_witness_v0_scripthash():
                            # P2SH-wrapped P2WSH - signature handling depends on witness script
                            if witness_data and len(witness_data) >= 2:
                                # For P2WSH multisig, first item is usually OP_0 (empty), skip it
                                # Try items from index 1 onwards
                                for i in range(1, len(witness_data) - 1):  # Exclude last item (witness script)
                                    witness_item = witness_data[i]
                                    if len(witness_item) > 6:  # Minimum DER signature size
                                        logger.debug(f"P2SH P2WSH trying witness item {i}: {len(witness_item)} bytes")
                                        result = self._parse_der_signature(witness_item)
                                        if result:
                                            return result
                                logger.debug(f"P2SH P2WSH witness data: len={len(witness_data)}, no valid signatures found")
                            else:
                                logger.debug(f"P2SH P2WSH but insufficient witness data: witness_data={witness_data}")
                
                # Regular P2SH - try to find signature in scriptSig operations
                for op in ops:
                    data = None
                    if isinstance(op, tuple) and len(op) >= 2:
                        data = op[1]
                    elif isinstance(op, bytes):
                        data = op
                    
                    if isinstance(data, bytes) and len(data) > 6:  # Minimum DER signature size
                        result = self._parse_der_signature(data)
                        if result:
                            return result
            
            elif script_type == "P2WPKH":
                # Native SegWit P2WPKH - signature is in witness data
                if witness_data and len(witness_data) >= 1:
                    sig_with_hashtype = witness_data[0]
                    return self._parse_der_signature(sig_with_hashtype)
            
            elif script_type == "P2WSH":
                # Native SegWit P2WSH - signature depends on witness script
                if witness_data and len(witness_data) >= 2:
                    # Try to find signature in witness stack (excluding last item which is script)
                    for i in range(len(witness_data) - 1):
                        witness_item = witness_data[i]
                        if len(witness_item) > 6:  # Minimum DER signature size
                            result = self._parse_der_signature(witness_item)
                            if result:
                                return result
            
            elif script_type == "P2TR":
                # Taproot - use Schnorr signatures, not ECDSA
                logger.debug("Taproot uses Schnorr signatures, not ECDSA")
                return None
            
            elif script_type == "MULTISIG":
                # Multisig: OP_0 <sig1> <sig2> ... <redeemScript>
                # Skip multisig for now
                return None
                
        except Exception as e:
            logger.debug(f"Error extracting signature from {script_type}: {e}")
        
        return None

    def _parse_der_signature(self, sig_with_hashtype: bytes) -> Optional[Tuple[int, int]]:
        """Parse DER-encoded signature and extract r, s values."""
        try:
            if not sig_with_hashtype:
                logger.debug("Signature data is None or empty")
                return None
                
            if not isinstance(sig_with_hashtype, bytes):
                logger.debug(f"Signature data is not bytes, got {type(sig_with_hashtype)}: {sig_with_hashtype}")
                return None
                
            if len(sig_with_hashtype) < 7:
                logger.debug(f"Signature too short: {len(sig_with_hashtype)} bytes")
                return None
            
            # Remove sighash type (last byte)
            der_sig = sig_with_hashtype[:-1]
            
            # Use ecdsa library to decode DER signature
            r, s = sigdecode_der(der_sig, SECP256k1.order)
            
            # Validate r, s are in valid range
            if r <= 0 or s <= 0 or r >= SECP256k1.order or s >= SECP256k1.order:
                logger.debug(f"Invalid r or s values: r={r}, s={s}")
                return None
            
            return r, s
            
        except Exception as e:
            logger.debug(f"Error parsing DER signature: {e}, sig_type={type(sig_with_hashtype)}, sig_data={sig_with_hashtype if isinstance(sig_with_hashtype, bytes) and len(sig_with_hashtype) < 20 else 'too long to display'}")
            return None

    def _extract_witness_data(self, tx: CTransaction, input_index: int) -> Optional[List[bytes]]:
        """Extract witness data from SegWit transaction input."""
        try:
            # Check if transaction has witness data
            if not hasattr(tx, 'wit') or not tx.wit:
                logger.debug(f"No witness data in transaction")
                return None
            
            # Check if this specific input has witness data
            if input_index >= len(tx.wit.vtxinwit):
                logger.debug(f"Input {input_index} beyond witness range: {len(tx.wit.vtxinwit)}")
                return None
            
            witness = tx.wit.vtxinwit[input_index]
            if not witness.scriptWitness:
                logger.debug(f"No scriptWitness for input {input_index}")
                return None
            
            # Convert witness stack to list of bytes
            witness_stack = []
            for i, item in enumerate(witness.scriptWitness):
                if isinstance(item, bytes):
                    witness_stack.append(item)
                    # logger.debug(f"Witness item {i}: {len(item)} bytes")
                else:
                    # Convert to bytes if needed
                    item_bytes = bytes(item)
                    witness_stack.append(item_bytes)
                    # logger.debug(f"Witness item {i}: {len(item_bytes)} bytes (converted)")
            
            logger.debug(f"Extracted {len(witness_stack)} witness items")
            return witness_stack if witness_stack else None
            
        except Exception as e:
            logger.debug(f"Error extracting witness data: {e}")
            return None

    def _compute_sighash(self, tx: CTransaction, input_index: int, script_pub_key: CScript, 
                        script_type: str, redeem_script: Optional[CScript] = None,
                        prev_value: Optional[int] = None) -> Optional[bytes]:
        """Compute the signature hash for different transaction types."""
        try:
            if script_type == "P2PKH":
                # Standard P2PKH
                return SignatureHash(script_pub_key, tx, input_index, SIGHASH_ALL)
            
            elif script_type == "P2SH":
                # For P2SH, use redeem script if available
                if redeem_script:
                    redeem_type = self._get_script_type(redeem_script)
                    logger.debug(f"P2SH redeem script type: {redeem_type}")
                    
                    if redeem_type == "P2PKH":
                        return SignatureHash(redeem_script, tx, input_index, SIGHASH_ALL)
                    elif self._is_p2wpkh_native(redeem_script):
                        # P2SH-wrapped SegWit P2WPKH
                        self.stats['p2sh_wrapped_segwit'] += 1
                        if prev_value is not None:
                            # Use SegWit signature hash (BIP143)
                            return self._compute_segwit_sighash(tx, input_index, redeem_script, prev_value)
                        else:
                            logger.debug("P2SH-wrapped SegWit requires previous output value")
                            return None
                    elif self._is_p2wsh_native(redeem_script):
                        # P2SH-wrapped SegWit P2WSH
                        self.stats['p2sh_wrapped_segwit'] += 1
                        if prev_value is not None:
                            return self._compute_segwit_sighash(tx, input_index, redeem_script, prev_value)
                        else:
                            logger.debug("P2SH-wrapped SegWit requires previous output value")
                            return None
                    else:
                        logger.debug(f"Unsupported P2SH redeem script type: {redeem_type}")
                        return None
                else:
                    logger.debug("P2SH without redeem script")
                    return None
            
            elif script_type in ["P2WPKH", "P2WSH"]:
                # Native SegWit - requires BIP143 signature hash
                if prev_value is not None:
                    return self._compute_segwit_sighash(tx, input_index, script_pub_key, prev_value)
                else:
                    logger.debug("SegWit requires previous output value")
                    return None
            
            elif script_type == "MULTISIG":
                # Direct multisig (rare)
                return SignatureHash(script_pub_key, tx, input_index, SIGHASH_ALL)
            
            elif script_type == "P2TR":
                # Taproot uses different signature hash (BIP341)
                logger.debug("Taproot signature hash not implemented")
                return None
            
            else:
                logger.debug(f"Unknown script type for sighash: {script_type}")
                return None
                
        except Exception as e:
            logger.debug(f"Error computing sighash for {script_type}: {e}")
            return None

    def _compute_segwit_sighash(self, tx: CTransaction, input_index: int, 
                               script_code: CScript, prev_value: int) -> Optional[bytes]:
        """Compute SegWit signature hash according to BIP143."""
        try:
            # Import the SegWit-specific signature hash function
            from bitcoin.core.script import SIGVERSION_WITNESS_V0
            
            # Use the SegWit signature hash function with witness version
            logger.debug(f"Computing SegWit sighash: input_index={input_index}, script_code_len={len(script_code)}, prev_value={prev_value}")
            return SignatureHash(script_code, tx, input_index, SIGHASH_ALL, prev_value, SIGVERSION_WITNESS_V0)
        except ImportError:
            # Fallback to regular signature hash if SIGVERSION_WITNESS_V0 not available
            logger.debug("SIGVERSION_WITNESS_V0 not available, using fallback")
            try:
                return SignatureHash(script_code, tx, input_index, SIGHASH_ALL, prev_value)
            except Exception as e:
                logger.debug(f"Fallback SegWit sighash also failed: {e}")
                return None
        except Exception as e:
            logger.debug(f"Error computing SegWit sighash: {e}")
            logger.debug(f"  Input index: {input_index}, Script code: {script_code.hex() if script_code else 'None'}, Prev value: {prev_value}")
            return None

    def _extract_redeem_script(self, script_sig: CScript) -> Optional[CScript]:
        """Extract redeem script from P2SH scriptSig."""
        try:
            ops = list(script_sig.raw_iter())
            if ops:
                # Last element should be redeem script
                last_op = ops[-1]
                redeem_script_bytes = None
                
                if isinstance(last_op, tuple) and len(last_op) >= 2:
                    redeem_script_bytes = last_op[1]  # Extract data from tuple
                elif isinstance(last_op, bytes):  # Sometimes raw_iter returns just bytes
                    redeem_script_bytes = last_op
                elif isinstance(last_op, int):
                    # This might be an opcode, check previous element
                    if len(ops) >= 2:
                        prev_op = ops[-2]
                        if isinstance(prev_op, tuple) and len(prev_op) >= 2:
                            redeem_script_bytes = prev_op[1]
                        elif isinstance(prev_op, bytes):
                            redeem_script_bytes = prev_op
                
                if isinstance(redeem_script_bytes, bytes) and len(redeem_script_bytes) > 0:
                    return CScript(redeem_script_bytes)
        except Exception as e:
            logger.debug(f"Error extracting redeem script: {e}")
        return None

    def extract_signature(
        self, tx: CTransaction, input_index: int, prev_tx_vout: CTxOut, block_number: int
    ) -> Optional[Signature]:
        """Extract an ECDSA signature from a single transaction input."""
        try:
            self.stats['processed'] += 1
            
            if input_index >= len(tx.vin):
                logger.debug(f"Invalid input index {input_index} for transaction")
                return None
                
            txin = tx.vin[input_index]
            
            # Check for coinbase transaction
            if txin.prevout.is_null():
                self.stats['skipped_coinbase'] += 1
                logger.debug("Skipping coinbase transaction")
                return None
            
            script_pub_key = prev_tx_vout.scriptPubKey
            script_type = self._get_script_type(script_pub_key)
            
            # Update statistics
            if script_type == "P2PKH":
                self.stats['p2pkh'] += 1
            elif script_type == "P2SH":
                self.stats['p2sh'] += 1
            elif script_type == "P2WPKH":
                self.stats['p2wpkh'] += 1
            elif script_type == "P2WSH":
                self.stats['p2wsh'] += 1
            elif script_type == "MULTISIG":
                self.stats['multisig'] += 1
            elif script_type == "P2TR":
                self.stats['p2tr'] += 1
            else:
                self.stats['unknown'] += 1
            
            # logger.debug(f"Processing {script_type} input {input_index}")  # Reduced verbosity
            
            # Skip Taproot for now (uses Schnorr signatures, not ECDSA)
            if script_type == "P2TR":
                logger.debug("Skipping Taproot (uses Schnorr, not ECDSA)")
                return None
            
            # Extract witness data for SegWit transactions
            witness_data = None
            if script_type in ["P2WPKH", "P2WSH"] or script_type == "P2SH":
                witness_data = self._extract_witness_data(tx, input_index)
                if script_type in ["P2WPKH", "P2WSH"] and not witness_data:
                    self.stats['skipped_no_witness'] += 1
                    logger.debug(f"No witness data for {script_type} transaction")
                    return None
            
            # Extract redeem script for P2SH transactions
            redeem_script = None
            if script_type == "P2SH":
                redeem_script = self._extract_redeem_script(txin.scriptSig)
                if not redeem_script:
                    logger.debug(f"Could not extract redeem script from P2SH input")
                    return None
            
            # 1. Compute the signature hash (message hash)
            sighash = self._compute_sighash(
                tx, input_index, script_pub_key, script_type, 
                redeem_script, prev_tx_vout.nValue
            )
            if sighash is None:
                logger.debug(f"Could not compute sighash for {script_type}")
                return None
            
            # 2. Extract r, s values from the signature
            r_s = self._extract_signature_from_script(txin.scriptSig, script_type, witness_data)
            if r_s is None:
                logger.debug(f"Could not extract signature from {script_type}")
                return None
            r, s = r_s
            
            # 3. Extract the public key
            pubkey = self._extract_pubkey_from_script(txin.scriptSig, script_type, witness_data)
            if pubkey is None:
                logger.debug(f"Could not extract pubkey from {script_type}")
                return None
            
            # Validate the extracted values
            if not pubkey or not pubkey.is_valid:
                logger.debug(f"Invalid public key extracted")
                return None
            
            # Track witness signature extraction
            if witness_data:
                self.stats['witness_sigs_extracted'] += 1
            
            # Create and return the signature object
            signature = Signature(
                transaction_hash=b2x(tx.GetTxid()),
                block_number=block_number,
                pubkey=b2x(bytes(pubkey)),  # Convert CPubKey to bytes
                r=hex(r),
                s=hex(s),
                h=b2x(sighash),
            )
            
            self.stats['signatures_extracted'] += 1
            # logger.debug(f"Successfully extracted signature from {script_type} input")  # Reduced verbosity after confirming extraction works
            return signature
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Error extracting signature from input {input_index}: {e}", exc_info=True)
            return None

    def process_transaction(
        self, tx: CTransaction, input_indices: List[int], prev_tx_vouts: List[CTxOut], block_number: int
    ) -> List[Signature]:
        """
        Process a single transaction and extract all valid signatures from its inputs.
        
        Args:
            tx: The transaction to process.
            input_indices: A list of indices for the inputs we are analyzing.
            prev_tx_vouts: A list of the previous output transactions corresponding to the input indices.
            block_number: The block number of the transaction.

        Returns:
            A list of extracted Signature objects.
        """
        signatures = []
        
        if len(input_indices) != len(prev_tx_vouts):
            logger.error(f"Mismatch between input_indices ({len(input_indices)}) and prev_tx_vouts ({len(prev_tx_vouts)})")
            return signatures
        
        for i, vout_index in enumerate(input_indices):
            try:
                prev_vout = prev_tx_vouts[i]
                signature = self.extract_signature(tx, vout_index, prev_vout, block_number)
                if signature:
                    signatures.append(signature)
            except Exception as e:
                logger.error(f"Error processing input {vout_index}: {e}")
                continue
        
        return signatures

    def get_stats(self) -> Dict[str, int]:
        """Get processing statistics."""
        return self.stats.copy()

    def reset_stats(self) -> None:
        """Reset processing statistics."""
        for key in self.stats:
            self.stats[key] = 0

    def log_stats(self) -> None:
        """Log current processing statistics."""
        total = self.stats['processed']
        if total > 0:
            logger.info(f"Transaction parsing stats (total: {total}):")
            logger.info(f"  P2PKH: {self.stats['p2pkh']} ({100*self.stats['p2pkh']/total:.1f}%)")
            logger.info(f"  P2SH: {self.stats['p2sh']} ({100*self.stats['p2sh']/total:.1f}%)")
            logger.info(f"  P2WPKH: {self.stats['p2wpkh']} ({100*self.stats['p2wpkh']/total:.1f}%)")
            logger.info(f"  P2WSH: {self.stats['p2wsh']} ({100*self.stats['p2wsh']/total:.1f}%)")
            logger.info(f"  P2SH-wrapped SegWit: {self.stats['p2sh_wrapped_segwit']} ({100*self.stats['p2sh_wrapped_segwit']/total:.1f}%)")
            logger.info(f"  Multisig: {self.stats['multisig']} ({100*self.stats['multisig']/total:.1f}%)")
            logger.info(f"  P2TR (Taproot): {self.stats['p2tr']} ({100*self.stats['p2tr']/total:.1f}%)")
            logger.info(f"  Unknown: {self.stats['unknown']} ({100*self.stats['unknown']/total:.1f}%)")
            logger.info(f"  Signatures extracted: {self.stats['signatures_extracted']} ({100*self.stats['signatures_extracted']/total:.1f}%)")
            logger.info(f"  Witness signatures: {self.stats['witness_sigs_extracted']} ({100*self.stats['witness_sigs_extracted']/total:.1f}%)")
            logger.info(f"  Skipped coinbase: {self.stats['skipped_coinbase']}")
            logger.info(f"  Skipped no witness: {self.stats['skipped_no_witness']}")
            logger.info(f"  Errors: {self.stats['errors']} ({100*self.stats['errors']/total:.1f}%)")