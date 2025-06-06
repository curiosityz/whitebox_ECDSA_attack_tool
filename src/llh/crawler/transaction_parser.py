"""
Transaction parser module for extracting ECDSA signatures from Bitcoin transactions.
"""

import logging
from typing import List, Optional, Tuple

from bitcoin.core import b2x, CTransaction, CTxOut
from bitcoin.core.script import CScript, SignatureHash, SIGHASH_ALL
from bitcoin.core.key import CPubKey

from ..database.models import Signature

# We will need ecdsa to parse DER-encoded signatures
try:
    from ecdsa.util import sigdecode_der
except ImportError:
    # This should be installed with pyproject.toml
    # If not, it will fail at runtime
    pass


logger = logging.getLogger(__name__)

class TransactionParser:
    """Parser for extracting ECDSA signatures from Bitcoin transactions."""

    def _compute_message_hash(self, tx_to_sign: CTransaction, input_index: int, scriptPubKey: CScript) -> Optional[bytes]:
        """Compute the message hash for a Bitcoin transaction input."""
        if scriptPubKey.is_p2sh():
            # For P2SH, we need to find the redeemScript from the scriptSig.
            # This is complex as it requires parsing the scriptSig to find the redeemScript.
            # We will focus on non-P2SH for now.
            logger.debug(f"P2SH transaction input skipped for now: {b2x(tx_to_sign.GetTxid())}:{input_index}")
            return None

        return SignatureHash(scriptPubKey, tx_to_sign, input_index, SIGHASH_ALL)

    def _extract_r_s(self, scriptSig: CScript) -> Optional[Tuple[int, int]]:
        """Extract r and s from a DER-encoded signature in the scriptSig."""
        try:
            # The signature is usually the first data push in a P2PKH scriptSig
            sig_with_hashtype = scriptSig[0]
            # The last byte is the sighash type
            der_sig = sig_with_hashtype[:-1]
            # Use ecdsa to decode the DER signature
            r, s = sigdecode_der(der_sig, CPubKey._curve.order)
            return r, s
        except Exception:
            # This can fail for many reasons (multisig, non-standard scripts)
            return None

    def _extract_pubkey(self, scriptSig: CScript) -> Optional[CPubKey]:
        """Extract the public key from the scriptSig."""
        try:
            # For P2PKH, the pubkey is the second data push
            pubkey_bytes = scriptSig[1]
            pubkey = CPubKey(pubkey_bytes)
            if pubkey.is_valid():
                return pubkey
            return None
        except (IndexError, ValueError):
            return None

    def extract_signature(
        self, tx: CTransaction, input_index: int, prev_tx_vout: CTxOut, block_number: int
    ) -> Optional[Signature]:
        """Extract an ECDSA signature from a single transaction input."""
        txin = tx.vin[input_index]

        # 1. Compute message hash
        h = self._compute_message_hash(tx, input_index, prev_tx_vout.scriptPubKey)
        if h is None:
            return None

        # 2. Extract r and s from the signature
        r_s = self._extract_r_s(txin.scriptSig)
        if r_s is None:
            return None
        r, s = r_s
        
        # 3. Extract public key
        pubkey = self._extract_pubkey(txin.scriptSig)
        if pubkey is None:
            # Could try to recover from signature, but it's less reliable and complex.
            # For now, we only support transactions where the pubkey is explicit.
            return None

        return Signature(
            transaction_hash=b2x(tx.GetTxid()),
            block_number=block_number,
            pubkey=b2x(pubkey.get_bytes()),
            r=hex(r),
            s=hex(s),
            h=b2x(h),
        )

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
        for i, vout_index in enumerate(input_indices):
            prev_vout = prev_tx_vouts[i]
            signature = self.extract_signature(tx, vout_index, prev_vout, block_number)
            if signature:
                signatures.append(signature)
        return signatures 