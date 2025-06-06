"""
Lattice Solver for the Ledger Lattice Hunter.

This module orchestrates the lattice attack by running the sieving algorithm
and using the predicate to find the solution.
"""

import logging
from typing import Optional

from fpylll import GSO
from g6k import Siever

from .builder import LatticeBuilder
from .predicate import Predicate

logger = logging.getLogger(__name__)

class LatticeSolver:
    """
    Orchestrates the lattice attack using the g6k siever.
    """

    def __init__(self, builder: LatticeBuilder, predicate: Predicate, config: dict):
        """
        Initializes the LatticeSolver.

        Args:
            builder: The LatticeBuilder for constructing the lattice.
            predicate: The Predicate for checking candidate vectors.
            config: The project configuration dictionary.
        """
        self.builder = builder
        self.predicate = predicate
        self.config = config

    def solve(self, M: GSO.Mat, klen: int, x_param: int) -> Optional[int]:
        """
        Runs the lattice attack on the given lattice M.

        Args:
            M: The GSO matrix object representing the lattice.
            klen: The assumed nonce bit-length for the attack.
            x_param: The decomposition parameter 'x' for the attack.

        Returns:
            The recovered private key as an integer, or None if not found.
        """
        # Initialize the G6K siever with the lattice
        g6k = Siever(M, **self.config["g6k_params"])
        
        # Run the sieving algorithm
        g6k()
        logger.info(f"Sieving complete. Database contains {g6k.M.db_size()} vectors.")

        # Check the vectors in the database using the predicate
        for i in range(g6k.M.db_size()):
            # The vector is returned in canonical coordinates
            v_canonical = g6k.M.db_get(i)
            # Convert to a standard Python list of integers
            v = [int(coord) for coord in v_canonical]

            private_key = self.predicate.check(v, klen, x_param)
            if private_key:
                logger.info("Predicate check successful. Solution found.")
                return private_key

        logger.info("No solution found in the siever database.")
        return None 