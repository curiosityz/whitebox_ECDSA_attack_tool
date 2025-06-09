"""
Lattice Solver for the Ledger Lattice Hunter.

This module orchestrates the lattice attack by running the sieving algorithm
and using the predicate to find the solution.
"""

import logging
from typing import Optional
import numpy as np

try:
    from fpylll import GSO, IntegerMatrix
    HAS_FPYLLL = True
except ImportError:
    HAS_FPYLLL = False
    logging.warning("fpylll not available, lattice attacks will be limited")

try:
    from g6k import Siever
    from g6k.algorithms.bkz import pump_n_jump_bkz_tour
    from g6k.utils.stats import SieveTreeTracer
    HAS_G6K = True
except ImportError:
    HAS_G6K = False
    logging.warning("g6k not available, using fallback lattice reduction")

from .builder import LatticeBuilder
from .predicate import Predicate

logger = logging.getLogger(__name__)

class LatticeSolver:
    """
    Orchestrates the lattice attack using the g6k siever or fallback methods.
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
        if HAS_G6K:
            return self._solve_with_g6k(M, klen, x_param)
        else:
            return self._solve_with_fallback(M, klen, x_param)

    def _solve_with_g6k(self, M: GSO.Mat, klen: int, x_param: int) -> Optional[int]:
        """Use g6k for lattice solving."""
        try:
            # Get g6k parameters from config with defaults
            g6k_params = self.config.get("g6k_params", {})
            
            # Set default parameters if not provided
            default_params = {
                "threads": 1,
                "verbose": True,
                "seed": 0,
                "default_sieve": "gauss",
                "dual_mode": False,
            }
            
            # Merge defaults with provided params
            for key, value in default_params.items():
                if key not in g6k_params:
                    g6k_params[key] = value
            
            # Initialize the G6K siever with the lattice
            logger.info("Initializing g6k siever...")
            g6k = Siever(M, **g6k_params)
            
            # Get dimensions
            n = M.B.nrows
            
            # Set up tracer for statistics
            tracer = SieveTreeTracer(g6k, root_label="lattice_solve")
            
            # Run progressive sieving
            logger.info(f"Starting progressive sieving on {n}-dimensional lattice...")
            
            # Progressive sieving parameters
            pump_params = self.config.get("pump_params", {
                "down_sieve": True,
                "max_loops": 3,
            })
            
            # Run pump-and-jump BKZ tour
            with tracer.context("pump_n_jump"):
                pump_n_jump_bkz_tour(g6k, tracer, 
                                   0, n, 
                                   pump_params=pump_params)
            
            logger.info(f"Sieving complete. Database contains {g6k.db_size()} vectors.")

            # Check the vectors in the database using the predicate
            found_solutions = []
            
            for i in range(min(g6k.db_size(), 10000)):  # Limit checks to avoid hanging
                try:
                    # Get vector from database
                    with tracer.context("vector_check"):
                        # The vector is returned in coefficient representation
                        v = g6k[i]
                        
                        # Convert to standard Python list of integers
                        if hasattr(v, 'coeffs'):
                            v_list = [int(coeff) for coeff in v.coeffs]
                        else:
                            v_list = [int(coord) for coord in v]
                        
                        # Check with predicate
                        private_key = self.predicate.check(v_list, klen, x_param)
                        if private_key:
                            logger.info(f"Predicate check successful for vector {i}. Solution found.")
                            found_solutions.append(private_key)
                            
                            # Return first valid solution
                            return private_key
                            
                except Exception as e:
                    logger.debug(f"Error checking vector {i}: {e}")
                    continue

            logger.info("No solution found in the siever database.")
            
            # Print statistics
            if hasattr(tracer, 'trace'):
                stats = tracer.trace
                logger.info(f"Sieving statistics: {stats}")
                
            return None
            
        except Exception as e:
            logger.error(f"Error during g6k lattice solving: {e}", exc_info=True)
            return None

    def _solve_with_fallback(self, M: GSO.Mat, klen: int, x_param: int) -> Optional[int]:
        """Fallback lattice solving using only fpylll."""
        try:
            logger.info("Using fallback lattice reduction (fpylll only, no g6k)")
            
            # Get the lattice dimension
            n = M.B.nrows
            
            # Perform stronger BKZ reduction
            from fpylll import BKZ
            from fpylll.algorithms.bkz2 import BKZReduction
            
            # BKZ parameters
            beta = self.config.get("lattice", {}).get("beta_parameter", 20)
            
            logger.info(f"Running BKZ reduction with beta={beta} on {n}-dimensional lattice...")
            
            # Create BKZ parameters
            bkz_params = BKZ.Param(beta, strategies=BKZ.DEFAULT_STRATEGY)
            
            # Run BKZ reduction
            bkz = BKZReduction(M)
            bkz(bkz_params)
            
            logger.info("BKZ reduction complete. Checking short vectors...")
            
            # Check the first few rows for short vectors
            num_vectors_to_check = min(n, 100)
            
            for i in range(num_vectors_to_check):
                # Get the i-th row as a potential solution vector
                v_list = []
                for j in range(n):
                    v_list.append(int(M.B[i][j]))
                
                # Check with predicate
                private_key = self.predicate.check(v_list, klen, x_param)
                if private_key:
                    logger.info(f"Predicate check successful for vector {i}. Solution found.")
                    return private_key
            
            logger.info("No solution found using fallback method.")
            return None
            
        except Exception as e:
            logger.error(f"Error during fallback lattice solving: {e}", exc_info=True)
            return None