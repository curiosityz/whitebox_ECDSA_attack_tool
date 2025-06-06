"""
Analysis Module for the Ledger Lattice Hunter.

This module performs meta-analysis on the discovered vulnerabilities
to identify patterns and correlations.
"""

import asyncio
import logging
from collections import Counter
from datetime import datetime
from typing import Dict, Any, List, Optional
import numpy as np

from ..database.connection import DatabaseConnection
from ..database.models import VulnerabilityReport, PubkeyMetadata
from ..utils.config import load_config
from ..utils.logging import setup_logging

logger = logging.getLogger(__name__)

class AnalysisManager:
    """Manages the analysis of vulnerability data."""

    def __init__(self, config: Dict[str, Any]):
        """Initializes the AnalysisManager."""
        self.config = config
        self.db = DatabaseConnection(self.config)

    async def run_analysis(self):
        """Connects to the database and runs the full analysis pipeline."""
        try:
            await self.db.connect()
            logger.info("Starting vulnerability analysis...")
            
            vulnerabilities = await self._fetch_vulnerabilities()
            if not vulnerabilities:
                logger.info("No vulnerabilities found in the database. Nothing to analyze.")
                return

            pubkey_metadata_list = await self._fetch_pubkey_metadata_for_vulns(vulnerabilities)

            report = self._generate_report(vulnerabilities, pubkey_metadata_list)
            print(report)

            if self.config.get("analysis", {}).get("enable_prioritization", False):
                await self._update_attack_priorities()

        except Exception as e:
            logger.error(f"An error occurred during analysis: {e}", exc_info=True)
        finally:
            if self.db:
                await self.db.close()
            logger.info("Analysis complete.")

    async def _fetch_vulnerabilities(self) -> List[VulnerabilityReport]:
        """Fetch all vulnerability reports from the database."""
        vulnerabilities = await self.db.get_all_vulnerabilities()
        logger.info(f"Fetched {len(vulnerabilities)} vulnerability reports from the database.")
        return vulnerabilities

    async def _fetch_pubkey_metadata_for_vulns(self, vulnerabilities: List[VulnerabilityReport]) -> List[PubkeyMetadata]:
        """Fetch PubkeyMetadata for a list of vulnerable public keys."""
        pubkeys = [v.pubkey for v in vulnerabilities]
        metadata_list = await self.db.get_pubkey_metadata_bulk(pubkeys)
        return metadata_list

    def _generate_report(self, vulnerabilities: List[VulnerabilityReport], pubkey_metadata: List[PubkeyMetadata]) -> str:
        """
        Generates a textual report and a Mermaid chart from the analysis.

        Args:
            vulnerabilities: A list of vulnerability reports.
            pubkey_metadata: A list of PubkeyMetadata objects.

        Returns:
            A string containing the formatted report.
        """
        num_vulnerabilities = len(vulnerabilities)
        
        # --- Signature Count Analysis ---
        sig_counts = [meta.signature_count for meta in pubkey_metadata if meta]
        avg_sig_count = np.mean(sig_counts) if sig_counts else 0
        
        # --- Key Age Analysis (days) ---
        key_ages = [(datetime.utcnow() - meta.first_seen).days for meta in pubkey_metadata if meta]
        avg_key_age = np.mean(key_ages) if key_ages else 0

        # --- Temporal Analysis ---
        timestamps = [v.timestamp for v in vulnerabilities]
        monthly_counts = Counter(ts.strftime('%Y-%m') for ts in timestamps)
        
        # Prepare data for Mermaid chart
        sorted_months = sorted(monthly_counts.keys())
        month_labels = " ".join([f'"{month}"' for month in sorted_months])
        count_values = " ".join([str(monthly_counts[month]) for month in sorted_months])

        report_str = f"""
======================================
Vulnerability Analysis Report
======================================

Summary
-------
- Total Vulnerabilities Found: {num_vulnerabilities}

Correlation Analysis
--------------------
- Average Signature Count for Vulnerable Keys: {avg_sig_count:.2f}
- Average Age of Vulnerable Keys (days): {avg_key_age:.2f}

Temporal Distribution
---------------------
This chart shows the number of vulnerabilities discovered per month.

```mermaid
graph TD
    subgraph Vulnerabilities Over Time
        direction LR
        A[Count] --> B(Month)
    end
    
    subgraph Chart
        direction LR
        {month_labels}
        {count_values}
    end
```

Detailed Breakdown
------------------
"""
        # Create a mapping of pubkey to metadata for easy lookup
        metadata_map = {meta.pubkey: meta for meta in pubkey_metadata if meta}

        for i, vuln in enumerate(vulnerabilities, 1):
            meta = metadata_map.get(vuln.pubkey)
            if meta:
                report_str += (
                    f"{i}. Pubkey: {vuln.pubkey}\\n"
                    f"   - Found: {vuln.timestamp.isoformat()}\\n"
                    f"   - Signature Count: {meta.signature_count}\\n"
                    f"   - First Seen: {meta.first_seen.isoformat()}\\n"
                )
            else:
                report_str += f"{i}. Pubkey: {vuln.pubkey}, Found: {vuln.timestamp.isoformat()}\\n"

        report_str += "\\n======================================\\n"
        
        return report_str

    async def _update_attack_priorities(self):
        """
        Analyzes all public key metadata to find and store high-priority attack targets.
        """
        logger.info("Starting attack prioritization analysis...")
        
        all_metadata = await self.db.get_all_pubkey_metadata()
        
        priority_targets = []
        priority_config = self.config.get("analysis", {}).get("priority_criteria", {})
        min_age_days = priority_config.get("min_age_days", 365)
        min_sigs = priority_config.get("min_signatures", 50)
        
        for meta in all_metadata:
            if meta.is_vulnerable:
                continue
            
            age_in_days = (datetime.utcnow() - meta.first_seen).days
            
            if age_in_days >= min_age_days and meta.signature_count >= min_sigs:
                priority_targets.append(meta.pubkey)
                
        if priority_targets:
            logger.info(f"Found {len(priority_targets)} high-priority targets. Storing to database.")
            await self.db.set_high_priority_targets(priority_targets)
        else:
            logger.info("No new high-priority targets found based on current criteria.")


async def main():
    """Main entry point for the analysis module."""
    setup_logging()
    config = load_config("config/config.yaml")
    manager = AnalysisManager(config)
    await manager.run_analysis()


if __name__ == "__main__":
    asyncio.run(main()) 