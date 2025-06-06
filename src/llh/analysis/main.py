"""
Analysis Module for the Ledger Lattice Hunter.

This module performs meta-analysis on the discovered vulnerabilities
to identify patterns and correlations.
"""

import asyncio
import logging
from collections import Counter
from datetime import datetime
from typing import Dict, Any, List

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

            report = self._generate_report(vulnerabilities)
            print(report)

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

    def _generate_report(self, vulnerabilities: List[VulnerabilityReport]) -> str:
        """
        Generates a textual report and a Mermaid chart from the analysis.

        Args:
            vulnerabilities: A list of vulnerability reports.

        Returns:
            A string containing the formatted report.
        """
        num_vulnerabilities = len(vulnerabilities)
        
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
        for i, vuln in enumerate(vulnerabilities, 1):
            report_str += f"{i}. Pubkey: {vuln.pubkey}, Found: {vuln.timestamp.isoformat()}\\n"

        report_str += "\\n======================================\\n"
        
        return report_str


async def main():
    """Main entry point for the analysis module."""
    setup_logging()
    config = load_config("config/config.yaml")
    manager = AnalysisManager(config)
    await manager.run_analysis()


if __name__ == "__main__":
    asyncio.run(main()) 