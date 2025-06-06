"""
Database connection handler for MongoDB operations.
"""

import logging
from typing import Dict, Any, Optional
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure
from datetime import datetime, timedelta

from ..utils.config import load_config
from .models import Signature, PubkeyMetadata, VulnerabilityReport

logger = logging.getLogger(__name__)

class DatabaseConnection:
    """Handles database connections and operations."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize database connection with configuration."""
        self.config = config
        self.client: Optional[AsyncIOMotorClient] = None
        self.db = None
        
    async def connect(self) -> None:
        """Establish connection to MongoDB."""
        try:
            self.client = AsyncIOMotorClient(self.config["database"]["mongodb"]["uri"])
            self.db = self.client[self.config["database"]["mongodb"]["database_name"]]
            # Verify connection
            await self.client.admin.command('ping')
            logger.info("Successfully connected to MongoDB")
            await self._setup_indexes()
        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
    
    async def _setup_indexes(self) -> None:
        """Create necessary indexes in the database if they don't exist."""
        try:
            # Index for quickly finding signatures by public key
            sig_collection = self.db[self.config["database"]["mongodb"]["collections"]["signatures"]]
            await sig_collection.create_index("pubkey", background=True)
            
            # Index for finding attack candidates
            pubkey_collection = self.db[self.config["database"]["mongodb"]["collections"]["pubkeys"]]
            await pubkey_collection.create_index(
                [("signature_count", -1), ("is_vulnerable", 1)],
                background=True
            )
            
            logger.info("Database indexes ensured.")
        except Exception as e:
            logger.error(f"Error setting up database indexes: {e}")
    
    async def close(self) -> None:
        """Close the database connection."""
        if self.client:
            self.client.close()
            logger.info("Closed MongoDB connection")
    
    async def insert_signature(self, signature: Signature) -> None:
        """Insert a new signature into the database."""
        collection = self.db[self.config["database"]["mongodb"]["collections"]["signatures"]]
        await collection.insert_one(signature.dict())
    
    async def update_pubkey_metadata(self, metadata: PubkeyMetadata) -> None:
        """Update metadata for a public key."""
        collection = self.db[self.config["database"]["mongodb"]["collections"]["pubkeys"]]
        await collection.update_one(
            {"pubkey": metadata.pubkey},
            {"$set": metadata.dict()},
            upsert=True
        )
    
    async def insert_vulnerability(self, report: VulnerabilityReport) -> None:
        """Insert a new vulnerability report."""
        collection = self.db[self.config["database"]["mongodb"]["collections"]["vulnerabilities"]]
        await collection.insert_one(report.dict())
    
    async def mark_as_vulnerable(self, pubkey: str, vulnerability_type: str):
        """Mark a public key as vulnerable."""
        collection = self.db[self.config["database"]["mongodb"]["collections"]["pubkeys"]]
        await collection.update_one(
            {"pubkey": pubkey},
            {"$set": {"is_vulnerable": True, "vulnerability_type": vulnerability_type}}
        )

    async def mark_as_checked(self, pubkey: str):
        """Update the timestamp for when a public key was last checked."""
        collection = self.db[self.config["database"]["mongodb"]["collections"]["pubkeys"]]
        await collection.update_one(
            {"pubkey": pubkey},
            {"$set": {"last_checked": datetime.utcnow()}}
        )

    async def get_next_attack_candidate(self, min_signatures: int) -> Optional[PubkeyMetadata]:
        """
        Gets the next public key that is a good candidate for an attack.
        A good candidate has enough signatures, is not vulnerable, and hasn't been checked recently.
        """
        recheck_interval_hours = self.config.get("attack", {}).get("recheck_interval_hours", 24)
        recheck_threshold = datetime.utcnow() - timedelta(hours=recheck_interval_hours)

        collection = self.db[self.config["database"]["mongodb"]["collections"]["pubkeys"]]
        candidate = await collection.find_one(
            {
                "signature_count": {"$gte": min_signatures},
                "is_vulnerable": False,
                "$or": [
                    {"last_checked": {"$exists": False}},
                    {"last_checked": {"$lt": recheck_threshold}}
                ]
            }
        )
        return PubkeyMetadata(**candidate) if candidate else None

    async def get_signatures_for_pubkey(self, pubkey: str, limit: int = 100, skip: int = 0) -> list:
        """Retrieve signatures for a specific public key."""
        collection = self.db[self.config["database"]["mongodb"]["collections"]["signatures"]]
        cursor = collection.find({"pubkey": pubkey}).skip(skip).limit(limit)
        return [Signature(**s) for s in await cursor.to_list(length=limit)]
    
    async def get_pubkeys_by_signature_count(self, min_count: int) -> list:
        """Retrieve public keys with at least the specified number of signatures."""
        collection = self.db[self.config["database"]["mongodb"]["collections"]["pubkeys"]]
        cursor = collection.find({"signature_count": {"$gte": min_count}})
        return await cursor.to_list(length=None) 