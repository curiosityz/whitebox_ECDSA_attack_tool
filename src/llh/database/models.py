"""
Database models for storing signature and vulnerability data.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict

class Signature(BaseModel):
    """Model for storing ECDSA signature data."""
    
    transaction_hash: str = Field(..., description="Hash of the transaction")
    block_number: int = Field(..., description="Block number containing the transaction")
    pubkey: str = Field(..., description="Public key associated with the signature")
    r: str = Field(..., description="r component of the ECDSA signature")
    s: str = Field(..., description="s component of the ECDSA signature")
    h: str = Field(..., description="Message hash that was signed")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    model_config = ConfigDict(populate_by_name=True)

class PubkeyMetadata(BaseModel):
    """Model for storing metadata about public keys."""
    
    pubkey: str = Field(..., description="Public key")
    signature_count: int = Field(default=0, description="Number of signatures collected")
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    last_checked: Optional[datetime] = Field(None, description="Timestamp of the last attack check")
    is_vulnerable: bool = Field(default=False, description="Whether this key is known to be vulnerable")
    vulnerability_type: Optional[str] = Field(None, description="Type of vulnerability if any")
    
    model_config = ConfigDict(populate_by_name=True)

class VulnerabilityReport(BaseModel):
    """Model for storing vulnerability analysis results."""
    
    pubkey: str = Field(..., description="Public key that was analyzed")
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    vulnerability_type: str = Field(..., description="Type of vulnerability discovered")
    nonce_properties: dict = Field(..., description="Properties of the nonce that made it vulnerable")
    attack_parameters: dict = Field(..., description="Parameters used in the successful attack")
    private_key: Optional[str] = Field(None, description="Recovered private key if successful")
    
    model_config = ConfigDict(populate_by_name=True) 