"""
Utility modules for device fingerprinting and user-agent processing.
"""
from .hash_generator import generate_device_id
from .ua_parser import parse_user_agent

__all__ = ["generate_device_id", "parse_user_agent"]
