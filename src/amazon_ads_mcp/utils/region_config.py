"""Centralized region configuration for Amazon Ads API.

This module provides a single source of truth for all region-specific
configurations including API endpoints, OAuth endpoints, and region metadata.
All region mappings should be defined here to avoid duplication.
"""

from typing import Dict, Literal, Optional
from urllib.parse import urlparse

# Type alias for region codes
RegionCode = Literal["na", "eu", "fe"]


class RegionConfig:
    """Centralized configuration for Amazon Ads API regions.

    This class provides a single source of truth for all region-specific
    endpoints and configurations. All components should use this class
    instead of defining their own region mappings.
    """

    # Single source of truth for API endpoints
    API_ENDPOINTS: Dict[RegionCode, str] = {
        "na": "https://advertising-api.amazon.com",
        "eu": "https://advertising-api-eu.amazon.com",
        "fe": "https://advertising-api-fe.amazon.com",
    }

    # Single source of truth for OAuth token endpoints
    OAUTH_ENDPOINTS: Dict[RegionCode, str] = {
        "na": "https://api.amazon.com/auth/o2/token",
        "eu": "https://api.amazon.co.uk/auth/o2/token",
        "fe": "https://api.amazon.co.jp/auth/o2/token",
    }

    # Host mappings for URL parsing (without https://)
    API_HOSTS: Dict[RegionCode, str] = {
        "na": "advertising-api.amazon.com",
        "eu": "advertising-api-eu.amazon.com",
        "fe": "advertising-api-fe.amazon.com",
    }

    # Region display names for UI/logging
    REGION_NAMES: Dict[RegionCode, str] = {
        "na": "North America",
        "eu": "Europe",
        "fe": "Far East",
    }

    # Default region if none specified
    DEFAULT_REGION: RegionCode = "na"

    @classmethod
    def get_api_endpoint(cls, region: Optional[str] = None) -> str:
        """Get API endpoint URL for the specified region.

        :param region: Region code (na, eu, fe) or None for default
        :type region: Optional[str]
        :return: Full API endpoint URL
        :rtype: str

        Example:
            >>> RegionConfig.get_api_endpoint("eu")
            'https://advertising-api-eu.amazon.com'
        """
        if region is None:
            region = cls.DEFAULT_REGION
        region = region.lower()
        return cls.API_ENDPOINTS.get(region, cls.API_ENDPOINTS[cls.DEFAULT_REGION])

    @classmethod
    def get_oauth_endpoint(cls, region: Optional[str] = None) -> str:
        """Get OAuth token endpoint URL for the specified region.

        :param region: Region code (na, eu, fe) or None for default
        :type region: Optional[str]
        :return: Full OAuth token endpoint URL
        :rtype: str

        Example:
            >>> RegionConfig.get_oauth_endpoint("fe")
            'https://api.amazon.co.jp/auth/o2/token'
        """
        if region is None:
            region = cls.DEFAULT_REGION
        region = region.lower()
        return cls.OAUTH_ENDPOINTS.get(region, cls.OAUTH_ENDPOINTS[cls.DEFAULT_REGION])

    @classmethod
    def get_api_host(cls, region: Optional[str] = None) -> str:
        """Get API host (without protocol) for the specified region.

        :param region: Region code (na, eu, fe) or None for default
        :type region: Optional[str]
        :return: API host without https://
        :rtype: str

        Example:
            >>> RegionConfig.get_api_host("eu")
            'advertising-api-eu.amazon.com'
        """
        if region is None:
            region = cls.DEFAULT_REGION
        region = region.lower()
        return cls.API_HOSTS.get(region, cls.API_HOSTS[cls.DEFAULT_REGION])

    @classmethod
    def get_region_from_url(cls, url: str) -> str:
        """Extract region code from an API or OAuth URL.

        :param url: URL to parse for region
        :type url: str
        :return: Region code (na, eu, fe)
        :rtype: str

        Example:
            >>> RegionConfig.get_region_from_url("https://advertising-api-eu.amazon.com/v2/profiles")
            'eu'
        """
        if not url:
            return cls.DEFAULT_REGION

        # Parse URL and extract hostname only
        parsed = urlparse(url)
        hostname = (parsed.hostname or parsed.netloc or "").lower()

        if not hostname:
            return cls.DEFAULT_REGION

        # Check for EU indicators in hostname only
        if "-eu." in hostname or hostname.endswith(".co.uk") or "api-eu" in hostname:
            return "eu"

        # Check for FE indicators in hostname only
        if "-fe." in hostname or hostname.endswith(".co.jp") or "api-fe" in hostname:
            return "fe"

        # Default to NA
        return "na"

    @classmethod
    def is_valid_region(cls, region: str) -> bool:
        """Check if a region code is valid.

        :param region: Region code to validate
        :type region: str
        :return: True if valid, False otherwise
        :rtype: bool

        Example:
            >>> RegionConfig.is_valid_region("eu")
            True
            >>> RegionConfig.is_valid_region("invalid")
            False
        """
        if not region:
            return False
        return region.lower() in cls.API_ENDPOINTS

    @classmethod
    def get_region_name(cls, region: Optional[str] = None) -> str:
        """Get display name for a region.

        :param region: Region code (na, eu, fe) or None for default
        :type region: Optional[str]
        :return: Human-readable region name
        :rtype: str

        Example:
            >>> RegionConfig.get_region_name("na")
            'North America'
        """
        if region is None:
            region = cls.DEFAULT_REGION
        region = region.lower()
        return cls.REGION_NAMES.get(region, cls.REGION_NAMES[cls.DEFAULT_REGION])

    @classmethod
    def get_all_regions(cls) -> Dict[str, Dict[str, str]]:
        """Get all region configurations.

        :return: Dictionary of all regions with their configurations
        :rtype: Dict[str, Dict[str, str]]

        Example:
            >>> regions = RegionConfig.get_all_regions()
            >>> regions["na"]["api_endpoint"]
            'https://advertising-api.amazon.com'
        """
        result = {}
        for region in cls.API_ENDPOINTS.keys():
            result[region] = {
                "code": region,
                "name": cls.get_region_name(region),
                "api_endpoint": cls.get_api_endpoint(region),
                "oauth_endpoint": cls.get_oauth_endpoint(region),
                "api_host": cls.get_api_host(region),
            }
        return result
