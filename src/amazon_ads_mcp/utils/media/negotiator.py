"""Media type negotiation helpers.

This module provides functionality for negotiating media types based on
resource types and URL patterns. It includes a resource type negotiator
that can determine appropriate content types for specific resources,
particularly for export operations where the content type depends on
the export ID and resource type.

The module also provides an enhanced media type registry that combines
base registry functionality with negotiation capabilities.
"""

import base64
import logging
import re
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

def _decode_export_id(export_id: str) -> Optional[str]:
    pad_len = (-len(export_id)) % 4
    padded = export_id + ("=" * pad_len)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(padded).decode("utf-8")
        except Exception:
            continue
    return None


class ResourceTypeNegotiator:
    """Negotiator for determining media types based on resource types.

    This class provides a framework for negotiating appropriate media
    types based on the resource type extracted from URLs. It supports
    registering custom negotiators for different resource types and
    includes built-in negotiation logic for export operations.

    The negotiator extracts resource types from URL paths and applies
    type-specific logic to determine the most appropriate content type
    from available options.
    """

    def __init__(self):
        """Initialize the resource type negotiator.

        Sets up internal storage for negotiator functions and registers
        the default negotiator for export operations.
        """
        self._negotiators: Dict[
            str, Callable[[str, str, List[str]], Optional[str]]
        ] = {}
        self._register_default_negotiators()

    def _register_default_negotiators(self):
        """Register the default negotiator for export operations.

        Sets up the built-in negotiator for handling export resource
        types, which determines content types based on export ID suffixes.
        """
        self.register_negotiator("exports", self._negotiate_exports)

    def register_negotiator(
        self,
        resource_type: str,
        negotiator: Callable[[str, str, List[str]], Optional[str]],
    ):
        """Register a custom negotiator function for a resource type.

        :param resource_type: The resource type to register the negotiator for
        :type resource_type: str
        :param negotiator: Function that implements negotiation logic for the
                          resource type
        :type negotiator: Callable[[str, str, List[str]], Optional[str]]
        """
        self._negotiators[resource_type.lower()] = negotiator
        logger.debug("Registered negotiator for resource type: %s", resource_type)

    def negotiate(
        self, method: str, url: str, available_types: List[str]
    ) -> Optional[str]:
        """Negotiate the appropriate media type for a request.

        Extracts the resource type from the URL and applies the appropriate
        negotiator to determine the best content type from the available
        options. Falls back gracefully if negotiation fails.

        :param method: HTTP method of the request
        :type method: str
        :param url: URL to negotiate media type for
        :type url: str
        :param available_types: List of available content types to choose from
        :type available_types: List[str]
        :return: Negotiated content type or None if negotiation fails
        :rtype: Optional[str]
        """
        resource_type = self._extract_resource_type(url)
        if resource_type and resource_type in self._negotiators:
            try:
                result = self._negotiators[resource_type](method, url, available_types)
                if result:
                    logger.debug("Negotiated %s for %s resource", result, resource_type)
                    return result
            except Exception as e:
                logger.warning("Negotiator failed for %s: %s", resource_type, e)
        return None

    def _extract_resource_type(self, url: str) -> Optional[str]:
        """Extract the resource type from a URL path.

        Parses the URL path to identify the resource type, handling
        version prefixes and normalizing the result.

        :param url: URL to extract resource type from
        :type url: str
        :return: Resource type string or None if extraction fails
        :rtype: Optional[str]
        """
        path = urlparse(url).path
        path = re.sub(r"^/v\d+/", "/", path)
        match = re.match(r"^/([^/]+)", path)
        if match:
            return match.group(1).lower()
        return None

    def _negotiate_exports(
        self, method: str, url: str, available_types: List[str]
    ) -> Optional[str]:
        """Negotiate media type for export operations.

        This negotiator handles export-specific media type determination
        by decoding the export ID from the URL and mapping suffix codes
        to appropriate content types. It only processes GET requests
        and expects URLs in the format /exports/{export_id}.

        :param method: HTTP method of the request
        :type method: str
        :param url: URL containing the export ID
        :type url: str
        :param available_types: List of available content types
        :type available_types: List[str]
        :return: Appropriate content type for the export or None if
                 negotiation fails
        :rtype: Optional[str]
        """
        if method.upper() != "GET":
            return None
        m = re.search(r"/exports/([^/?]+)", url)
        if not m:
            return None
        export_id = m.group(1)
        try:
            decoded = _decode_export_id(export_id)
            if not decoded:
                return None
            if "," in decoded:
                _, suffix = decoded.rsplit(",", 1)
                suffix_map = {
                    "C": "application/vnd.campaignsexport.v1+json",
                    "A": "application/vnd.adgroupsexport.v1+json",
                    "AD": "application/vnd.adsexport.v1+json",
                    # Some export IDs use ',R' for ads exports.
                    "R": "application/vnd.adsexport.v1+json",
                    "T": "application/vnd.targetsexport.v1+json",
                }
                ct = suffix_map.get(suffix.upper())
                if ct and ct in available_types:
                    return ct
        except Exception:
            pass
        return None


class EnhancedMediaTypeRegistry:
    """Enhanced media type registry with negotiation capabilities.

    This class extends a base media type registry with negotiation
    functionality. It can resolve media types using the base registry
    and then apply negotiation logic when multiple content types are
    available to select the most appropriate one.
    """

    def __init__(self, base_registry):
        """Initialize the enhanced registry with a base registry.

        :param base_registry: Base media type registry to extend
        :type base_registry: Any
        """
        self.base_registry = base_registry
        self.negotiator = ResourceTypeNegotiator()

    def resolve(self, method: str, url: str):
        """Resolve media types with optional negotiation.

        First attempts to resolve media types using the base registry.
        If multiple response content types are available, applies
        negotiation to select the most appropriate one.

        :param method: HTTP method of the request
        :type method: str
        :param url: URL to resolve media types for
        :type url: str
        :return: Tuple of (request_content_type, response_content_types)
        :rtype: tuple
        """
        content_type, accepts = self.base_registry.resolve(method, url)
        if accepts and len(accepts) > 1:
            negotiated = self.negotiator.negotiate(method, url, accepts)
            if negotiated:
                return content_type, [negotiated]
        return content_type, accepts

    def add_negotiator(self, resource_type: str, negotiator: Callable):
        """Add a custom negotiator for a specific resource type.

        :param resource_type: Resource type to add negotiator for
        :type resource_type: str
        :param negotiator: Negotiation function to register
        :type negotiator: Callable
        """
        self.negotiator.register_negotiator(resource_type, negotiator)


def create_enhanced_registry(base_registry) -> EnhancedMediaTypeRegistry:
    """Create an enhanced media type registry.

    Factory function that creates an EnhancedMediaTypeRegistry instance
    with the provided base registry.

    :param base_registry: Base media type registry to enhance
    :type base_registry: Any
    :return: Enhanced media type registry instance
    :rtype: EnhancedMediaTypeRegistry
    """
    return EnhancedMediaTypeRegistry(base_registry)


__all__ = [
    "ResourceTypeNegotiator",
    "EnhancedMediaTypeRegistry",
    "create_enhanced_registry",
]
