"""
Error-related models for the FastMCP server.

This module provides Pydantic-based error models and exception classes
following the same abstraction pattern as other models in the package.

The module provides:
- Error categories and classification
- Standardized error response models
- Compact error data for context window optimization
- Pydantic validation error handling
- FastMCP error statistics and optimization
- Exception classes with Pydantic model integration
- Error pattern recognition and compression rules
"""

from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ErrorCategory(str, Enum):
    """Categories of errors for proper handling.

    This enum defines the different categories of errors that can occur
    in the FastMCP server, enabling proper error classification and handling.

    The categories include:
    - Authentication and permission errors
    - Validation and input errors
    - Network and external service errors
    - Database and internal errors
    - Rate limiting and resource errors
    """

    AUTHENTICATION = "authentication"
    VALIDATION = "validation"
    NETWORK = "network"
    DATABASE = "database"
    PERMISSION = "permission"
    NOT_FOUND = "not_found"
    RATE_LIMIT = "rate_limit"
    INTERNAL = "internal"
    EXTERNAL_SERVICE = "external_service"


class ErrorContext(BaseModel):
    """Context information for errors.

    This model provides contextual information about errors including
    source, request tracking, user identification, and metadata.

    The context includes:
    - Error source identification
    - Request and user tracking
    - Timestamp information
    - Additional metadata for debugging
    """

    source: str = Field(..., description="Source of the error")
    request_id: Optional[str] = Field(None, description="Request identifier")
    user_id: Optional[str] = Field(None, description="User identifier")
    timestamp: Optional[str] = Field(None, description="Error timestamp")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional error metadata"
    )


class ErrorResponse(BaseModel):
    """Standardized error response model.

    This model provides a standardized format for error responses
    that can be returned to clients, ensuring consistency across
    all error handling in the FastMCP server.

    The response includes:
    - User-friendly error message
    - Error category classification
    - HTTP status code
    - Request tracking information
    - Additional error details
    """

    message: str = Field(..., description="User-friendly error message")
    category: ErrorCategory = Field(..., description="Error category")
    code: int = Field(..., description="HTTP status code")
    request_id: Optional[str] = Field(None, description="Request identifier")
    details: Dict[str, Any] = Field(
        default_factory=dict, description="Additional error details"
    )


class CompactErrorData(BaseModel):
    """Compressed error data optimized for context windows.

    This model provides compressed error information optimized for
    use in context windows where space is limited, while maintaining
    essential error information.

    The compressed data includes:
    - Original and compressed message lengths
    - Compression ratio information
    - Field-specific error details
    - Model context for validation errors
    """

    original_length: int = Field(..., description="Original error message length")
    compressed_length: int = Field(..., description="Compressed error message length")
    compression_ratio: float = Field(..., description="Compression ratio (0-1)")
    compressed_message: str = Field(..., description="Compressed error message")
    field_errors: Dict[str, str] = Field(
        default_factory=dict, description="Field-specific errors"
    )
    model_context: Optional[str] = Field(
        None, description="Model context for the error"
    )


class PydanticErrorInfo(BaseModel):
    """Pydantic validation error information.

    This model provides detailed information about Pydantic validation
    errors, including field paths, error types, and compressed messages
    for efficient error handling.

    The error info includes:
    - Field path to the invalid field
    - Type of validation error
    - Original and compressed error messages
    - Model name for context
    """

    field_path: str = Field(..., description="Path to the invalid field")
    error_type: str = Field(..., description="Type of validation error")
    error_message: str = Field(..., description="Original error message")
    compressed_message: str = Field(..., description="Compressed error message")
    model_name: Optional[str] = Field(None, description="Name of the Pydantic model")


class FastMCPErrorStats(BaseModel):
    """Statistics for FastMCP error optimization.

    This model tracks statistics about error processing and optimization,
    providing insights into error patterns and compression effectiveness.

    The statistics include:
    - Total errors processed
    - Pydantic error counts
    - Average compression ratios
    - Context window savings
    - Most common field errors
    """

    total_errors_processed: int = Field(default=0, description="Total errors processed")
    pydantic_errors_count: int = Field(
        default=0, description="Number of Pydantic validation errors"
    )
    average_compression_ratio: float = Field(
        default=0.0, description="Average compression ratio"
    )
    context_window_savings: int = Field(default=0, description="Total characters saved")
    most_common_field_errors: Dict[str, int] = Field(
        default_factory=dict, description="Most common field validation errors"
    )


# =============================================================================
# Exception Classes (Pydantic-based data + Exception behavior)
# =============================================================================


class MCPError(Exception):
    """Base exception for all MCP errors with Pydantic model integration.

    This class provides a base exception for all MCP-related errors,
    integrating Pydantic model functionality with standard exception behavior.
    It includes comprehensive error information and conversion methods.

    The exception includes:
    - Error message and category
    - Status code and details
    - User-friendly message generation
    - Context information
    - Conversion to response models
    """

    def __init__(
        self,
        message: str,
        category: ErrorCategory = ErrorCategory.INTERNAL,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
        user_message: Optional[str] = None,
        context: Optional[ErrorContext] = None,
    ):
        """Initialize the MCP error.

        :param message: Internal error message
        :type message: str
        :param category: Error category for classification
        :type category: ErrorCategory
        :param status_code: HTTP status code
        :type status_code: int
        :param details: Additional error details
        :type details: Optional[Dict[str, Any]]
        :param user_message: User-friendly error message
        :type user_message: Optional[str]
        :param context: Error context information
        :type context: Optional[ErrorContext]
        """
        super().__init__(message)
        self.message = message
        self.category = category
        self.status_code = status_code
        self.details = details or {}
        self.user_message = user_message or self._get_default_user_message()
        self.context = context

    def _get_default_user_message(self) -> str:
        """Get a safe default message for users.

        Returns a user-friendly error message based on the error category.

        :return: Default user-friendly error message
        :rtype: str
        """
        default_messages = {
            ErrorCategory.AUTHENTICATION: "Authentication failed. Please check your credentials.",
            ErrorCategory.VALIDATION: "Invalid input provided. Please check your request.",
            ErrorCategory.NETWORK: "Network error occurred. Please try again later.",
            ErrorCategory.PERMISSION: "Access denied. You don't have permission for this action.",
            ErrorCategory.NOT_FOUND: "Resource not found.",
            ErrorCategory.RATE_LIMIT: "Rate limit exceeded. Please try again later.",
            ErrorCategory.EXTERNAL_SERVICE: "External service error. Please try again later.",
        }
        return default_messages.get(
            self.category, "An error occurred. Please try again later."
        )

    def to_response_model(self) -> ErrorResponse:
        """Convert to Pydantic ErrorResponse model.

        Converts the exception to a standardized ErrorResponse model
        for consistent error handling.

        :return: ErrorResponse model instance
        :rtype: ErrorResponse
        """
        return ErrorResponse(
            message=self.user_message,
            category=self.category,
            code=self.status_code,
            request_id=self.details.get("request_id"),
            details=self.details,
        )

    def to_response(self) -> Dict[str, Any]:
        """Convert to response dictionary (backward compatibility).

        Converts the exception to a dictionary format for backward
        compatibility with existing error handling code.

        :return: Error response dictionary
        :rtype: Dict[str, Any]
        """
        return self.to_response_model().model_dump()


class ValidationError(MCPError):
    """Input validation errors with field-specific information.

    This exception class handles validation errors with specific
    field information and detailed error reporting.

    The validation error includes:
    - Field-specific error information
    - Detailed field error mapping
    - Validation-specific error handling
    """

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        field_errors: Optional[Dict[str, str]] = None,
        **kwargs,
    ):
        """Initialize the validation error.

        :param message: Validation error message
        :type message: str
        :param field: Specific field that failed validation
        :type field: Optional[str]
        :param field_errors: Dictionary of field-specific errors
        :type field_errors: Optional[Dict[str, str]]
        :param **kwargs: Additional keyword arguments
        """
        details = kwargs.get("details", {})
        if field:
            details["field"] = field
        if field_errors:
            details["field_errors"] = field_errors

        super().__init__(
            message,
            category=ErrorCategory.VALIDATION,
            status_code=400,
            details=details,
            **kwargs,
        )
        self.field = field
        self.field_errors = field_errors or {}


class MCPAuthenticationError(MCPError):
    """MCP authentication-related errors.

    This exception class handles MCP-specific authentication failures
    and related security errors for the FastMCP server.

    The authentication error includes:
    - MCP-specific authentication error handling
    - Security-focused error messages
    - Authentication failure details for MCP context
    """

    def __init__(self, message: str = "MCP authentication failed", **kwargs):
        """Initialize the MCP authentication error.

        :param message: MCP authentication error message
        :type message: str
        :param **kwargs: Additional keyword arguments
        """
        super().__init__(
            message,
            category=ErrorCategory.AUTHENTICATION,
            status_code=401,
            **kwargs,
        )


class NetworkError(MCPError):
    """Network-related errors.

    This exception class handles network failures and
    connectivity issues.

    The network error includes:
    - Network-specific error handling
    - Connectivity failure details
    - Network error categorization
    """

    def __init__(self, message: str, **kwargs):
        """Initialize the network error.

        :param message: Network error message
        :type message: str
        :param **kwargs: Additional keyword arguments
        """
        super().__init__(
            message,
            category=ErrorCategory.NETWORK,
            status_code=502,
            **kwargs,
        )


class ExternalServiceError(MCPError):
    """External service errors.

    This exception class handles errors from external services
    and third-party integrations.

    The external service error includes:
    - Service identification
    - External service error details
    - Service-specific error handling
    """

    def __init__(self, message: str, service: str, **kwargs):
        """Initialize the external service error.

        :param message: External service error message
        :type message: str
        :param service: Name of the external service
        :type service: str
        :param **kwargs: Additional keyword arguments
        """
        details = kwargs.get("details", {})
        details["service"] = service
        super().__init__(
            message,
            category=ErrorCategory.EXTERNAL_SERVICE,
            status_code=503,
            details=details,
            **kwargs,
        )
        self.service = service


class DownloadTooLargeError(MCPError):
    """Raised when a streamed download exceeds the configured size cap.

    :param size: Observed size in bytes (partial count when streamed).
    :type size: int
    :param max_size: Configured maximum size in bytes.
    :type max_size: int
    """

    def __init__(self, size: int, max_size: int, **kwargs):
        details = kwargs.pop("details", {})
        details.update({"size": size, "max_size": max_size})
        super().__init__(
            f"Download exceeds max size: {size} > {max_size} bytes",
            category=ErrorCategory.VALIDATION,
            status_code=413,
            details=details,
            **kwargs,
        )
        self.size = size
        self.max_size = max_size


# =============================================================================
# Error Pattern Models
# =============================================================================


class ErrorPattern(BaseModel):
    """Error pattern for compression and recognition.

    This model defines patterns for error recognition and compression,
    enabling efficient error handling and message optimization.

    The error pattern includes:
    - Pattern name and identification
    - Error type matching
    - Keyword triggers
    - Compressed format templates
    - Pattern priority for matching
    """

    pattern_name: str = Field(..., description="Name of the error pattern")
    error_types: list[str] = Field(
        ..., description="Error types that match this pattern"
    )
    keywords: list[str] = Field(..., description="Keywords that trigger this pattern")
    compressed_format: str = Field(..., description="Compressed message format")
    priority: int = Field(default=0, description="Pattern matching priority")


class ErrorCompressionRule(BaseModel):
    """Rules for error message compression.

    This model defines rules for compressing error messages
    to optimize context window usage while maintaining essential information.

    The compression rule includes:
    - Rule name and identification
    - Input pattern matching (regex)
    - Output template for compression
    - Maximum length constraints
    - Applicable error categories
    """

    rule_name: str = Field(..., description="Name of the compression rule")
    input_pattern: str = Field(..., description="Regex pattern to match")
    output_template: str = Field(..., description="Compressed output template")
    max_length: int = Field(default=50, description="Maximum compressed message length")
    applies_to: list[ErrorCategory] = Field(
        default_factory=list,
        description="Error categories this rule applies to",
    )
