# Clean Architecture for FastMCP 2.11

## Architecture Overview

This project follows a clean, layered architecture that separates concerns and maintains clear dependency directions:

```
┌─────────────────────────────────────┐
│         Tool Layer (Thin)           │  ← FastMCP @Tool decorators
│   tools/identity_profile_tools.py   │  ← Context state management
└─────────────────────────────────────┘
                 ↓ calls
┌─────────────────────────────────────┐
│       Service Layer (Logic)         │  ← Business logic
│     identity.py, profile.py         │  ← No FastMCP imports
└─────────────────────────────────────┘
                 ↓ uses
┌─────────────────────────────────────┐
│      Provider Layer (Infra)         │  ← External integrations
│   auth/providers.py, manager.py     │  ← API clients, caching
└─────────────────────────────────────┘
```

## Key Principles

### 1. **Tools are Thin Wrappers**
Tools contain NO business logic - they only:
- Accept `ctx: Context` parameter
- Read/write Context state
- Call service layer functions
- Add metadata (tags, schemas)

### 2. **Services are Pure Functions**
Service layer contains all business logic:
- No FastMCP imports
- Testable without server context
- Can be imported and used anywhere
- Handle all domain logic

### 3. **Clear Dependency Direction**
Dependencies flow in one direction:
- Tools → Services → Providers
- Never the reverse
- No circular dependencies

## File Structure

```
src/amazon_ads_mcp/
├── tools/
│   ├── identity_profile_tools.py  # Thin FastMCP tool wrappers
│   ├── identity.py                # Identity service logic
│   └── profile.py                 # Profile service logic
├── auth/
│   ├── manager.py                 # Auth management
│   ├── providers.py               # Auth providers
│   └── hooks.py                   # FastMCP request hooks
└── models/
    └── ...                        # Pydantic models
```

## Example: Tool as Thin Wrapper

```python
# tools/identity_profile_tools.py
@Tool(
    name="set_active_identity",
    tags={"identity", "authentication"},
    output_schema={...}
)
async def set_active_identity_tool(
    ctx: Context,
    identity_id: str,
    persist: bool = False
) -> dict:
    """Thin wrapper - no business logic."""
    # Create request
    request = SetActiveIdentityRequest(
        identity_id=identity_id,
        persist=persist
    )
    
    # Call service layer (all logic is there)
    result = await identity.set_active_identity(request)
    
    # Store in Context state for request scope
    ctx.state["active_identity_id"] = identity_id
    
    return result
```

## Example: Service with Business Logic

```python
# identity.py (service layer)
async def set_active_identity(request: SetActiveIdentityRequest) -> dict:
    """Service function with all business logic."""
    auth_manager = get_auth_manager()
    
    # Validate identity exists
    identity_info = await get_identity_info(request.identity_id)
    if not identity_info:
        raise ValueError(f"Identity {request.identity_id} not found")
    
    # Set the active identity
    auth_manager.set_active_identity(identity_info)
    
    # Persist if requested
    if request.persist:
        # ... persistence logic ...
    
    # Return structured response
    return {
        "success": True,
        "identity_id": request.identity_id,
        "identity_name": identity_info.get("name"),
        "message": f"Active identity set to {request.identity_id}"
    }
```

## Context State Management

Tools use FastMCP 2.11's Context state for request-scoped data:

```python
# Store in Context
ctx.state["active_identity_id"] = identity_id
ctx.state["active_profile_id"] = profile_id

# Read from Context
identity_id = ctx.state.get("active_identity_id")
profile_id = ctx.state.get("active_profile_id")
```

## Benefits

1. **No Duplication**: Business logic exists in one place
2. **Testability**: Services can be unit tested without FastMCP
3. **Flexibility**: Can easily swap tool layer (FastMCP → something else)
4. **Clarity**: Clear separation of concerns
5. **Maintainability**: Changes to business logic don't affect tool layer

## Migration from Old Pattern

### Old (Mixed Concerns):
```python
# tools/identity_tools.py
@tool
async def set_identity(identity_id: str):
    # Business logic mixed with tool code
    auth_manager = get_auth_manager()
    if not validate_identity(identity_id):
        raise ValueError("Invalid")
    # ... more logic ...
    return result
```

### New (Clean Separation):
```python
# tools/identity_profile_tools.py
@Tool(tags={"identity"})
async def set_identity_tool(ctx: Context, identity_id: str):
    # Just a wrapper
    result = await identity.set_active_identity(identity_id)
    ctx.state["identity_id"] = identity_id
    return result

# identity.py
async def set_active_identity(identity_id: str):
    # All business logic here
    # ... validation, processing, etc ...
    return result
```

## Testing Strategy

### Service Layer Tests
```python
# Test pure functions without FastMCP
def test_set_active_identity():
    result = await identity.set_active_identity("id123")
    assert result["success"] == True
```

### Tool Layer Tests
```python
# Test with mock Context
def test_set_identity_tool():
    ctx = MockContext()
    result = await set_identity_tool(ctx, "id123")
    assert ctx.state["identity_id"] == "id123"
```

## Summary

This architecture provides:
- **Clean separation** between FastMCP integration and business logic
- **Better testability** through pure service functions
- **Context-first** state management
- **No duplication** of business logic
- **Clear dependency** direction

Following these patterns ensures the codebase remains maintainable, testable, and aligned with FastMCP 2.11 best practices.