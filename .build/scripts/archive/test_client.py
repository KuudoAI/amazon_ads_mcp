#!/usr/bin/env python3
"""
Simple test client for Amazon Ads MCP Server
Tests the server's HTTP API directly
"""

import asyncio
import json
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.json import JSON
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

console = Console()

class SimpleMCPClient:
    def __init__(self, base_url="http://localhost:9080"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(
            base_url=base_url,
            timeout=30.0,
            headers={
                "Content-Type": "application/json",
            }
        )
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    async def test_connection(self):
        """Test basic connection to the server"""
        try:
            response = await self.client.get("/")
            console.print(f"[green]✓[/green] Server responded with status: {response.status_code}")
            return True
        except Exception as e:
            console.print(f"[red]✗[/red] Connection failed: {e}")
            return False
    
    async def list_tools(self):
        """List available tools from the server"""
        try:
            # Try the standard MCP endpoint
            response = await self.client.post(
                "/",
                json={
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "id": 1
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if "result" in data:
                    return data["result"].get("tools", [])
                elif "error" in data:
                    console.print(f"[red]Error from server: {data['error']}[/red]")
                    return []
            else:
                console.print(f"[yellow]Non-200 status: {response.status_code}[/yellow]")
                console.print(f"Response: {response.text}")
                return []
        except Exception as e:
            console.print(f"[red]Failed to list tools: {e}[/red]")
            return []
    
    async def call_tool(self, tool_name, arguments=None):
        """Call a specific tool"""
        try:
            response = await self.client.post(
                "/",
                json={
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": arguments or {}
                    },
                    "id": 2
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if "result" in data:
                    return data["result"]
                elif "error" in data:
                    console.print(f"[red]Error from server: {data['error']}[/red]")
                    return None
            else:
                console.print(f"[red]HTTP {response.status_code}: {response.text}[/red]")
                return None
        except Exception as e:
            console.print(f"[red]Failed to call tool: {e}[/red]")
            return None
    
    async def test_profiles_api(self):
        """Test the profiles API directly"""
        console.print("\n[bold cyan]Testing Profiles API Directly[/bold cyan]")
        
        # Try to call the API endpoint directly
        try:
            # Add auth headers if available
            headers = {
                "Content-Type": "application/json",
            }
            
            client_id = os.getenv("AMAZON_ADS_CLIENT_ID")
            if client_id:
                headers["Amazon-Ads-API-ClientId"] = client_id
                console.print(f"[green]Using Client ID from env: {client_id[:20]}...[/green]")
            
            # First, let's try the direct Amazon Ads API endpoint
            console.print("\n[yellow]Testing direct API call to /v2/profiles[/yellow]")
            
            response = await self.client.get(
                "/v2/profiles",
                headers=headers
            )
            
            console.print(f"Status: {response.status_code}")
            if response.status_code == 200:
                profiles = response.json()
                return profiles
            else:
                console.print(f"Response: {response.text[:500]}")
                return []
                
        except Exception as e:
            console.print(f"[red]Direct API test failed: {e}[/red]")
            return []


async def main():
    console.print(Panel.fit(
        "[bold cyan]Amazon Ads MCP Server Test Client[/bold cyan]\n"
        "Testing server functionality",
        border_style="cyan"
    ))
    
    # Test with the actual running server
    server_url = "http://localhost:9080"
    
    async with SimpleMCPClient(server_url) as client:
        # Test connection
        console.print("\n[bold]1. Testing Connection[/bold]")
        connected = await client.test_connection()
        
        if not connected:
            console.print("[red]Cannot connect to server. Is it running?[/red]")
            console.print("Start server with: python -m src.amazon_ads_mcp.server.mcp_server_mounted --transport http --port 9080")
            return
        
        # List tools
        console.print("\n[bold]2. Listing Available Tools[/bold]")
        tools = await client.list_tools()
        
        if tools:
            table = Table(title="Available Tools", show_header=True)
            table.add_column("Name", style="cyan")
            table.add_column("Description", style="white")
            
            for tool in tools:
                name = tool.get("name", "Unknown")
                desc = tool.get("description", "")[:60]
                if len(tool.get("description", "")) > 60:
                    desc += "..."
                table.add_row(name, desc)
            
            console.print(table)
        else:
            console.print("[yellow]No tools found or server returned empty list[/yellow]")
        
        # Try to call listProfiles tool
        console.print("\n[bold]3. Testing listProfiles Tool[/bold]")
        
        profiles_result = await client.call_tool("listProfiles", {})
        
        if profiles_result:
            console.print("[green]✓[/green] Tool call successful!")
            
            # Check if we got profiles
            if isinstance(profiles_result, dict) and "content" in profiles_result:
                content = profiles_result["content"]
                if isinstance(content, list) and len(content) > 0:
                    # Parse the content
                    if isinstance(content[0], dict) and "text" in content[0]:
                        try:
                            profiles_data = json.loads(content[0]["text"])
                            console.print(f"[green]Found {len(profiles_data)} profiles![/green]")
                            
                            # Display profiles in a table
                            profile_table = Table(title="Amazon Ads Profiles", show_header=True)
                            profile_table.add_column("Profile ID", style="cyan")
                            profile_table.add_column("Country", style="green")
                            profile_table.add_column("Currency", style="yellow")
                            profile_table.add_column("Type", style="magenta")
                            
                            for profile in profiles_data[:5]:  # Show first 5
                                profile_table.add_row(
                                    str(profile.get("profileId", "N/A")),
                                    profile.get("countryCode", "N/A"),
                                    profile.get("currencyCode", "N/A"),
                                    profile.get("accountInfo", {}).get("type", "N/A")
                                )
                            
                            console.print(profile_table)
                            
                            if len(profiles_data) > 5:
                                console.print(f"[dim]... and {len(profiles_data) - 5} more profiles[/dim]")
                        except json.JSONDecodeError:
                            console.print("[yellow]Could not parse profile data as JSON[/yellow]")
                            console.print(f"Raw content: {content[0]['text'][:200]}...")
                else:
                    console.print("[yellow]No profiles returned[/yellow]")
                    console.print(f"Result structure: {profiles_result}")
        else:
            console.print("[yellow]Tool call returned no result[/yellow]")
        
        # Test direct API
        console.print("\n[bold]4. Testing Direct API Access[/bold]")
        direct_profiles = await client.test_profiles_api()
        
        if direct_profiles:
            console.print(f"[green]Direct API returned {len(direct_profiles)} profiles[/green]")
        
        # Test a specific profile if we have one
        if tools and profiles_result:
            # Try to extract a profile ID
            try:
                if isinstance(profiles_result, dict) and "content" in profiles_result:
                    content = profiles_result["content"]
                    if isinstance(content, list) and len(content) > 0:
                        if isinstance(content[0], dict) and "text" in content[0]:
                            profiles_data = json.loads(content[0]["text"])
                            if profiles_data and len(profiles_data) > 0:
                                profile_id = profiles_data[0].get("profileId")
                                
                                if profile_id:
                                    console.print(f"\n[bold]5. Testing getProfileById with ID: {profile_id}[/bold]")
                                    
                                    profile_detail = await client.call_tool(
                                        "getProfileById",
                                        {"profileId": profile_id}
                                    )
                                    
                                    if profile_detail:
                                        console.print("[green]✓[/green] Successfully retrieved profile details")
                                        console.print(Panel(
                                            JSON(json.dumps(profile_detail, indent=2)),
                                            title=f"Profile {profile_id} Details",
                                            border_style="green"
                                        ))
            except Exception as e:
                console.print(f"[yellow]Could not test specific profile: {e}[/yellow]")
        
        console.print("\n[bold green]✓ Test Complete![/bold green]")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Test failed with error: {e}[/red]")
        import traceback
        traceback.print_exc()