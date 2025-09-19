#!/usr/bin/env python3
"""
Test client for FastMCP server using SSE transport
"""

import asyncio
import json
import httpx
from httpx_sse import aconnect_sse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from dotenv import load_dotenv
import os
import uuid

# Load environment variables
load_dotenv()

console = Console()

class SSEMCPClient:
    def __init__(self, base_url="http://localhost:9080"):
        self.base_url = base_url
        self.endpoint = f"{base_url}/mcp/v1"
        self.message_id = 0
        
    def get_next_id(self):
        self.message_id += 1
        return str(self.message_id)
    
    async def send_request(self, method, params=None):
        """Send a request and get response via SSE"""
        request_id = self.get_next_id()
        request_data = {
            "jsonrpc": "2.0",
            "method": method,
            "id": request_id
        }
        
        if params:
            request_data["params"] = params
        
        headers = {
            "Accept": "text/event-stream",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Send the request and get SSE response
            async with aconnect_sse(
                client,
                "POST",
                self.endpoint,
                json=request_data,
                headers=headers
            ) as event_source:
                async for sse in event_source.aiter_sse():
                    if sse.event == "message":
                        try:
                            data = json.loads(sse.data)
                            if data.get("id") == request_id:
                                return data
                        except json.JSONDecodeError:
                            console.print(f"[yellow]Failed to parse SSE data: {sse.data}[/yellow]")
                    elif sse.event == "error":
                        console.print(f"[red]SSE Error: {sse.data}[/red]")
                        return None
        
        return None
    
    async def initialize(self):
        """Initialize the MCP session"""
        console.print("[cyan]Initializing MCP session...[/cyan]")
        
        result = await self.send_request(
            "initialize",
            {
                "protocolVersion": "0.1.0",
                "capabilities": {
                    "tools": {},
                    "prompts": {},
                    "resources": {}
                },
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        )
        
        if result and "result" in result:
            console.print("[green]✓[/green] Session initialized")
            return result["result"]
        else:
            console.print("[red]✗[/red] Failed to initialize session")
            if result and "error" in result:
                console.print(f"Error: {result['error']}")
            return None
    
    async def list_tools(self):
        """List available tools"""
        console.print("\n[cyan]Listing tools...[/cyan]")
        
        result = await self.send_request("tools/list")
        
        if result and "result" in result:
            tools = result["result"].get("tools", [])
            return tools
        else:
            console.print("[red]Failed to list tools[/red]")
            if result and "error" in result:
                console.print(f"Error: {result['error']}")
            return []
    
    async def call_tool(self, tool_name, arguments=None):
        """Call a specific tool"""
        console.print(f"\n[cyan]Calling tool: {tool_name}[/cyan]")
        
        result = await self.send_request(
            "tools/call",
            {
                "name": tool_name,
                "arguments": arguments or {}
            }
        )
        
        if result and "result" in result:
            return result["result"]
        else:
            console.print(f"[red]Failed to call tool {tool_name}[/red]")
            if result and "error" in result:
                console.print(f"Error: {result['error']}")
            return None


async def main():
    console.print(Panel.fit(
        "[bold cyan]Amazon Ads MCP Server SSE Test[/bold cyan]\n"
        "Testing server via SSE transport",
        border_style="cyan"
    ))
    
    client = SSEMCPClient("http://localhost:9080")
    
    # Initialize session
    init_result = await client.initialize()
    if not init_result:
        console.print("[red]Failed to initialize. Exiting.[/red]")
        return
    
    console.print(f"Server info: {init_result.get('serverInfo', {})}")
    
    # List tools
    tools = await client.list_tools()
    
    if tools:
        table = Table(title="Available Tools", show_header=True)
        table.add_column("Name", style="cyan")
        table.add_column("Description", style="white", width=50)
        
        for tool in tools:
            name = tool.get("name", "Unknown")
            desc = tool.get("description", "")[:50]
            if len(tool.get("description", "")) > 50:
                desc += "..."
            table.add_row(name, desc)
        
        console.print(table)
        
        # Test listProfiles
        console.print("\n[bold]Testing listProfiles tool[/bold]")
        profiles_result = await client.call_tool("listProfiles")
        
        if profiles_result:
            # Extract profiles from result
            if "content" in profiles_result:
                content = profiles_result["content"]
                if isinstance(content, list) and len(content) > 0:
                    if isinstance(content[0], dict) and "text" in content[0]:
                        try:
                            # The text field contains the JSON response
                            profiles = json.loads(content[0]["text"])
                            
                            console.print(f"[green]✓ Found {len(profiles)} profiles![/green]")
                            
                            # Display profiles
                            profile_table = Table(title="Amazon Ads Profiles", show_header=True)
                            profile_table.add_column("Profile ID", style="cyan")
                            profile_table.add_column("Country", style="green")
                            profile_table.add_column("Currency", style="yellow")
                            profile_table.add_column("Account Type", style="magenta")
                            profile_table.add_column("Account Name", style="white")
                            
                            for profile in profiles[:5]:
                                account_info = profile.get("accountInfo", {})
                                profile_table.add_row(
                                    str(profile.get("profileId", "N/A")),
                                    profile.get("countryCode", "N/A"),
                                    profile.get("currencyCode", "N/A"),
                                    account_info.get("type", "N/A"),
                                    account_info.get("name", "N/A")[:30]
                                )
                            
                            console.print(profile_table)
                            
                            if len(profiles) > 5:
                                console.print(f"[dim]... and {len(profiles) - 5} more profiles[/dim]")
                            
                            # Test getting a specific profile
                            if profiles:
                                profile_id = profiles[0].get("profileId")
                                if profile_id:
                                    console.print(f"\n[bold]Testing getProfileById with ID: {profile_id}[/bold]")
                                    
                                    profile_detail = await client.call_tool(
                                        "getProfileById",
                                        {"profileId": profile_id}
                                    )
                                    
                                    if profile_detail and "content" in profile_detail:
                                        content = profile_detail["content"]
                                        if isinstance(content, list) and len(content) > 0:
                                            if isinstance(content[0], dict) and "text" in content[0]:
                                                profile_data = json.loads(content[0]["text"])
                                                console.print("[green]✓ Successfully retrieved profile details[/green]")
                                                
                                                # Display key details
                                                console.print(f"Profile ID: {profile_data.get('profileId')}")
                                                console.print(f"Country: {profile_data.get('countryCode')}")
                                                console.print(f"Currency: {profile_data.get('currencyCode')}")
                                                console.print(f"Timezone: {profile_data.get('timezone')}")
                                                
                                                if "accountInfo" in profile_data:
                                                    acc = profile_data["accountInfo"]
                                                    console.print(f"Account: {acc.get('name')} ({acc.get('type')})")
                                                    console.print(f"Marketplace: {acc.get('marketplaceStringId')}")
                            
                        except json.JSONDecodeError as e:
                            console.print(f"[red]Failed to parse profiles JSON: {e}[/red]")
                            console.print(f"Raw content: {content[0].get('text', '')[:200]}")
                    else:
                        console.print(f"[yellow]Unexpected content structure: {content}[/yellow]")
                else:
                    console.print("[yellow]No content in response[/yellow]")
            else:
                console.print(f"[yellow]No content field in result: {profiles_result}[/yellow]")
    else:
        console.print("[yellow]No tools found[/yellow]")
    
    console.print("\n[bold green]✓ Test Complete![/bold green]")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Test failed: {e}[/red]")
        import traceback
        traceback.print_exc()