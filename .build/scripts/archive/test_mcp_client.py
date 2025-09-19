#!/usr/bin/env python3
"""
Test the MCP server using the official MCP client library
"""

import asyncio
import json
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from dotenv import load_dotenv
import subprocess
import os

# Load environment variables
load_dotenv()

console = Console()

async def test_with_stdio():
    """Test the MCP server using stdio transport"""
    console.print(Panel.fit(
        "[bold cyan]Amazon Ads MCP Server Test[/bold cyan]\n"
        "Using stdio transport",
        border_style="cyan"
    ))
    
    # Configure the server parameters
    server_params = StdioServerParameters(
        command=".venv/bin/python",
        args=["-m", "src.amazon_ads_mcp.server.mcp_server_mounted", "--transport", "stdio"],
        env=None
    )
    
    console.print(f"[cyan]Starting server: {server_params.command} {' '.join(server_params.args)}[/cyan]")
    
    # Use stdio_client to connect to the server
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # Initialize
            console.print("\n[bold]1. Initializing session[/bold]")
            await session.initialize()
            console.print("[green]✓[/green] Session initialized")
            
            # List tools
            console.print("\n[bold]2. Listing available tools[/bold]")
            tools = await session.list_tools()
            
            if tools:
                table = Table(title="Available Tools", show_header=True)
                table.add_column("Name", style="cyan")
                table.add_column("Description", style="white", width=50)
                
                for tool in tools:
                    # Handle both tuple and object formats
                    if hasattr(tool, 'name'):
                        name = tool.name
                        desc = (tool.description or "")[:50]
                    elif isinstance(tool, tuple) and len(tool) >= 2:
                        name = tool[0]
                        desc = str(tool[1] or "")[:50]
                    else:
                        name = str(tool)
                        desc = ""
                    
                    if len(desc) > 50:
                        desc = desc[:50] + "..."
                    table.add_row(name, desc)
                
                console.print(table)
                console.print(f"[green]Found {len(tools)} tools[/green]")
            else:
                console.print("[yellow]No tools found[/yellow]")
                return
            
            # Test listProfiles
            console.print("\n[bold]3. Testing listProfiles tool[/bold]")
            
            try:
                result = await session.call_tool("listProfiles", {})
                
                if result and result.content:
                    # Parse the result
                    if isinstance(result.content, list) and len(result.content) > 0:
                        if hasattr(result.content[0], 'text'):
                            try:
                                profiles = json.loads(result.content[0].text)
                                console.print(f"[green]✓ Found {len(profiles)} profiles![/green]")
                                
                                # Display profiles
                                profile_table = Table(title="Amazon Ads Profiles", show_header=True)
                                profile_table.add_column("Profile ID", style="cyan")
                                profile_table.add_column("Country", style="green")
                                profile_table.add_column("Currency", style="yellow")
                                profile_table.add_column("Account Type", style="magenta")
                                
                                for profile in profiles[:5]:
                                    account_info = profile.get("accountInfo", {})
                                    profile_table.add_row(
                                        str(profile.get("profileId", "N/A")),
                                        profile.get("countryCode", "N/A"),
                                        profile.get("currencyCode", "N/A"),
                                        account_info.get("type", "N/A")
                                    )
                                
                                console.print(profile_table)
                                
                                if len(profiles) > 5:
                                    console.print(f"[dim]... and {len(profiles) - 5} more profiles[/dim]")
                                
                                # Test getting a specific profile
                                if profiles:
                                    profile_id = profiles[0].get("profileId")
                                    if profile_id:
                                        console.print(f"\n[bold]4. Testing getProfileById with ID: {profile_id}[/bold]")
                                        
                                        profile_result = await session.call_tool(
                                            "getProfileById",
                                            {"profileId": profile_id}
                                        )
                                        
                                        if profile_result and profile_result.content:
                                            if isinstance(profile_result.content, list) and len(profile_result.content) > 0:
                                                if hasattr(profile_result.content[0], 'text'):
                                                    profile_data = json.loads(profile_result.content[0].text)
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
                                console.print(f"[red]Failed to parse profiles: {e}[/red]")
                        else:
                            console.print(f"[yellow]Unexpected result format[/yellow]")
            except Exception as e:
                console.print(f"[red]Error calling tool: {e}[/red]")
            
            # List resources
            console.print("\n[bold]5. Listing available resources[/bold]")
            try:
                resources = await session.list_resources()
                if resources:
                    console.print(f"[green]Found {len(resources)} resources[/green]")
                    for resource in resources[:5]:
                        console.print(f"  - {resource.uri}: {resource.name}")
                else:
                    console.print("[yellow]No resources found[/yellow]")
            except Exception as e:
                console.print(f"[yellow]Resources not available: {e}[/yellow]")
            
            console.print("\n[bold green]✓ Test Complete![/bold green]")


async def main():
    try:
        await test_with_stdio()
    except Exception as e:
        console.print(f"[red]Test failed: {e}[/red]")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")