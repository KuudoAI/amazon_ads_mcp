"""Report formatters for MCP tool token audit."""

from .models import AuditReport

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False


def render_json(report: AuditReport) -> None:
    """Emit AuditReport as indented JSON to stdout."""
    print(report.model_dump_json(indent=2))


def render_console(
    report: AuditReport,
    threshold: int = 1000,
    limit: int = 20,
) -> None:
    """Render the audit report to console.

    Uses rich for pretty tables if available, otherwise plain text.

    :param report: The audit report to render.
    :param threshold: Token count threshold for [!] markers.
    :param limit: Max tools to show (0 = all).
    """
    if _HAS_RICH:
        _render_rich(report, threshold, limit)
    else:
        _render_plain(report, threshold, limit)


def _render_rich(
    report: AuditReport,
    threshold: int,
    limit: int,
) -> None:
    """Render with rich tables."""
    console = Console()

    # Header
    console.print()
    console.print("[bold]MCP Tool Token Audit[/bold]")
    console.print("=" * 40)
    console.print(f"Server:   {report.server_url}")
    console.print(f"Tools:    {report.tool_count}")
    console.print(f"Encoding: {report.encoding}")
    mode_desc = (
        "strict (name + description + inputSchema only)"
        if report.mode == "strict"
        else "full (all wire fields)"
    )
    console.print(f"Mode:     {mode_desc}")
    console.print()

    # Tools table
    tools = report.tools
    display_count = len(tools) if limit == 0 else min(limit, len(tools))
    remaining = len(tools) - display_count

    if display_count > 0:
        title = "Top Token Consumers"
        if limit > 0 and remaining > 0:
            title += f" (showing top {display_count} of {len(tools)})"

        table = Table(title=title, show_lines=False)
        table.add_column("#", justify="right", style="dim", width=4)
        table.add_column("Tool Name", min_width=30)
        table.add_column("Prefix", justify="center", width=8)
        table.add_column("Schema", justify="right", width=8)
        table.add_column("Desc", justify="right", width=7)
        table.add_column("Name", justify="right", width=6)
        table.add_column("Total", justify="right", width=8)
        table.add_column("", width=3)

        for i, tool in enumerate(tools[:display_count], 1):
            flag = "[!]" if tool.total_tokens > threshold else ""
            style = "bold red" if tool.total_tokens > threshold else None
            table.add_row(
                str(i),
                tool.name,
                tool.prefix,
                f"{tool.schema_tokens:,}",
                f"{tool.description_tokens:,}",
                f"{tool.name_tokens:,}",
                f"{tool.total_tokens:,}",
                flag,
                style=style,
            )

        console.print(table)

        violation_count = len(report.threshold_violations)
        if violation_count > 0:
            console.print(
                f"\n[bold red][!][/bold red] = exceeds "
                f"{threshold:,} token threshold "
                f"({violation_count} tool{'s' if violation_count != 1 else ''} total)"
            )
        if remaining > 0:
            console.print(
                f"[dim]... {remaining} more tools not shown "
                f"(use --limit 0 to show all)[/dim]"
            )
    else:
        console.print("[yellow]No tools found on server.[/yellow]")

    console.print()

    # Group analysis
    if report.groups:
        group_table = Table(title="Group Analysis", show_lines=False)
        group_table.add_column("Prefix", width=10)
        group_table.add_column("Tools", justify="right", width=6)
        group_table.add_column("Total Tokens", justify="right", width=13)
        group_table.add_column("Avg/Tool", justify="right", width=9)
        group_table.add_column("Largest Tool (tokens)", min_width=30)

        for group in report.groups:
            group_table.add_row(
                group.prefix,
                str(group.tool_count),
                f"{group.total_tokens:,}",
                f"{group.avg_tokens_per_tool:,.0f}",
                f"{group.largest_tool} ({group.largest_tool_tokens:,})",
            )

        console.print(group_table)
    console.print()

    # Optional code mode probe section
    probe = report.code_mode_probe
    if probe and probe.enabled:
        console.print("[bold]Code Mode Probe[/bold]")
        console.print("-" * 30)
        console.print(f"Meta-tools:       {', '.join(probe.meta_tools) if probe.meta_tools else '(none)'}")
        console.print(f"Search tool:      {probe.search_tool or '(not found)'}")
        console.print(f"Schema tool:      {probe.schema_tool or '(not found)'}")
        console.print(f"Sampled tools:    {probe.sampled_tool_count}")
        if probe.sampled_tool_count > 0:
            console.print(f"Total schema tok: {probe.total_schema_tokens:,}")
            console.print(f"Avg/schema tok:   {probe.avg_schema_tokens:,.1f}")
        failed = [f for f in probe.schema_fetches if not f.ok]
        if failed:
            console.print(f"[yellow]Schema fetch failures: {len(failed)}[/yellow]")
        console.print()

    # Context window impact
    console.print("[bold]Context Window Impact[/bold]")
    console.print("-" * 30)
    console.print(
        f"Total tool tokens:  {report.total_tool_tokens:>10,}"
    )
    console.print(
        f"Context window:     {report.context_window_size:>10,}"
    )

    pct = report.context_window_percent
    pct_style = "bold red" if pct > 30 else "bold yellow" if pct > 15 else "bold green"
    console.print(
        "Consumed:           ",
        Text(f"{pct:>9.2f}%", style=pct_style),
    )
    console.print()

    # Footer
    console.print(
        f"[dim]Note: Token counts use {report.encoding} encoding.[/dim]"
    )
    if "fallback" in report.encoding:
        console.print(
            "[dim bold]      Coarse estimate only. "
            "Install tiktoken for accurate counts.[/dim bold]"
        )
    else:
        console.print(
            "[dim]      Actual Claude tokenization may vary ~5-10%.[/dim]"
        )
    console.print()


def _render_plain(
    report: AuditReport,
    threshold: int,
    limit: int,
) -> None:
    """Render with plain text formatting (no rich)."""
    print()
    print("MCP Tool Token Audit")
    print("=" * 40)
    print(f"Server:   {report.server_url}")
    print(f"Tools:    {report.tool_count}")
    print(f"Encoding: {report.encoding}")
    mode_desc = (
        "strict (name + description + inputSchema only)"
        if report.mode == "strict"
        else "full (all wire fields)"
    )
    print(f"Mode:     {mode_desc}")
    print()

    # Tools table
    tools = report.tools
    display_count = len(tools) if limit == 0 else min(limit, len(tools))
    remaining = len(tools) - display_count

    if display_count > 0:
        header = "--- Top Token Consumers"
        if limit > 0 and remaining > 0:
            header += f" (showing top {display_count} of {len(tools)})"
        header += " ---"
        print(header)
        print()

        # Column header
        print(
            f"{'#':>4s}  {'Tool Name':<40s}  {'Prefix':<8s}  "
            f"{'Schema':>7s}  {'Desc':>6s}  {'Name':>5s}  {'Total':>7s}"
        )
        print(
            f"{'':->4s}  {'':->40s}  {'':->8s}  "
            f"{'':->7s}  {'':->6s}  {'':->5s}  {'':->7s}"
        )

        for i, tool in enumerate(tools[:display_count], 1):
            flag = " [!]" if tool.total_tokens > threshold else ""
            print(
                f"{i:>4d}  {tool.name:<40s}  {tool.prefix:<8s}  "
                f"{tool.schema_tokens:>7,}  {tool.description_tokens:>6,}  "
                f"{tool.name_tokens:>5,}  {tool.total_tokens:>7,}{flag}"
            )

        violation_count = len(report.threshold_violations)
        if violation_count > 0:
            print(
                f"\n[!] = exceeds {threshold:,} token threshold "
                f"({violation_count} tool{'s' if violation_count != 1 else ''} total)"
            )
        if remaining > 0:
            print(
                f"... {remaining} more tools not shown "
                f"(use --limit 0 to show all)"
            )
    else:
        print("No tools found on server.")

    print()

    # Group analysis
    if report.groups:
        print("--- Group Analysis ---")
        print()
        print(
            f"{'Prefix':<10s}  {'Tools':>5s}  {'Total Tokens':>13s}  "
            f"{'Avg/Tool':>9s}  {'Largest Tool (tokens)'}"
        )
        print(
            f"{'':->10s}  {'':->5s}  {'':->13s}  "
            f"{'':->9s}  {'':->30s}"
        )

        for group in report.groups:
            print(
                f"{group.prefix:<10s}  {group.tool_count:>5d}  "
                f"{group.total_tokens:>13,}  "
                f"{group.avg_tokens_per_tool:>9,.0f}  "
                f"{group.largest_tool} ({group.largest_tool_tokens:,})"
            )

    print()

    # Optional code mode probe section
    probe = report.code_mode_probe
    if probe and probe.enabled:
        print("--- Code Mode Probe ---")
        print()
        print(f"Meta-tools:       {', '.join(probe.meta_tools) if probe.meta_tools else '(none)'}")
        print(f"Search tool:      {probe.search_tool or '(not found)'}")
        print(f"Schema tool:      {probe.schema_tool or '(not found)'}")
        print(f"Sampled tools:    {probe.sampled_tool_count}")
        if probe.sampled_tool_count > 0:
            print(f"Total schema tok: {probe.total_schema_tokens:,}")
            print(f"Avg/schema tok:   {probe.avg_schema_tokens:,.1f}")
        failed = [f for f in probe.schema_fetches if not f.ok]
        if failed:
            print(f"Schema fetch failures: {len(failed)}")
        print()

    # Context window impact
    print("--- Context Window Impact ---")
    print()
    print(f"Total tool tokens:  {report.total_tool_tokens:>10,}")
    print(f"Context window:     {report.context_window_size:>10,}")
    print(f"Consumed:           {report.context_window_percent:>9.2f}%")
    print()

    # Footer
    print(f"Note: Token counts use {report.encoding} encoding.")
    if "fallback" in report.encoding:
        print(
            "      Coarse estimate only. "
            "Install tiktoken for accurate counts."
        )
    else:
        print("      Actual Claude tokenization may vary ~5-10%.")
    print()
