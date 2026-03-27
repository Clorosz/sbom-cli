"""CLI interface for SBOM ingestion and querying with CycloneDX 1.7 support."""

import json
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .core import SBOMDatabase
from .config import get_db_path
from .utils import get_logger
from . import __version__

app = typer.Typer(
    name="sbom-cli",
    help="CLI tool for ingesting and querying Software Bill of Materials (SBOMs). Supports CycloneDX 1.7 and SPDX.",
    add_completion=False,
)

console = Console()
logger = get_logger("sbom_cli")


def get_database(db_path: Optional[str] = None) -> SBOMDatabase:
    """Get database instance with optional custom path.

    Args:
        db_path: Optional database path.

    Returns:
        SBOMDatabase instance.
    """
    path = get_db_path(db_path)
    logger.debug(f"Using database path: {path}")
    return SBOMDatabase(path)


@app.command("ingest")
def ingest_sbom(
    sbom_file: str = typer.Argument(..., help="Path to the SBOM JSON file"),
    db_path: Optional[str] = typer.Option(
        None, "--db", "-d", help="Path to database file (default: sbom.db)"
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress output, only show errors"
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output results as JSON"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate without ingesting"),
) -> None:
    """Ingest an SBOM file into the database.

    Supports CycloneDX 1.7 and SPDX formats.
    """
    try:
        logger.info(f"Processing SBOM file: {sbom_file}")

        if dry_run:
            logger.info("Dry run mode - validating only")
            # Just validate the file can be loaded
            db = get_database(db_path)
            result = db.ingest_sbom(sbom_file)
            db.close()

            if json_output:
                console.print(
                    json.dumps({"dry_run": True, "validation": result}, indent=2)
                )
            elif not quiet:
                console.print(
                    Panel(
                        "[green]✓[/green] SBOM validation successful",
                        title="Dry Run Complete",
                        border_style="green",
                    )
                )
                console.print(
                    f"  [bold]Would ingest:[/bold] {result['components_ingested']} components"
                )
            sys.exit(0)
            return

        db = get_database(db_path)
        result = db.ingest_sbom(sbom_file)
        db.close()

        logger.info(f"Successfully ingested {result['components_ingested']} components")

        if json_output:
            console.print(json.dumps(result, indent=2))
        elif not quiet:
            console.print(
                Panel(
                    "[green]✓[/green] Successfully ingested SBOM",
                    title="Ingestion Complete",
                    border_style="green",
                )
            )
            console.print(f"  [bold]Document ID:[/bold] {result['document_id']}")
            console.print(
                f"  [bold]Type:[/bold] {result['sbom_type']} (v{result.get('sbom_version', 'N/A')})"
            )
            console.print(f"  [bold]Components:[/bold] {result['components_ingested']}")
            if result.get("services_ingested", 0) > 0:
                console.print(f"  [bold]Services:[/bold] {result['services_ingested']}")
            if result.get("vulnerabilities_ingested", 0) > 0:
                console.print(
                    f"  [bold]Vulnerabilities:[/bold] {result['vulnerabilities_ingested']}"
                )
            console.print(f"  [bold]Source:[/bold] {result['source_file']}")

        sys.exit(0)

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        if json_output:
            console.print(json.dumps({"error": str(e)}, indent=2))
        else:
            console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    except ValueError as e:
        logger.error(f"Invalid SBOM format: {e}")
        if json_output:
            console.print(json.dumps({"error": str(e)}, indent=2))
        else:
            console.print(f"[red]Error:[/red] {e}")
        sys.exit(2)

    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        if json_output:
            console.print(json.dumps({"error": str(e)}, indent=2))
        else:
            console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@app.command("query")
def query_sbom(
    component: Optional[str] = typer.Option(
        None,
        "--component",
        "-c",
        help="Component name to search for. Supports '*' wildcard (e.g., '*requests*', 'numpy*')",
    ),
    version: Optional[str] = typer.Option(
        None,
        "--version",
        "-v",
        help="Filter by version. Supports '*' wildcard (requires --component)",
    ),
    license: Optional[str] = typer.Option(
        None,
        "--license",
        "-l",
        help="License name to search for. Supports '*' wildcard (e.g., 'MIT*', '*Apache*')",
    ),
    vulnerability: Optional[str] = typer.Option(
        None,
        "--vulnerability",
        "-V",
        help="Vulnerability ID (e.g., CVE-2021-1234). Supports '*' wildcard",
    ),
    purl: Optional[str] = typer.Option(
        None, "--purl", "-p", help="Search by Package URL (purl). Supports '*' wildcard"
    ),
    db_path: Optional[str] = typer.Option(
        None, "--db", "-d", help="Path to database file (default: sbom.db)"
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output results as JSON"
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress output if no results"
    ),
) -> None:
    """Query SBOMs for components, licenses, or vulnerabilities.

    Search for packages by component name (optionally filtered by version),
    by license type, by vulnerability ID, or by purl.

    Wildcard Support:
        Use '*' to match any sequence of characters.
        Examples:
            - '*requests*' matches any component containing "requests"
            - 'numpy*' matches components starting with "numpy"
            - '*Apache*' matches any license containing "Apache"
            - 'CVE-2021-*' matches all CVEs from 2021
    """
    # Validate arguments
    search_params = [component, license, vulnerability, purl]
    active_params = [p for p in search_params if p]

    if len(active_params) == 0:
        console.print(
            "[red]Error:[/red] Must specify one of: --component, --license, --vulnerability, or --purl"
        )
        sys.exit(2)

    if len(active_params) > 1:
        console.print(
            "[red]Error:[/red] Cannot specify multiple search types simultaneously"
        )
        sys.exit(2)

    if version and not component:
        console.print("[red]Error:[/red] --version requires --component")
        sys.exit(2)

    try:
        db = get_database(db_path)
        results = []
        query_type = ""
        query_value = ""

        if component:
            logger.info(f"Querying component: {component}@{version or '*'}")
            results = db.query_by_component(component, version)
            query_type = "component"
            query_value = f"{component}@{version}" if version else component
        elif license:
            logger.info(f"Querying license: {license}")
            results = db.query_by_license(license)
            query_type = "license"
            query_value = license
        elif vulnerability:
            logger.info(f"Querying vulnerability: {vulnerability}")
            results = db.query_by_vulnerability(vulnerability)
            query_type = "vulnerability"
            query_value = vulnerability
        elif purl:
            logger.info(f"Querying purl: {purl}")
            # Search by purl with wildcard support
            results = db._query_by_purl(purl)
            query_type = "purl"
            query_value = purl

        db.close()

        logger.debug(f"Found {len(results)} results")

        if json_output:
            output = {
                "query": {"type": query_type, "value": query_value},
                "count": len(results),
                "results": results,
            }
            console.print(json.dumps(output, indent=2))
        else:
            if not results:
                if not quiet:
                    console.print(
                        f"[yellow]No results found[/yellow] for {query_type}: {query_value}"
                    )
                sys.exit(0)

            console.print(
                f"[green]Found {len(results)} result(s)[/green] for {query_type}: {query_value}\n"
            )

            if query_type == "vulnerability":
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Vulnerability", style="cyan")
                table.add_column("Source", style="green")
                table.add_column("Severity", style="yellow")
                table.add_column("Description", style="white")
                table.add_column("Published", style="blue")

                for result in results:
                    table.add_row(
                        result["vuln_id"],
                        result.get("source", "N/A"),
                        result.get("severity", "N/A"),
                        (
                            (result.get("description", "")[:50] + "...")
                            if result.get("description")
                            else "N/A"
                        ),
                        result.get("published", "N/A"),
                    )

                console.print(table)
            else:
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Component", style="cyan")
                table.add_column("Version", style="green")
                table.add_column("Type", style="blue")
                table.add_column("License(s)", style="yellow")
                table.add_column("Source", style="white")

                for result in results:
                    licenses = (
                        ", ".join(
                            [
                                lic.get("spdx_id") or lic.get("name", "UNKNOWN")
                                for lic in result.get("licenses", [])
                            ]
                        )
                        if result.get("licenses")
                        else "UNKNOWN"
                    )

                    table.add_row(
                        result["name"],
                        result.get("version", "N/A") or "N/A",
                        result.get("type", "N/A") or "N/A",
                        licenses,
                        result["document"]["source_file"],
                    )

                console.print(table)

        sys.exit(0)

    except Exception as e:
        logger.exception(f"Query error: {e}")
        if json_output:
            console.print(json.dumps({"error": str(e)}, indent=2))
        else:
            console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@app.command("list")
def list_documents(
    db_path: Optional[str] = typer.Option(
        None, "--db", "-d", help="Path to database file (default: sbom.db)"
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output results as JSON"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show detailed information"
    ),
) -> None:
    """List all ingested SBOM documents."""
    try:
        logger.info("Listing all documents")
        db = get_database(db_path)
        results = db.get_all_documents()
        db.close()

        if json_output:
            console.print(json.dumps({"documents": results}, indent=2))
        else:
            if not results:
                console.print("[yellow]No documents in database[/yellow]")
                sys.exit(0)

            console.print(f"[green]Ingested Documents ({len(results)})[/green]\n")

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("ID", style="cyan", justify="right")
            table.add_column("Type", style="green")
            table.add_column("Version", style="white")
            table.add_column("Components", style="yellow", justify="right")
            if verbose:
                table.add_column("Services", style="blue", justify="right")
                table.add_column("Vulns", style="red", justify="right")
            table.add_column("Name", style="white")
            table.add_column("Source", style="blue")

            for doc in results:
                row = [
                    str(doc["id"]),
                    doc["sbom_type"],
                    doc["sbom_version"] or "N/A",
                    str(doc["component_count"]),
                ]
                if verbose:
                    row.extend(
                        [
                            str(doc.get("service_count", 0)),
                            str(doc.get("vulnerability_count", 0)),
                        ]
                    )
                row.extend([doc["document_name"] or "N/A", doc["source_file"]])
                table.add_row(*row)

            console.print(table)

        sys.exit(0)

    except Exception as e:
        logger.exception(f"List error: {e}")
        if json_output:
            console.print(json.dumps({"error": str(e)}, indent=2))
        else:
            console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@app.command("stats")
def show_statistics(
    db_path: Optional[str] = typer.Option(
        None, "--db", "-d", help="Path to database file (default: sbom.db)"
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output results as JSON"
    ),
) -> None:
    """Show database statistics."""
    try:
        logger.info("Getting database statistics")
        db = get_database(db_path)
        stats = db.get_statistics()
        db.close()

        if json_output:
            console.print(json.dumps(stats, indent=2))
        else:
            console.print(
                Panel("[bold]SBOM Database Statistics[/bold]", border_style="blue")
            )
            console.print(f"  [bold]Documents:[/bold]      {stats['documents']}")
            console.print(f"  [bold]Components:[/bold]    {stats['components']}")
            console.print(f"  [bold]Services:[/bold]      {stats['services']}")
            console.print(f"  [bold]Vulnerabilities:[/bold] {stats['vulnerabilities']}")
            console.print(f"  [bold]Licenses:[/bold]      {stats['licenses']}")

        sys.exit(0)

    except Exception as e:
        logger.exception(f"Stats error: {e}")
        if json_output:
            console.print(json.dumps({"error": str(e)}, indent=2))
        else:
            console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@app.command("version")
def show_version() -> None:
    """Show version information."""
    console.print(f"sbom-cli version {__version__}")
    sys.exit(0)


def main() -> None:
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
