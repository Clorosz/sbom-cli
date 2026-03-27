# SBOM CLI

A command-line tool for ingesting and querying Software Bill of Materials (SBOMs). Supports CycloneDX 1.7 and SPDX 2.3/3.0 formats with persistent SQLite storage.

## Quick Start

```bash
cd sbom-cli
pip install -e .

# Ingest an SBOM
sbom-cli ingest path/to/bom.json

# Query components
sbom-cli query --component lodash

# Check for vulnerabilities
sbom-cli query --vulnerability CVE-2021-44228
```

## Installation

Requires Python 3.8+.

```bash
pip install -e .
```

Dependencies (installed automatically):
- `typer` - CLI framework
- `rich` - Terminal formatting

## Commands

### `ingest` - Load an SBOM

```bash
sbom-cli ingest bom.json
sbom-cli ingest bom.json --db /custom/path.db
sbom-cli ingest bom.json --json      # Machine-readable output
sbom-cli ingest bom.json --quiet     # Suppress output
```

### `query` - Search Components

```bash
# By name
sbom-cli query --component lodash

# By version
sbom-cli query --component lodash --version 4.17.21

# By Package URL
sbom-cli query --purl "pkg:npm/lodash@4.17.21"

# By license
sbom-cli query --license MIT
sbom-cli query --license Apache-2.0

# By vulnerability
sbom-cli query --vulnerability CVE-2021-44228

# JSON output for scripting
sbom-cli query --component lodash --json
```

### `list` - View Ingested Documents

```bash
sbom-cli list
sbom-cli list --verbose    # Include service and vulnerability counts
sbom-cli list --json
```

### `stats` - Database Statistics

```bash
sbom-cli stats
sbom-cli stats --json
```

### `version` - Show Version

```bash
sbom-cli version
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SBOM_DB_PATH` | Custom database location | `sbom.db` |

```bash
export SBOM_DB_PATH=/path/to/database.db
sbom-cli ingest bom.json
```

## Exit Codes

- `0` - Success
- `1` - Runtime error (file not found, database error)
- `2` - Invalid arguments

## Supported Formats

### CycloneDX 1.7

Full support for components, services, vulnerabilities, dependencies, and metadata.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "components": [
    {
      "type": "library",
      "group": "org.apache.commons",
      "name": "commons-lang3",
      "version": "3.12.0",
      "licenses": [{"license": {"id": "Apache-2.0"}}],
      "purl": "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "ratings": [{"score": 10.0, "severity": "critical"}]
    }
  ]
}
```

### SPDX 2.3/3.0

```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "name": "package-name",
      "versionInfo": "1.0.0",
      "licenseConcluded": "MIT"
    }
  ]
}
```

## Database Schema

Data is stored in SQLite with the following tables:

- `documents` - SBOM metadata
- `components` - Package information
- `services` - Service definitions
- `vulnerabilities` - CVE and vulnerability data
- `dependencies` - Dependency relationships
- `licenses` - Normalized license info
- `component_licenses` - Component-license mappings
- `external_references` - External references
- `compositions` - Completeness declarations
- `annotations` - Annotations and comments

## Examples

### Basic Workflow

```bash
sbom-cli ingest sample-bom.json
sbom-cli query --component commons-lang3
sbom-cli query --license Apache-2.0
sbom-cli query --vulnerability CVE-2021-44228
```

### Scripting with JSON

```bash
# Extract component names
sbom-cli query --component "" --json 2>/dev/null | jq '.results[].name'

# Count by license
sbom-cli query --license MIT --json | jq '.count'
```

### Multiple BOMs

```bash
sbom-cli ingest bom-1.json
sbom-cli ingest bom-2.json
sbom-cli ingest bom-3.json

sbom-cli list --verbose
sbom-cli stats
```

## Development

```bash
pip install pytest
pytest tests/
```

### Project Structure

```
sbom-cli/
├── pyproject.toml
├── README.md
├── sbom_cli/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   └── core.py
└── tests/
    └── test_cli.py
```

## License

MIT

## Contributing

Issues and pull requests welcome.
