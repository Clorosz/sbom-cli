"""Tests for SBOM CLI."""

import json
import os
import tempfile
import pytest

from sbom_cli.core import SBOMDatabase


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    # Ensure file exists before trying to delete
    if os.path.exists(db_path):
        try:
            os.unlink(db_path)
        except PermissionError:
            # File may still be in use, ignore on Windows
            pass


@pytest.fixture
def cyclonedx_sbom():
    """Sample CycloneDX SBOM for testing."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"name": "test-app", "bom-ref": "pkg:test-app"}},
        "components": [
            {
                "name": "lodash",
                "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21",
                "licenses": [{"license": {"name": "MIT"}}],
            },
            {
                "name": "express",
                "version": "4.18.2",
                "purl": "pkg:npm/express@4.18.2",
                "licenses": [{"license": {"name": "MIT"}}],
            },
            {
                "name": "axios",
                "version": "1.6.0",
                "purl": "pkg:npm/axios@1.6.0",
                "licenses": [{"license": {"name": "MIT"}}],
            },
        ],
    }


@pytest.fixture
def spdx_sbom():
    """Sample SPDX SBOM for testing."""
    return {
        "spdxVersion": "SPDX-2.3",
        "name": "test-project",
        "documentNamespace": "https://example.com/test",
        "packages": [
            {
                "name": "requests",
                "versionInfo": "2.31.0",
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "supplier": "Organization: PSF",
            },
            {
                "name": "flask",
                "versionInfo": "3.0.0",
                "licenseConcluded": "BSD-3-Clause",
                "licenseDeclared": "BSD-3-Clause",
                "supplier": "Organization: Pallets",
            },
        ],
    }


@pytest.fixture
def sbom_file(cyclonedx_sbom):
    """Create a temporary SBOM file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(cyclonedx_sbom, f)
        file_path = f.name
    yield file_path
    os.unlink(file_path)


class TestSBOMDatabase:
    """Tests for SBOMDatabase class."""

    def test_init_memory_db(self):
        """Test in-memory database initialization."""
        db = SBOMDatabase(":memory:")
        assert db.conn is not None
        db.close()

    def test_init_file_db(self, temp_db):
        """Test file-based database initialization."""
        db = SBOMDatabase(temp_db)
        assert db.conn is not None
        assert os.path.exists(temp_db)
        db.close()

    def test_ingest_cyclonedx(self, temp_db, sbom_file):
        """Test ingesting CycloneDX SBOM."""
        db = SBOMDatabase(temp_db)
        result = db.ingest_sbom(sbom_file)

        assert result["status"] == "success"
        assert result["sbom_type"] == "cyclonedx"
        assert result["packages_ingested"] == 3
        db.close()

    def test_ingest_spdx(self, temp_db, spdx_sbom):
        """Test ingesting SPDX SBOM."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(spdx_sbom, f)
            file_path = f.name

        try:
            db = SBOMDatabase(temp_db)
            result = db.ingest_sbom(file_path)

            assert result["status"] == "success"
            assert result["sbom_type"] == "spdx"
            assert result["packages_ingested"] == 2
            db.close()
        finally:
            os.unlink(file_path)

    def test_ingest_nonexistent_file(self, temp_db):
        """Test ingesting nonexistent file raises error."""
        db = SBOMDatabase(temp_db)
        with pytest.raises(FileNotFoundError):
            db.ingest_sbom("/nonexistent/path/file.json")
        db.close()

    def test_ingest_invalid_format(self, temp_db):
        """Test ingesting invalid SBOM format raises error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"invalid": "format"}, f)
            file_path = f.name

        try:
            db = SBOMDatabase(temp_db)
            with pytest.raises(ValueError):
                db.ingest_sbom(file_path)
            db.close()
        finally:
            os.unlink(file_path)

    def test_query_by_component(self, temp_db, sbom_file):
        """Test querying by component name."""
        db = SBOMDatabase(temp_db)
        db.ingest_sbom(sbom_file)

        results = db.query_by_component("lodash")
        assert len(results) == 1
        assert results[0]["name"] == "lodash"
        assert results[0]["version"] == "4.17.21"
        db.close()

    def test_query_by_component_with_version(self, temp_db, sbom_file):
        """Test querying by component name and version."""
        db = SBOMDatabase(temp_db)
        db.ingest_sbom(sbom_file)

        results = db.query_by_component("lodash", "4.17.21")
        assert len(results) == 1

        results_wrong_version = db.query_by_component("lodash", "1.0.0")
        assert len(results_wrong_version) == 0
        db.close()

    def test_query_by_license(self, temp_db, sbom_file):
        """Test querying by license."""
        db = SBOMDatabase(temp_db)
        db.ingest_sbom(sbom_file)

        results = db.query_by_license("MIT")
        assert len(results) == 3

        results_empty = db.query_by_license("GPL-3.0")
        assert len(results_empty) == 0
        db.close()

    def test_get_all_documents(self, temp_db, sbom_file, spdx_sbom):
        """Test listing all documents."""
        db = SBOMDatabase(temp_db)

        # Ingest two SBOMs
        db.ingest_sbom(sbom_file)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(spdx_sbom, f)
            spdx_file = f.name

        try:
            db.ingest_sbom(spdx_file)
        finally:
            os.unlink(spdx_file)

        documents = db.get_all_documents()
        assert len(documents) == 2
        db.close()


class TestCLI:
    """Tests for CLI functionality."""

    def test_cli_import(self):
        """Test that CLI module can be imported."""
        from sbom_cli.cli import app, main

        assert app is not None
        assert main is not None

    def test_cli_version_command(self):
        """Test version command."""
        from typer.testing import CliRunner
        from sbom_cli.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "sbom-cli version" in result.output
