"""Core business logic for SBOM ingestion and querying with CycloneDX 1.7 support."""

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone


class SBOMDatabase:
    """SQLite-based database for storing and querying SBOMs with CycloneDX 1.7 support."""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize the database connection.

        Args:
            db_path: Path to SQLite database file. If None, uses in-memory database.
        """
        self.db_path = db_path or ":memory:"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        """Initialize database schema for CycloneDX 1.7."""
        cursor = self.conn.cursor()

        # Documents table (stores SBOM metadata)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_file TEXT NOT NULL,
                sbom_type TEXT NOT NULL,
                sbom_version TEXT,
                bom_format TEXT,
                serial_number TEXT,
                version INTEGER,
                document_name TEXT,
                document_namespace TEXT,
                metadata_timestamp TEXT,
                ingested_at TEXT NOT NULL
            )
        """)

        # Components table (stores component/package information)
        # Note: "group" is escaped with double quotes as it's a SQL reserved keyword
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS components (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                bom_ref TEXT,
                type TEXT,
                mime_type TEXT,
                "group" TEXT,
                name TEXT NOT NULL,
                version TEXT,
                version_range TEXT,
                description TEXT,
                scope TEXT,
                supplier_name TEXT,
                supplier_url TEXT,
                manufacturer_name TEXT,
                manufacturer_url TEXT,
                publisher TEXT,
                author TEXT,
                cpe TEXT,
                purl TEXT,
                omnibor_id TEXT,
                swhid TEXT,
                swid_tag_id TEXT,
                copyright TEXT,
                external_references TEXT,
                hashes TEXT,
                licenses_concluded TEXT,
                licenses_declared TEXT,
                pedigree TEXT,
                evidence TEXT,
                release_notes TEXT,
                model_card TEXT,
                crypto_properties TEXT,
                properties TEXT,
                tags TEXT,
                is_external INTEGER DEFAULT 0,
                modified INTEGER DEFAULT 0,
                FOREIGN KEY (document_id) REFERENCES documents(id)
            )
        """)

        # Services table (CycloneDX 1.7 services)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                bom_ref TEXT,
                "group" TEXT,
                name TEXT NOT NULL,
                version TEXT,
                description TEXT,
                provider_name TEXT,
                provider_url TEXT,
                endpoints TEXT,
                authenticated INTEGER DEFAULT 0,
                x_trust_boundary INTEGER DEFAULT 0,
                trust_zone TEXT,
                data TEXT,
                licenses TEXT,
                external_references TEXT,
                properties TEXT,
                tags TEXT,
                FOREIGN KEY (document_id) REFERENCES documents(id)
            )
        """)

        # Vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                bom_ref TEXT,
                vuln_id TEXT NOT NULL,
                source_name TEXT,
                source_url TEXT,
                description TEXT,
                detail TEXT,
                recommendation TEXT,
                workaround TEXT,
                created TEXT,
                published TEXT,
                updated TEXT,
                rejected TEXT,
                ratings TEXT,
                cwes TEXT,
                advisories TEXT,
                analysis TEXT,
                affects TEXT,
                properties TEXT,
                FOREIGN KEY (document_id) REFERENCES documents(id)
            )
        """)

        # Dependencies table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dependencies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                ref_bom_ref TEXT NOT NULL,
                depends_on TEXT,
                provides TEXT,
                FOREIGN KEY (document_id) REFERENCES documents(id)
            )
        """)

        # Licenses table (normalized license information)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bom_ref TEXT,
                name TEXT,
                spdx_id TEXT,
                license_text TEXT,
                license_url TEXT,
                licensing_info TEXT,
                acknowledgement TEXT,
                properties TEXT
            )
        """)

        # Component-Licenses junction table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS component_licenses (
                component_id INTEGER NOT NULL,
                license_id INTEGER NOT NULL,
                license_type TEXT,
                PRIMARY KEY (component_id, license_id),
                FOREIGN KEY (component_id) REFERENCES components(id),
                FOREIGN KEY (license_id) REFERENCES licenses(id)
            )
        """)

        # External references table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS external_references (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                component_id INTEGER,
                service_id INTEGER,
                document_id INTEGER,
                url TEXT NOT NULL,
                type TEXT NOT NULL,
                comment TEXT,
                hashes TEXT,
                properties TEXT,
                FOREIGN KEY (component_id) REFERENCES components(id),
                FOREIGN KEY (service_id) REFERENCES services(id),
                FOREIGN KEY (document_id) REFERENCES documents(id)
            )
        """)

        # Compositions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compositions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                bom_ref TEXT,
                aggregate TEXT NOT NULL,
                assemblies TEXT,
                dependencies_refs TEXT,
                vulnerabilities_refs TEXT,
                FOREIGN KEY (document_id) REFERENCES documents(id)
            )
        """)

        # Annotations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS annotations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                bom_ref TEXT,
                subjects TEXT,
                annotator TEXT,
                timestamp TEXT,
                text TEXT,
                FOREIGN KEY (document_id) REFERENCES documents(id)
            )
        """)

        # Create indexes for faster queries
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_components_name ON components(name)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_components_version ON components(version)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_components_doc_id ON components(document_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_components_purl ON components(purl)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_components_cpe ON components(cpe)"
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_services_name ON services(name)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_id ON vulnerabilities(vuln_id)"
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_licenses_name ON licenses(name)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_licenses_spdx_id ON licenses(spdx_id)"
        )

        self.conn.commit()

    def _convert_wildcard_to_sql(self, pattern: str) -> str:
        """Convert user wildcard pattern to SQL LIKE pattern.

        Args:
            pattern: User input pattern with '*' wildcards

        Returns:
            SQL pattern with '*' converted to '%'
        """
        # Convert * to % for SQL LIKE
        return pattern.replace("*", "%")

    def ingest_sbom(self, file_path: str) -> Dict[str, Any]:
        """Ingest an SBOM file into the database.

        Args:
            file_path: Path to the SBOM JSON file.

        Returns:
            Dictionary with ingestion results.

        Raises:
            ValueError: If SBOM format is not recognized.
            FileNotFoundError: If file does not exist.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"SBOM file not found: {file_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Detect SBOM format
        if "bomFormat" in data and data["bomFormat"] == "CycloneDX":
            sbom_type = "cyclonedx"
            doc_info = self._parse_cyclonedx(data)
        elif "spdxVersion" in data:
            sbom_type = "spdx"
            doc_info = self._parse_spdx(data)
        else:
            raise ValueError("Unrecognized SBOM format. Expected CycloneDX or SPDX.")

        # Store in database
        cursor = self.conn.cursor()

        # Insert document
        cursor.execute(
            """
            INSERT INTO documents (
                source_file, sbom_type, sbom_version, bom_format, serial_number, 
                version, document_name, document_namespace, metadata_timestamp, ingested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                str(path.absolute()),
                sbom_type,
                doc_info.get("version"),
                doc_info.get("bom_format"),
                doc_info.get("serial_number"),
                doc_info.get("version_number"),
                doc_info.get("name"),
                doc_info.get("namespace"),
                doc_info.get("timestamp"),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

        document_id = cursor.lastrowid
        components_ingested = 0
        services_ingested = 0
        vulnerabilities_ingested = 0

        # Insert components - note "group" is escaped with double quotes
        for comp in doc_info.get("components", []):
            cursor.execute(
                """
                INSERT INTO components (
                    document_id, bom_ref, type, mime_type, "group", name, version, 
                    version_range, description, scope, supplier_name, supplier_url,
                    manufacturer_name, manufacturer_url, publisher, author, cpe, purl,
                    omnibor_id, swhid, swid_tag_id, copyright, external_references,
                    hashes, licenses_concluded, licenses_declared, pedigree, evidence,
                    release_notes, model_card, crypto_properties, properties, tags,
                    is_external, modified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    document_id,
                    comp.get("bom_ref"),
                    comp.get("type"),
                    comp.get("mime_type"),
                    comp.get("group"),
                    comp.get("name"),
                    comp.get("version"),
                    comp.get("version_range"),
                    comp.get("description"),
                    comp.get("scope"),
                    comp.get("supplier_name"),
                    comp.get("supplier_url"),
                    comp.get("manufacturer_name"),
                    comp.get("manufacturer_url"),
                    comp.get("publisher"),
                    comp.get("author"),
                    comp.get("cpe"),
                    comp.get("purl"),
                    self._serialize_list(comp.get("omnibor_id")),
                    self._serialize_list(comp.get("swhid")),
                    comp.get("swid_tag_id"),
                    comp.get("copyright"),
                    self._serialize_list(comp.get("external_references")),
                    self._serialize_list(comp.get("hashes")),
                    comp.get("licenses_concluded"),
                    comp.get("licenses_declared"),
                    self._serialize_json(comp.get("pedigree")),
                    self._serialize_json(comp.get("evidence")),
                    self._serialize_json(comp.get("release_notes")),
                    self._serialize_json(comp.get("model_card")),
                    self._serialize_json(comp.get("crypto_properties")),
                    self._serialize_json(comp.get("properties")),
                    self._serialize_list(comp.get("tags")),
                    1 if comp.get("is_external", False) else 0,
                    1 if comp.get("modified", False) else 0,
                ),
            )

            component_id = cursor.lastrowid
            components_ingested += 1

            # Handle licenses
            self._insert_licenses(
                cursor, component_id, comp.get("licenses", []), "component"
            )

        # Insert services - note "group" is escaped with double quotes
        for svc in doc_info.get("services", []):
            cursor.execute(
                """
                INSERT INTO services (
                    document_id, bom_ref, "group", name, version, description,
                    provider_name, provider_url, endpoints, authenticated,
                    x_trust_boundary, trust_zone, data, licenses,
                    external_references, properties, tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    document_id,
                    svc.get("bom_ref"),
                    svc.get("group"),
                    svc.get("name"),
                    svc.get("version"),
                    svc.get("description"),
                    svc.get("provider_name"),
                    svc.get("provider_url"),
                    self._serialize_list(svc.get("endpoints")),
                    1 if svc.get("authenticated", False) else 0,
                    1 if svc.get("x_trust_boundary", False) else 0,
                    svc.get("trust_zone"),
                    self._serialize_json(svc.get("data")),
                    self._serialize_json(svc.get("licenses")),
                    self._serialize_list(svc.get("external_references")),
                    self._serialize_json(svc.get("properties")),
                    self._serialize_list(svc.get("tags")),
                ),
            )
            services_ingested += 1

        # Insert vulnerabilities
        for vuln in doc_info.get("vulnerabilities", []):
            cursor.execute(
                """
                INSERT INTO vulnerabilities (
                    document_id, bom_ref, vuln_id, source_name, source_url,
                    description, detail, recommendation, workaround, created,
                    published, updated, rejected, ratings, cwes, advisories,
                    analysis, affects, properties
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    document_id,
                    vuln.get("bom_ref"),
                    vuln.get("id"),
                    vuln.get("source_name"),
                    vuln.get("source_url"),
                    vuln.get("description"),
                    vuln.get("detail"),
                    vuln.get("recommendation"),
                    vuln.get("workaround"),
                    vuln.get("created"),
                    vuln.get("published"),
                    vuln.get("updated"),
                    vuln.get("rejected"),
                    self._serialize_json(vuln.get("ratings")),
                    self._serialize_list(vuln.get("cwes")),
                    self._serialize_json(vuln.get("advisories")),
                    self._serialize_json(vuln.get("analysis")),
                    self._serialize_json(vuln.get("affects")),
                    self._serialize_json(vuln.get("properties")),
                ),
            )
            vulnerabilities_ingested += 1

        # Insert dependencies
        for dep in doc_info.get("dependencies", []):
            cursor.execute(
                """
                INSERT INTO dependencies (document_id, ref_bom_ref, depends_on, provides)
                VALUES (?, ?, ?, ?)
            """,
                (
                    document_id,
                    dep.get("ref"),
                    self._serialize_list(dep.get("depends_on")),
                    self._serialize_list(dep.get("provides")),
                ),
            )

        # Insert compositions
        for compo in doc_info.get("compositions", []):
            cursor.execute(
                """
                INSERT INTO compositions (document_id, bom_ref, aggregate, assemblies, dependencies_refs, vulnerabilities_refs)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    document_id,
                    compo.get("bom_ref"),
                    compo.get("aggregate"),
                    self._serialize_list(compo.get("assemblies")),
                    self._serialize_list(compo.get("dependencies")),
                    self._serialize_list(compo.get("vulnerabilities")),
                ),
            )

        # Insert annotations
        for annot in doc_info.get("annotations", []):
            cursor.execute(
                """
                INSERT INTO annotations (document_id, bom_ref, subjects, annotator, timestamp, text)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    document_id,
                    annot.get("bom_ref"),
                    self._serialize_list(annot.get("subjects")),
                    self._serialize_json(annot.get("annotator")),
                    annot.get("timestamp"),
                    annot.get("text"),
                ),
            )

        self.conn.commit()

        # Use packages_ingested key for test compatibility (alias for components_ingested)
        packages_ingested = components_ingested

        return {
            "status": "success",
            "document_id": document_id,
            "sbom_type": sbom_type,
            "sbom_version": doc_info.get("version"),
            "components_ingested": components_ingested,
            "packages_ingested": packages_ingested,
            "services_ingested": services_ingested,
            "vulnerabilities_ingested": vulnerabilities_ingested,
            "source_file": str(path.absolute()),
        }

    def _serialize_list(self, value: Optional[Any]) -> Optional[str]:
        """Serialize a list to JSON string."""
        if value is None:
            return None
        if isinstance(value, list):
            return json.dumps(value) if value else None
        return str(value) if value else None

    def _serialize_json(self, value: Optional[Any]) -> Optional[str]:
        """Serialize any value to JSON string."""
        if value is None:
            return None
        return json.dumps(value) if not isinstance(value, str) else value

    def _parse_cyclonedx(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CycloneDX 1.7 format SBOM."""
        metadata = data.get("metadata", {})
        components = data.get("components", [])
        services = data.get("services", [])
        vulnerabilities = data.get("vulnerabilities", [])
        dependencies = data.get("dependencies", [])
        compositions = data.get("compositions", [])
        annotations = data.get("annotations", [])

        parsed_components = []
        for comp in components:
            # Parse supplier
            supplier = comp.get("supplier", {})
            supplier_name = supplier.get("name") if isinstance(supplier, dict) else None
            supplier_url = None
            if isinstance(supplier, dict) and supplier.get("url"):
                supplier_url = (
                    supplier["url"][0]
                    if isinstance(supplier["url"], list)
                    else supplier["url"]
                )

            # Parse manufacturer
            manufacturer = comp.get("manufacturer", {})
            manufacturer_name = (
                manufacturer.get("name") if isinstance(manufacturer, dict) else None
            )
            manufacturer_url = None
            if isinstance(manufacturer, dict) and manufacturer.get("url"):
                manufacturer_url = (
                    manufacturer["url"][0]
                    if isinstance(manufacturer["url"], list)
                    else manufacturer["url"]
                )

            # Parse licenses
            licenses = self._parse_licenses(comp.get("licenses", []))

            # Parse hashes
            hashes = []
            for h in comp.get("hashes", []):
                if isinstance(h, dict):
                    hashes.append(f"{h.get('alg', '')}:{h.get('content', '')}")

            # Parse external references
            ext_refs = []
            for ref in comp.get("externalReferences", []):
                if isinstance(ref, dict):
                    ext_refs.append(
                        {
                            "url": ref.get("url"),
                            "type": ref.get("type"),
                            "comment": ref.get("comment"),
                        }
                    )

            # Parse SWID
            swid = comp.get("swid", {})
            swid_tag_id = swid.get("tagId") if isinstance(swid, dict) else None

            parsed_components.append(
                {
                    "bom_ref": comp.get("bom-ref"),
                    "type": comp.get("type"),
                    "mime_type": comp.get("mime-type"),
                    "group": comp.get("group"),
                    "name": comp.get("name", "UNKNOWN"),
                    "version": comp.get("version"),
                    "version_range": comp.get("versionRange"),
                    "description": comp.get("description"),
                    "scope": comp.get("scope", "required"),
                    "supplier_name": supplier_name,
                    "supplier_url": supplier_url,
                    "manufacturer_name": manufacturer_name,
                    "manufacturer_url": manufacturer_url,
                    "publisher": comp.get("publisher"),
                    "author": comp.get("author"),
                    "cpe": comp.get("cpe"),
                    "purl": comp.get("purl"),
                    "omnibor_id": comp.get("omniborId"),
                    "swhid": comp.get("swhid"),
                    "swid_tag_id": swid_tag_id,
                    "copyright": comp.get("copyright"),
                    "external_references": ext_refs,
                    "hashes": hashes,
                    "licenses_concluded": licenses.get("concluded"),
                    "licenses_declared": licenses.get("declared"),
                    "licenses": licenses.get("list", []),
                    "pedigree": comp.get("pedigree"),
                    "evidence": comp.get("evidence"),
                    "release_notes": comp.get("releaseNotes"),
                    "model_card": comp.get("modelCard"),
                    "crypto_properties": comp.get("cryptoProperties"),
                    "properties": comp.get("properties"),
                    "tags": comp.get("tags"),
                    "is_external": comp.get("isExternal", False),
                    "modified": comp.get("modified", False),
                }
            )

        # Parse services
        parsed_services = []
        for svc in services:
            provider = svc.get("provider", {})
            provider_name = provider.get("name") if isinstance(provider, dict) else None
            provider_url = None
            if isinstance(provider, dict) and provider.get("url"):
                provider_url = (
                    provider["url"][0]
                    if isinstance(provider["url"], list)
                    else provider["url"]
                )

            parsed_services.append(
                {
                    "bom_ref": svc.get("bom-ref"),
                    "group": svc.get("group"),
                    "name": svc.get("name", "UNKNOWN"),
                    "version": svc.get("version"),
                    "description": svc.get("description"),
                    "provider_name": provider_name,
                    "provider_url": provider_url,
                    "endpoints": svc.get("endpoints"),
                    "authenticated": svc.get("authenticated", False),
                    "x_trust_boundary": svc.get("x-trust-boundary", False),
                    "trust_zone": svc.get("trustZone"),
                    "data": svc.get("data"),
                    "licenses": svc.get("licenses"),
                    "external_references": svc.get("externalReferences"),
                    "properties": svc.get("properties"),
                    "tags": svc.get("tags"),
                }
            )

        # Parse vulnerabilities
        parsed_vulnerabilities = []
        for vuln in vulnerabilities:
            source = vuln.get("source", {})
            parsed_vulnerabilities.append(
                {
                    "bom_ref": vuln.get("bom-ref"),
                    "id": vuln.get("id"),
                    "source_name": (
                        source.get("name") if isinstance(source, dict) else None
                    ),
                    "source_url": (
                        source.get("url") if isinstance(source, dict) else None
                    ),
                    "description": vuln.get("description"),
                    "detail": vuln.get("detail"),
                    "recommendation": vuln.get("recommendation"),
                    "workaround": vuln.get("workaround"),
                    "created": vuln.get("created"),
                    "published": vuln.get("published"),
                    "updated": vuln.get("updated"),
                    "rejected": vuln.get("rejected"),
                    "ratings": vuln.get("ratings"),
                    "cwes": vuln.get("cwes"),
                    "advisories": vuln.get("advisories"),
                    "analysis": vuln.get("analysis"),
                    "affects": vuln.get("affects"),
                    "properties": vuln.get("properties"),
                }
            )

        # Parse metadata
        metadata_component = metadata.get("component", {}) if metadata else {}

        return {
            "bom_format": data.get("bomFormat"),
            "version": data.get("specVersion"),
            "version_number": data.get("version"),
            "serial_number": data.get("serialNumber"),
            "name": metadata_component.get("name") if metadata_component else None,
            "namespace": (
                metadata_component.get("bom-ref") if metadata_component else None
            ),
            "timestamp": metadata.get("timestamp") if metadata else None,
            "components": parsed_components,
            "services": parsed_services,
            "vulnerabilities": parsed_vulnerabilities,
            "dependencies": dependencies,
            "compositions": compositions,
            "annotations": annotations,
        }

    def _parse_licenses(self, licenses_data: List[Any]) -> Dict[str, Any]:
        """Parse license information from CycloneDX format."""
        result = {"list": [], "concluded": None, "declared": None}

        if not licenses_data:
            return result

        for lic_entry in licenses_data:
            if not isinstance(lic_entry, dict):
                continue

            # Handle license expression
            if "expression" in lic_entry:
                result["concluded"] = lic_entry.get("expression")
                result["list"].append(lic_entry.get("expression"))
                continue

            # Handle license object
            if "license" in lic_entry:
                lic = lic_entry["license"]
                if isinstance(lic, dict):
                    license_name = lic.get("name") or lic.get("id", "UNKNOWN")
                    result["list"].append(license_name)

                    acknowledgement = lic.get("acknowledgement")
                    if acknowledgement == "concluded":
                        result["concluded"] = license_name
                    elif acknowledgement == "declared":
                        result["declared"] = license_name

        return result

    def _insert_licenses(
        self,
        cursor,
        component_id: int,
        licenses_data: List[Any],
        license_type: str = "component",
    ) -> None:
        """Insert license information for a component."""
        if not licenses_data:
            return

        for lic_entry in licenses_data:
            license_name = None
            spdx_id = None
            license_text = None
            license_url = None

            if isinstance(lic_entry, str):
                license_name = lic_entry
            elif isinstance(lic_entry, dict):
                if "expression" in lic_entry:
                    license_name = lic_entry.get("expression")
                elif "license" in lic_entry:
                    lic = lic_entry["license"]
                    if isinstance(lic, dict):
                        license_name = lic.get("name")
                        spdx_id = lic.get("id")
                        license_text = (
                            lic.get("text", {}).get("content")
                            if isinstance(lic.get("text"), dict)
                            else None
                        )
                        license_url = lic.get("url")

            if license_name:
                # Insert or get license
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO licenses (name, spdx_id, license_text, license_url)
                    VALUES (?, ?, ?, ?)
                """,
                    (license_name, spdx_id, license_text, license_url),
                )

                cursor.execute(
                    "SELECT id FROM licenses WHERE name = ?", (license_name,)
                )
                row = cursor.fetchone()
                if row:
                    license_id = row[0]

                    # Link component to license
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO component_licenses (component_id, license_id, license_type)
                        VALUES (?, ?, ?)
                    """,
                        (component_id, license_id, license_type),
                    )

    def _parse_spdx(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse SPDX format SBOM."""
        packages = []
        for pkg in data.get("packages", []):
            licenses = []
            license_concluded = pkg.get("licenseConcluded")
            license_declared = pkg.get("licenseDeclared")

            if license_concluded and license_concluded != "NOASSERTION":
                licenses.append(license_concluded)
            if license_declared and license_declared != "NOASSERTION":
                licenses.append(license_declared)

            packages.append(
                {
                    "bom_ref": pkg.get("SPDXID"),
                    "name": pkg.get("name", "UNKNOWN"),
                    "version": pkg.get("versionInfo"),
                    "supplier": pkg.get("supplier"),
                    "license_concluded": (
                        license_concluded
                        if license_concluded != "NOASSERTION"
                        else None
                    ),
                    "license_declared": (
                        license_declared if license_declared != "NOASSERTION" else None
                    ),
                    "purl": None,
                    "licenses": licenses,
                }
            )

        return {
            "version": data.get("spdxVersion"),
            "name": data.get("name"),
            "namespace": data.get("documentNamespace"),
            "components": packages,
            "services": [],
            "vulnerabilities": [],
            "dependencies": [],
            "compositions": [],
            "annotations": [],
        }

    def query_by_component(
        self, name: str, version: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Query components by name and optionally version with wildcard support.

        Args:
            name: Component name to search for. Supports '*' wildcard.
            version: Optional version filter. Supports '*' wildcard.

        Returns:
            List of matching components.
        """
        cursor = self.conn.cursor()

        # Convert wildcards to SQL LIKE patterns
        name_pattern = self._convert_wildcard_to_sql(name)

        if version:
            version_pattern = self._convert_wildcard_to_sql(version)
            cursor.execute(
                """
                SELECT * FROM components
                WHERE name LIKE ? AND version LIKE ?
            """,
                (name_pattern, version_pattern),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM components
                WHERE name LIKE ?
            """,
                (name_pattern,),
            )

        results = []
        for row in cursor.fetchall():
            # Get licenses for this component
            cursor.execute(
                """
                SELECT l.name, l.spdx_id FROM licenses l
                JOIN component_licenses cl ON l.id = cl.license_id
                WHERE cl.component_id = ?
            """,
                (row["id"],),
            )
            licenses = [
                {"name": r["name"], "spdx_id": r["spdx_id"]} for r in cursor.fetchall()
            ]

            # Get document info
            cursor.execute(
                "SELECT source_file, sbom_type, document_name FROM documents WHERE id = ?",
                (row["document_id"],),
            )
            doc = cursor.fetchone()

            results.append(
                {
                    "component_id": row["id"],
                    "bom_ref": row["bom_ref"],
                    "name": row["name"],
                    "version": row["version"],
                    "type": row["type"],
                    "group": row["group"],
                    "purl": row["purl"],
                    "cpe": row["cpe"],
                    "supplier": row["supplier_name"],
                    "manufacturer": row["manufacturer_name"],
                    "licenses": licenses,
                    "document": {
                        "id": row["document_id"],
                        "source_file": doc["source_file"] if doc else None,
                        "sbom_type": doc["sbom_type"] if doc else None,
                        "document_name": doc["document_name"] if doc else None,
                    },
                }
            )

        return results

    def query_by_license(self, license_name: str) -> List[Dict[str, Any]]:
        """Query components by license with wildcard support.

        Args:
            license_name: License name to search for. Supports '*' wildcard.

        Returns:
            List of components with matching licenses.
        """
        cursor = self.conn.cursor()

        # Convert wildcards to SQL LIKE patterns
        license_pattern = self._convert_wildcard_to_sql(license_name)

        cursor.execute(
            """
            SELECT c.* FROM components c
            JOIN component_licenses cl ON c.id = cl.component_id
            JOIN licenses l ON cl.license_id = l.id
            WHERE l.name LIKE ? OR l.spdx_id LIKE ?
        """,
            (license_pattern, license_pattern),
        )

        results = []
        for row in cursor.fetchall():
            # Get all licenses for this component
            cursor.execute(
                """
                SELECT l.name, l.spdx_id FROM licenses l
                JOIN component_licenses cl ON l.id = cl.license_id
                WHERE cl.component_id = ?
            """,
                (row["id"],),
            )
            licenses = [
                {"name": r["name"], "spdx_id": r["spdx_id"]} for r in cursor.fetchall()
            ]

            # Get document info
            cursor.execute(
                "SELECT source_file, sbom_type, document_name FROM documents WHERE id = ?",
                (row["document_id"],),
            )
            doc = cursor.fetchone()

            results.append(
                {
                    "component_id": row["id"],
                    "bom_ref": row["bom_ref"],
                    "name": row["name"],
                    "version": row["version"],
                    "type": row["type"],
                    "purl": row["purl"],
                    "licenses": licenses,
                    "document": {
                        "id": row["document_id"],
                        "source_file": doc["source_file"] if doc else None,
                        "sbom_type": doc["sbom_type"] if doc else None,
                    },
                }
            )

        return results

    def query_by_vulnerability(self, vuln_id: str) -> List[Dict[str, Any]]:
        """Query vulnerabilities by ID with wildcard support.

        Args:
            vuln_id: Vulnerability ID to search for. Supports '*' wildcard.

        Returns:
            List of matching vulnerabilities.
        """
        cursor = self.conn.cursor()

        # Convert wildcards to SQL LIKE patterns
        vuln_pattern = self._convert_wildcard_to_sql(vuln_id)

        cursor.execute(
            """
            SELECT * FROM vulnerabilities
            WHERE vuln_id LIKE ?
        """,
            (vuln_pattern,),
        )

        results = []
        for row in cursor.fetchall():
            results.append(
                {
                    "vulnerability_id": row["id"],
                    "bom_ref": row["bom_ref"],
                    "vuln_id": row["vuln_id"],
                    "source": row["source_name"],
                    "description": row["description"],
                    "severity": self._parse_severity(row["ratings"]),
                    "cwes": self._deserialize_list(row["cwes"]),
                    "published": row["published"],
                    "updated": row["updated"],
                }
            )

        return results

    def _query_by_purl(self, purl: str) -> List[Dict[str, Any]]:
        """Query components by purl with wildcard support.

        Args:
            purl: Package URL to search for. Supports '*' wildcard.

        Returns:
            List of matching components.
        """
        cursor = self.conn.cursor()

        # Convert wildcards to SQL LIKE patterns
        purl_pattern = self._convert_wildcard_to_sql(purl)

        cursor.execute(
            """
            SELECT * FROM components
            WHERE purl LIKE ?
        """,
            (purl_pattern,),
        )

        results = []
        for row in cursor.fetchall():
            # Get licenses for this component
            cursor.execute(
                """
                SELECT l.name, l.spdx_id FROM licenses l
                JOIN component_licenses cl ON l.id = cl.license_id
                WHERE cl.component_id = ?
            """,
                (row["id"],),
            )
            licenses = [
                {"name": r["name"], "spdx_id": r["spdx_id"]} for r in cursor.fetchall()
            ]

            # Get document info
            cursor.execute(
                "SELECT source_file, sbom_type, document_name FROM documents WHERE id = ?",
                (row["document_id"],),
            )
            doc = cursor.fetchone()

            results.append(
                {
                    "component_id": row["id"],
                    "bom_ref": row["bom_ref"],
                    "name": row["name"],
                    "version": row["version"],
                    "type": row["type"],
                    "group": row["group"],
                    "purl": row["purl"],
                    "cpe": row["cpe"],
                    "supplier": row["supplier_name"],
                    "manufacturer": row["manufacturer_name"],
                    "licenses": licenses,
                    "document": {
                        "id": row["document_id"],
                        "source_file": doc["source_file"] if doc else None,
                        "sbom_type": doc["sbom_type"] if doc else None,
                        "document_name": doc["document_name"] if doc else None,
                    },
                }
            )

        return results

    def _parse_severity(self, ratings_json: Optional[str]) -> Optional[str]:
        """Parse severity from ratings JSON."""
        if not ratings_json:
            return None
        try:
            ratings = json.loads(ratings_json)
            if ratings and isinstance(ratings, list):
                return (
                    ratings[0].get("severity") if isinstance(ratings[0], dict) else None
                )
        except (json.JSONDecodeError, IndexError):
            pass
        return None

    def _deserialize_list(self, data: Optional[str]) -> Optional[List]:
        """Deserialize JSON string to list."""
        if not data:
            return None
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return None

    def get_all_documents(self) -> List[Dict[str, Any]]:
        """Get all ingested documents."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM documents")

        results = []
        for row in cursor.fetchall():
            # Count components, services, vulnerabilities
            cursor.execute(
                "SELECT COUNT(*) FROM components WHERE document_id = ?", (row["id"],)
            )
            component_count = cursor.fetchone()[0]

            cursor.execute(
                "SELECT COUNT(*) FROM services WHERE document_id = ?", (row["id"],)
            )
            service_count = cursor.fetchone()[0]

            cursor.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE document_id = ?",
                (row["id"],),
            )
            vuln_count = cursor.fetchone()[0]

            results.append(
                {
                    "id": row["id"],
                    "source_file": row["source_file"],
                    "sbom_type": row["sbom_type"],
                    "sbom_version": row["sbom_version"],
                    "bom_format": row["bom_format"],
                    "serial_number": row["serial_number"],
                    "document_name": row["document_name"],
                    "component_count": component_count,
                    "service_count": service_count,
                    "vulnerability_count": vuln_count,
                    "ingested_at": row["ingested_at"],
                }
            )

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics."""
        cursor = self.conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM documents")
        doc_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM components")
        component_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM services")
        service_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        vuln_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT name) FROM licenses")
        license_count = cursor.fetchone()[0]

        return {
            "documents": doc_count,
            "components": component_count,
            "services": service_count,
            "vulnerabilities": vuln_count,
            "licenses": license_count,
        }

    def close(self) -> None:
        """Close database connection."""
        self.conn.close()
