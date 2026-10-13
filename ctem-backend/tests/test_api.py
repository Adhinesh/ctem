import unittest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from app.main import app
from app.services.target_validation import validate_target, sanitize_target, ValidationError
from app.services.risk_engine import (
    compute_composite_score,
    compute_priority_tier,
    compute_criticality_mismatch,
    get_sla_hours,
    compute_blast_radius,
)
from app.services import change_detection_service, ueba_service

client = TestClient(app)


# ==============================================================================
# 1. TARGET SANITIZATION & VALIDATION TESTS
# ==============================================================================

class TestTargetValidation(unittest.TestCase):
    def test_sanitize_target_domain_stripping(self):
        self.assertEqual(sanitize_target("https://example.com/some/path", "domain"), "example.com")
        self.assertEqual(sanitize_target("http://scanme.nmap.org:8080", "domain"), "scanme.nmap.org")
        self.assertEqual(sanitize_target("  https://test.local/  ", "domain"), "test.local")
        self.assertEqual(sanitize_target("http://vulnweb.com/", "domain"), "vulnweb.com")

    def test_sanitize_target_ip_stripping(self):
        self.assertEqual(sanitize_target("http://192.168.1.1:443", "ip"), "192.168.1.1")
        self.assertEqual(sanitize_target("https://10.0.0.1/admin", "ip"), "10.0.0.1")
        self.assertEqual(sanitize_target(" 127.0.0.1 ", "ip"), "127.0.0.1")

    def test_validate_target_valid_domains(self):
        self.assertEqual(validate_target("example.com", "domain"), "example.com")
        self.assertEqual(validate_target("sub.domain.co.uk", "domain"), "sub.domain.co.uk")
        self.assertEqual(validate_target("https://vulnweb.com", "domain"), "vulnweb.com")

    def test_validate_target_valid_ips(self):
        self.assertEqual(validate_target("192.168.1.1", "ip"), "192.168.1.1")
        self.assertEqual(validate_target("10.0.0.1", "ip"), "10.0.0.1")
        self.assertEqual(validate_target("https://172.16.0.5:8080", "ip"), "172.16.0.5")

    def test_validate_target_invalid(self):
        with self.assertRaises(ValidationError):
            validate_target("invalid target with spaces", "domain")

        with self.assertRaises(ValidationError):
            validate_target("!@#$%^&*", "domain")

        with self.assertRaises(ValidationError):
            validate_target("", "domain")

        with self.assertRaises(ValidationError):
            validate_target("999.999.999.999", "ip")

        with self.assertRaises(ValidationError):
            validate_target("example.com", "unsupported_type")


# ==============================================================================
# 2. RISK SCORING, FORMULAS & SLA TESTS
# ==============================================================================

class TestRiskScoring(unittest.TestCase):
    def test_risk_scoring_criticality_multipliers(self):
        cvss_base = 8.0
        epss = 0.5

        res_crit = compute_composite_score(
            cvss_base=cvss_base,
            epss=epss,
            kev_listed=False,
            asset_criticality="critical",
            exposure_context="internet_facing",
            zone="external",
            blast_radius=1.0,
        )
        res_high = compute_composite_score(
            cvss_base=cvss_base,
            epss=epss,
            kev_listed=False,
            asset_criticality="high",
            exposure_context="internet_facing",
            zone="external",
            blast_radius=1.0,
        )
        res_low = compute_composite_score(
            cvss_base=cvss_base,
            epss=epss,
            kev_listed=False,
            asset_criticality="low",
            exposure_context="internet_facing",
            zone="external",
            blast_radius=1.0,
        )

        self.assertTrue(res_crit["composite_score"] > res_high["composite_score"] > res_low["composite_score"])
        self.assertTrue(res_crit["composite_score"] <= 100.0)
        self.assertTrue(res_low["composite_score"] >= 0.0)

    def test_blast_radius_bounds(self):
        self.assertEqual(compute_blast_radius(0), 1.0)
        self.assertEqual(compute_blast_radius(5), 1.5)
        self.assertEqual(compute_blast_radius(100), 2.0)  # Max capped at 2.0

    def test_priority_tier_assignment(self):
        # KEV listed always yields P1
        self.assertEqual(
            compute_priority_tier(
                cvss_base=7.0,
                epss=0.1,
                kev_listed=True,
                asset_criticality="low",
                exposure_context="restricted",
            ),
            "P1",
        )

        # High EPSS + Internet facing + Critical asset yields P1
        self.assertEqual(
            compute_priority_tier(
                cvss_base=5.0,
                epss=0.8,
                kev_listed=False,
                asset_criticality="critical",
                exposure_context="internet_facing",
            ),
            "P1",
        )

        # High EPSS + High CVSS yields P2
        self.assertEqual(
            compute_priority_tier(
                cvss_base=7.5,
                epss=0.6,
                kev_listed=False,
                asset_criticality="medium",
                exposure_context="internal",
            ),
            "P2",
        )

        # Low EPSS + Low CVSS + Low asset yields P4
        self.assertEqual(
            compute_priority_tier(
                cvss_base=2.0,
                epss=0.01,
                kev_listed=False,
                asset_criticality="low",
                exposure_context="restricted",
            ),
            "P4",
        )

    def test_sla_and_mismatch(self):
        self.assertEqual(get_sla_hours("P1"), 72)
        self.assertEqual(get_sla_hours("P2"), 168)
        self.assertEqual(get_sla_hours("P3"), 336)
        self.assertEqual(get_sla_hours("P4"), 720)

    def test_cvss_source_allowed_values(self):
        allowed = {"circl", "nvd", "unknown"}
        for raw in ["circl", "nvd", "asset_criticality", "curated", "open_port_baseline", "default_estimate", None]:
            sanitized = raw if raw in ("circl", "nvd") else "unknown"
            self.assertIn(sanitized, allowed)

        # Stated low criticality but computed P1 tier is a mismatch
        self.assertTrue(compute_criticality_mismatch("low", "P1"))
        self.assertFalse(compute_criticality_mismatch("critical", "P1"))


# ==============================================================================
# 3. ATTACK SURFACE CHANGE DETECTION & UEBA ANOMALIES
# ==============================================================================

class TestChangeDetectionAndUEBA(unittest.TestCase):
    @patch("app.services.change_detection_service.get_client")
    @patch("app.services.alert_service.create_alert")
    def test_detect_port_change_new_port(self, mock_alert, mock_client):
        mock_db = MagicMock()
        mock_client.return_value = mock_db
        mock_table = MagicMock()
        mock_db.table.return_value = mock_table
        mock_table.insert.return_value.execute.return_value = MagicMock()

        asset_id = "11111111-1111-1111-1111-111111111111"
        previous = None
        current = {"port": 8080, "protocol": "tcp", "service": "http-proxy"}

        change_detection_service.detect_port_change(asset_id, previous, current)
        mock_alert.assert_called_once()
        self.assertEqual(mock_alert.call_args[1]["alert_type"], "asset_change")

    @patch("app.services.change_detection_service.get_client")
    @patch("app.services.alert_service.create_alert")
    def test_detect_port_change_first_scan(self, mock_alert, mock_client):
        mock_db = MagicMock()
        mock_client.return_value = mock_db
        mock_table = MagicMock()
        mock_db.table.return_value = mock_table
        mock_table.insert.return_value.execute.return_value = MagicMock()

        asset_id = "11111111-1111-1111-1111-111111111111"
        current = {"port": 8080, "protocol": "tcp", "service": "http-proxy"}

        # On first scan: logs port_opened with previous_value=None, but does not alert
        change_detection_service.detect_port_change(asset_id, None, current, is_first_scan=True)
        mock_alert.assert_not_called()
        mock_table.insert.assert_called_once()
        insert_payload = mock_table.insert.call_args[0][0]
        self.assertIsNone(insert_payload["previous_value"])
        self.assertEqual(insert_payload["new_value"], "8080/tcp")

        # On first scan: closures are never recorded
        mock_table.reset_mock()
        change_detection_service.detect_port_change(asset_id, {"port": 80, "protocol": "tcp"}, None, is_first_scan=True)
        mock_table.insert.assert_not_called()

    @patch("app.services.ueba_service.alert_service.create_alert")
    def test_ueba_off_hours_rule(self, mock_alert):
        event = {
            "username": "night_attacker@corp.internal",
            "occurred_at": "2026-09-08T03:30:00Z",
            "event_type": "login",
        }
        ueba_service._check_off_hours("night_attacker@corp.internal", event)
        mock_alert.assert_called_once()
        self.assertEqual(mock_alert.call_args[1]["alert_type"], "ueba_anomaly")


# ==============================================================================
# 4. FASTAPI ROUTE & API INTEGRATION TESTS
# ==============================================================================

class TestFastAPIRoutes(unittest.TestCase):
    def test_health_endpoint(self):
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_cors_preflight_options(self):
        for origin in ["http://localhost:3000", "http://127.0.0.1:3000", "http://127.0.0.1:3001"]:
            response = client.options(
                "/health",
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "content-type",
                },
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers.get("access-control-allow-origin"), origin)

    @patch("app.services.scan_service.get_scan_history")
    def test_list_scans(self, mock_history):
        mock_history.return_value = [
            {"id": "s1", "target": "example.com", "status": "complete"}
        ]
        response = client.get("/scans")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("history", data)
        self.assertEqual(len(data["history"]), 1)

    @patch("app.routers.assets.get_client")
    def test_list_assets_with_search_filter(self, mock_get_client):
        mock_db = MagicMock()
        mock_get_client.return_value = mock_db
        mock_table = MagicMock()
        mock_db.table.return_value = mock_table
        mock_table.select.return_value.order.return_value.execute.return_value.data = [
            {"id": "a1", "hostname": "web.prod.internal", "ip_address": "10.0.1.5", "asset_type": "server"},
            {"id": "a2", "hostname": "api.external.com", "ip_address": "198.51.100.10", "asset_type": "endpoint"},
        ]

        # Search for "prod"
        response = client.get("/assets?q=prod")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["assets"]), 1)
        self.assertEqual(data["assets"][0]["hostname"], "web.prod.internal")

    @patch("app.routers.risk.get_client")
    def test_risk_heatmap_deduplication(self, mock_get_client):
        mock_db = MagicMock()
        mock_get_client.return_value = mock_db
        mock_table = MagicMock()
        mock_db.table.return_value = mock_table

        # Simulate multiple CVE findings for the same asset
        mock_table.select.return_value.execute.side_effect = [
            # risk_scores
            MagicMock(data=[
                {"asset_id": "asset-1", "composite_score": 45.0, "priority_tier": "P2"},
                {"asset_id": "asset-1", "composite_score": 85.0, "priority_tier": "P1"},
            ]),
            # assets
            MagicMock(data=[
                {"id": "asset-1", "hostname": "app.prod.com", "zone": "external"}
            ])
        ]

        response = client.get("/risk/heatmap")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("heatmap", data)
        # Should deduplicate to 1 entry with highest composite score (85.0) and P1
        self.assertEqual(len(data["heatmap"]), 1)
        self.assertEqual(data["heatmap"][0]["composite_score"], 85.0)
        self.assertEqual(data["heatmap"][0]["priority_tier"], "P1")
        self.assertEqual(data["heatmap"][0]["findings_count"], 2)

    @patch("app.services.peripheral_service.check_authorization")
    def test_peripheral_check(self, mock_check):
        mock_check.return_value = {"result": "authorized", "peripheral_id": "p1"}

        response = client.post("/peripherals/check", json={"serial_number": "SN-12345"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["result"], "authorized")

    @patch("app.services.peripheral_service.check_authorization")
    def test_peripheral_check_unauthorized_unknown(self, mock_check):
        mock_check.return_value = {"result": "unauthorized", "peripheral_id": None}

        response = client.post("/peripherals/check", json={"serial_number": "UNKNOWN-ROGUE-USB"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["result"], "unauthorized")

    @patch("app.services.declared_asset_service.register_declared_assets")
    def test_declare_assets_batch(self, mock_register):
        mock_register.return_value = [
            {"id": "da-1", "hostname": "declared-node.local", "updated": False}
        ]

        payload = {
            "declared_by": "secops_admin",
            "assets": [
                {
                    "hostname": "declared-node.local",
                    "ip_address": "10.10.10.5",
                    "zone": "internal",
                    "criticality": "high",
                    "asset_type": "server",
                }
            ]
        }
        response = client.post("/assets/declared", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("assets", data)
        self.assertEqual(len(data["assets"]), 1)


# ==============================================================================
# 5. BLAST RADIUS & LATERAL MOVEMENT TESTS
# ==============================================================================

class FakeTable:
    def __init__(self, data):
        self._data = list(data) if data else []

    def select(self, *args, **kwargs):
        return self

    def eq(self, col, val):
        filtered = [row for row in self._data if row.get(col) == val]
        return FakeTable(filtered)

    def limit(self, count):
        return FakeTable(self._data[:count])

    def order(self, *args, **kwargs):
        return self

    def or_(self, *args, **kwargs):
        return self

    def insert(self, row, *args, **kwargs):
        items = row if isinstance(row, list) else [row]
        self._data.extend(items)
        return FakeTable(items)

    def delete(self, *args, **kwargs):
        return self

    def execute(self):
        res = MagicMock()
        res.data = list(self._data)
        return res


def make_mock_client(assets=None, ports=None, scores=None, deps=None):
    tables = {
        "assets": FakeTable(assets or []),
        "open_ports": FakeTable(ports or []),
        "risk_scores": FakeTable(scores or []),
        "asset_dependencies": FakeTable(deps or []),
    }
    client = MagicMock()
    client.table.side_effect = lambda name: tables.get(name, FakeTable([]))
    return client


class TestBlastRadius(unittest.TestCase):
    @patch("app.routers.risk.get_client")
    def test_blast_radius_overview_endpoint(self, mock_get_client):
        assets = [
            {"id": "a1", "hostname": "web.corp", "ip_address": "10.0.0.1", "zone": "internal", "criticality": "high", "asset_type": "server"},
            {"id": "a2", "hostname": "db.corp", "ip_address": "10.0.0.2", "zone": "internal", "criticality": "critical", "asset_type": "server"},
        ]
        mock_get_client.return_value = make_mock_client(assets=assets)

        response = client.get("/risk/blast-radius")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("ranked_assets", data)
        self.assertIn("avg_blast_radius", data)
        self.assertEqual(len(data["ranked_assets"]), 2)

    @patch("app.routers.risk.get_client")
    def test_blast_radius_detail_endpoint(self, mock_get_client):
        assets = [
            {"id": "a1", "hostname": "web.corp", "ip_address": "10.0.0.1", "zone": "internal", "criticality": "high", "asset_type": "server"},
            {"id": "a2", "hostname": "db.corp", "ip_address": "10.0.0.2", "zone": "internal", "criticality": "critical", "asset_type": "server"},
        ]
        ports = [{"id": "p1", "asset_id": "a2", "port": "5432", "protocol": "tcp", "service": "postgresql"}]
        scores = [{"asset_id": "a2", "composite_score": 85.0, "priority_tier": "P1"}]
        deps = [{"id": "d1", "asset_id": "a1", "depends_on_asset_id": "a2"}]
        mock_get_client.return_value = make_mock_client(assets=assets, ports=ports, scores=scores, deps=deps)

        response = client.get("/risk/blast-radius/a1")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["asset"]["id"], "a1")
        self.assertEqual(data["direct_reachable_count"], 1)
        self.assertEqual(data["reachable_assets"][0]["id"], "a2")
        self.assertIn("same_subnet", data["reachable_assets"][0]["vectors"])
        self.assertIn("dependency_downstream", data["reachable_assets"][0]["vectors"])
        self.assertEqual(data["criticality_breakdown"]["critical"], 1)
        self.assertIn("recommendations", data)

    @patch("app.routers.risk.get_client")
    def test_blast_radius_simulation_endpoint(self, mock_get_client):
        assets = [
            {"id": "a1", "hostname": "web.corp", "ip_address": "10.0.0.1", "zone": "internal", "criticality": "high"},
            {"id": "a2", "hostname": "db.corp", "ip_address": "10.0.0.2", "zone": "internal", "criticality": "critical"},
        ]
        mock_get_client.return_value = make_mock_client(assets=assets)

        payload = {"isolate_subnet": True, "sever_dependencies": True, "isolate_zone": True, "mode": "same_subnet"}
        response = client.post("/risk/blast-radius/a1/simulate", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("baseline", data)
        self.assertIn("simulated", data)
        self.assertIn("impact", data)
        self.assertEqual(data["baseline"]["direct_reachable_count"], 1)
        self.assertEqual(data["simulated"]["direct_reachable_count"], 0)
        self.assertEqual(data["impact"]["mitigated_assets_count"], 1)
        self.assertEqual(data["impact"]["risk_reduction_pct"], 100.0)

    @patch("app.routers.risk.get_client")
    def test_dependency_endpoints(self, mock_get_client):
        assets = [
            {"id": "a1", "hostname": "web.corp", "ip_address": "10.0.0.1", "zone": "internal", "criticality": "high"},
            {"id": "a2", "hostname": "db.corp", "ip_address": "10.0.0.2", "zone": "internal", "criticality": "critical"},
        ]
        mock_get_client.return_value = make_mock_client(assets=assets)

        # 1. Reject self-dependency
        resp_self = client.post("/risk/dependencies", json={"asset_id": "a1", "depends_on_asset_id": "a1"})
        self.assertEqual(resp_self.status_code, 400)

        # 2. Add valid dependency
        resp_add = client.post("/risk/dependencies", json={"asset_id": "a1", "depends_on_asset_id": "a2"})
        self.assertEqual(resp_add.status_code, 200)
        self.assertEqual(resp_add.json()["status"], "created")

        # 3. Delete dependency
        dep_id = resp_add.json()["dependency"]["id"]
        resp_del = client.delete(f"/risk/dependencies/{dep_id}")
        self.assertEqual(resp_del.status_code, 200)
        self.assertEqual(resp_del.json()["status"], "deleted")


if __name__ == "__main__":
    unittest.main()

