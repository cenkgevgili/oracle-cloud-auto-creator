import os
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

os.environ["ENABLE_TASK_CLEANUP_THREAD"] = "false"
os.environ["SESSION_SECRET"] = "test-secret"

import app as app_module


def valid_payload(**overrides):
    payload = {
        "user_ocid": "ocid1.user.oc1..example",
        "tenancy_ocid": "ocid1.tenancy.oc1..example",
        "compartment_ocid": "ocid1.compartment.oc1..example",
        "subnet_ocid": "ocid1.subnet.oc1..example",
        "availability_domain": "Uocm:US-ASHBURN-AD-1",
        "image_ocid": "ocid1.image.oc1..example",
        "ssh_public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDc example@test",
        "fingerprint": "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00",
        "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
        "shape": "VM.Standard.E2.1.Micro",
        "max_attempts": 3,
        "retry_interval": 5,
    }
    payload.update(overrides)
    return payload


class AppApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()
        with app_module.active_tasks_lock:
            app_module.active_tasks.clear()

    def test_start_task_requires_json(self):
        response = self.client.post("/api/start_task", data="hello", headers={"Content-Type": "text/plain"})
        self.assertEqual(response.status_code, 415)
        self.assertFalse(response.get_json()["success"])

    def test_test_connection_requires_json(self):
        response = self.client.post("/api/test_connection", data="hello", headers={"Content-Type": "text/plain"})
        self.assertEqual(response.status_code, 415)
        self.assertFalse(response.get_json()["success"])

    def test_start_task_requires_required_fields(self):
        payload = valid_payload()
        del payload["private_key"]

        response = self.client.post("/api/start_task", json=payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn("private_key", response.get_json()["error"])

    def test_get_regions_includes_jeddah(self):
        response = self.client.get("/api/get_regions")
        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        regions = data["regions"]
        self.assertTrue(any(region["id"] == "me-jeddah-1" for region in regions))

    def test_start_task_rejects_invalid_a1_ratio(self):
        payload = valid_payload(
            shape="VM.Standard.A1.Flex",
            shape_config={"ocpus": 2, "memory_in_gbs": 8},
        )

        response = self.client.post("/api/start_task", json=payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn("ocpus * 6", response.get_json()["error"])

    @patch("app.oci.core.VirtualNetworkClient")
    @patch("app.oci.core.ComputeClient")
    def test_start_task_returns_400_when_oci_init_fails(self, compute_client_mock, _network_client_mock):
        compute_client_mock.side_effect = Exception("bad credentials")
        response = self.client.post("/api/start_task", json=valid_payload())

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["success"])
        with app_module.active_tasks_lock:
            self.assertEqual(len(app_module.active_tasks), 0)

    def test_test_connection_rejects_invalid_ssh_key_format(self):
        payload = valid_payload(ssh_public_key="not-a-valid-ssh-key")
        response = self.client.post("/api/test_connection", json=payload)

        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertFalse(data["success"])
        self.assertIn("ssh_public_key", data["invalid_fields"])

    @patch("app.oci.core.ComputeClient")
    @patch("app.oci.core.VirtualNetworkClient")
    @patch("app.oci.identity.IdentityClient")
    def test_test_connection_success(
        self,
        identity_client_mock,
        virtual_network_client_mock,
        compute_client_mock,
    ):
        identity_client = MagicMock()
        identity_client.list_availability_domains.return_value = MagicMock(
            data=[SimpleNamespace(name="Uocm:US-ASHBURN-AD-1")]
        )
        identity_client_mock.return_value = identity_client

        virtual_network_client = MagicMock()
        virtual_network_client.get_subnet.return_value = MagicMock(
            data=SimpleNamespace(compartment_id="ocid1.compartment.oc1..example")
        )
        virtual_network_client_mock.return_value = virtual_network_client

        compute_client = MagicMock()
        compute_client.get_image.return_value = MagicMock(
            data=SimpleNamespace(lifecycle_state="AVAILABLE")
        )
        compute_client_mock.return_value = compute_client

        response = self.client.post("/api/test_connection", json=valid_payload())
        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(data["success"])
        self.assertTrue(data["connected"])
        self.assertEqual(data["invalid_fields"], [])


class CreatorRuntimeTests(unittest.TestCase):
    def setUp(self):
        with app_module.active_tasks_lock:
            app_module.active_tasks.clear()

    @patch("app.oci.core.VirtualNetworkClient")
    @patch("app.oci.core.ComputeClient")
    def test_creator_stop_interrupts_retry_loop(self, compute_client_mock, network_client_mock):
        compute_client_mock.return_value = MagicMock()
        network_client_mock.return_value = MagicMock()

        creator = app_module.OCIInstanceCreator(
            valid_payload(max_attempts=20, retry_interval=2),
            task_id="stoptest",
        )

        with patch.object(creator, "check_existing_instances", return_value=[]), patch.object(
            creator,
            "create_instance",
            side_effect=lambda attempt: (time.sleep(0.2), False)[1],
        ):
            worker = threading.Thread(target=creator.run, daemon=True)
            worker.start()
            time.sleep(0.05)
            creator.stop("test stop")
            worker.join(timeout=5)

        snapshot = creator.snapshot()
        self.assertEqual(snapshot["status"], "stopped")
        self.assertLess(snapshot["attempts"], 20)


if __name__ == "__main__":
    unittest.main()
