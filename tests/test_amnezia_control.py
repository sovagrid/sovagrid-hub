# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import base64
import json
import shlex
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from sovagrid_hub.amnezia_actions import build_amnezia_command, control_status, is_amnezia_command
from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store


PUBLIC = base64.urlsafe_b64encode(b"\x04" + b"\x00" * 64).rstrip(b"=").decode()
CONFIG_SHA = "a" * 64
PROPOSED_SHA = "b" * 64
CONFIRMATION = base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode()
PLAN = {"action": "settings-plan", "target": "awg2", "expected_config_sha256": CONFIG_SHA,
        "expected_generation": 7, "parameters": {"S2": "15", "H1": "10-20"}}
INTENT = {**PLAN, "action": "settings-intent",
          "expected_proposed_config_sha256": PROPOSED_SHA}
APPLY = {**INTENT, "action": "settings-apply", "confirmation_id": CONFIRMATION}


class AmneziaActionTests(unittest.TestCase):
    def test_exact_schema_and_canonical_broker_command(self):
        cases = (
            ({"action": "status", "target": "awg2"},
             "/usr/local/bin/sovagrid-amnezia-ctl status awg2"),
            ({"action": "settings-preview", "target": "awg2"},
             "/usr/local/bin/sovagrid-amnezia-ctl settings-preview awg2"),
            (PLAN, shlex.join(["/usr/local/bin/sovagrid-amnezia-ctl", "settings-plan", "awg2",
                               CONFIG_SHA, "7", '{"H1":"10-20","S2":"15"}'])),
            (INTENT, shlex.join(["/usr/local/bin/sovagrid-amnezia-ctl", "settings-intent", "awg2",
                                 CONFIG_SHA, "7", PROPOSED_SHA, '{"H1":"10-20","S2":"15"}'])),
            (APPLY, shlex.join(["/usr/local/bin/sovagrid-amnezia-ctl", "settings-apply", "awg2",
                                CONFIG_SHA, "7", PROPOSED_SHA, '{"H1":"10-20","S2":"15"}',
                                CONFIRMATION])),
            ({"action": "add-profile", "target": "awg2", "client": "phone_1",
              "address": "10.22.0.9", "endpoint_host": "VPN.Example.COM",
              "public_key": PUBLIC, "route": "full"},
             f"/usr/local/bin/sovagrid-amnezia-ctl add-profile awg2 phone_1 10.22.0.9 vpn.example.com {PUBLIC} --route full"),
            ({"action": "add-profile", "target": "awg2", "client": "phone_1",
              "address": "auto", "endpoint_host": "vpn.example.com",
              "public_key": PUBLIC, "route": "split"},
             f"/usr/local/bin/sovagrid-amnezia-ctl add-profile awg2 phone_1 auto vpn.example.com {PUBLIC} --route split"),
            ({"action": "sealed-export", "target": "awg2", "client": "phone_1",
              "public_key": PUBLIC},
             f"/usr/local/bin/sovagrid-amnezia-ctl sealed-export awg2 phone_1 {PUBLIC}"),
            ({"action": "revoke", "target": "awg2", "client": "phone_1"},
             "/usr/local/bin/sovagrid-amnezia-ctl revoke awg2 phone_1"),
            ({"action": "status", "target": "wireguard"},
             "/usr/local/bin/sovagrid-amnezia-ctl status wireguard"),
            ({"action": "settings-preview", "target": "wireguard"},
             "/usr/local/bin/sovagrid-amnezia-ctl settings-preview wireguard"),
            ({"action": "add-profile", "target": "wireguard", "client": "phone_1",
              "address": "10.22.0.9", "endpoint_host": "vpn.example.com",
              "public_key": PUBLIC, "route": "split"},
             f"/usr/local/bin/sovagrid-amnezia-ctl add-profile wireguard phone_1 10.22.0.9 vpn.example.com {PUBLIC} --route split"),
            ({"action": "sealed-export", "target": "wireguard", "client": "phone_1",
              "public_key": PUBLIC},
             f"/usr/local/bin/sovagrid-amnezia-ctl sealed-export wireguard phone_1 {PUBLIC}"),
            ({"action": "revoke", "target": "wireguard", "client": "phone_1"},
             "/usr/local/bin/sovagrid-amnezia-ctl revoke wireguard phone_1"),
        )
        for body, expected in cases:
            with self.subTest(body=body):
                self.assertEqual(build_amnezia_command(body), expected)
                self.assertTrue(is_amnezia_command(expected))
        for body in (
            {"action": "enroll", "target": "awg2"},
            {"action": "status", "target": "xray"},
            {"action": "status", "target": "awg2", "command": "id"},
            {"action": "settings-preview", "target": "awg2", "command": "cat /etc/shadow"},
            INTENT | {"expected_proposed_config_sha256": CONFIG_SHA},
            APPLY | {"confirmation_id": "bad"},
            APPLY | {"parameters": {"PrivateKey": "secret"}},
            {"action": "revoke", "target": "awg2", "client": "../etc"},
            {"action": "sealed-export", "target": "awg2", "client": "phone_1", "public_key": "bad"},
            {"action": "add-profile", "target": "awg2", "client": "phone_1",
             "address": "10.22.0.09", "endpoint_host": "vpn.example.com",
             "public_key": PUBLIC, "route": "full"},
            {"action": "add-profile", "target": "awg2", "client": "phone_1",
             "address": "AUTO", "endpoint_host": "vpn.example.com",
             "public_key": PUBLIC, "route": "full"},
        ):
            with self.subTest(body=body), self.assertRaises(ValueError):
                build_amnezia_command(body)
        self.assertFalse(is_amnezia_command("/usr/local/bin/sovagrid-amnezia-ctl status awg2; id"))
        self.assertFalse(is_amnezia_command("/usr/local/bin/sovagrid-amnezia-ctl status xray"))
        self.assertFalse(is_amnezia_command("/usr/local/bin/sovagrid-amnezia-ctl settings-preview awg2 --private"))

    def test_settings_plan_rejects_noncanonical_and_shell_values(self):
        bad_patches = ({}, {"Jc": 2}, {"Jc": "02"}, {"Jc": "65536"},
                       {"H1": "20-10"}, {"H1": "4294967296-4294967296"},
                       {"Jc": "1; id"}, {"Jmin": "12", "Jmax": "3"},
                       {"HeaderProtectionKey": "secret"})
        for patch in bad_patches:
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                build_amnezia_command(PLAN | {"parameters": patch})
        for changed in ({"target": "wireguard"}, {"expected_config_sha256": CONFIG_SHA.upper()},
                        {"expected_generation": True}, {"expected_generation": -1},
                        {"expected_generation": 1_000_000_001}, {"command": "; id"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                build_amnezia_command(PLAN | changed)
        base = ["/usr/local/bin/sovagrid-amnezia-ctl", "settings-plan", "awg2",
                CONFIG_SHA, "7", '{"H1":"10-20","S2":"15"}']
        for changed in (
            base[:4] + ["07", base[5]],
            base[:5] + ['{"S2":"15","H1":"10-20"}'],
            base[:5] + ['{"Jc":"1","Jc":"2"}'],
            base[:5] + ['{"Jc":"1; id"}'],
        ):
            with self.subTest(argv=changed):
                self.assertFalse(is_amnezia_command(shlex.join(changed)))
        self.assertFalse(is_amnezia_command(build_amnezia_command(PLAN) + " ; id"))
        self.assertFalse(is_amnezia_command(build_amnezia_command(APPLY) + " ; id"))
        self.assertFalse(is_amnezia_command(shlex.join(
            ["/usr/local/bin/sovagrid-amnezia-ctl", "settings-apply", "awg2",
             CONFIG_SHA, "07", PROPOSED_SHA, '{"H1":"10-20","S2":"15"}', CONFIRMATION])))

    def test_status_projection_rejects_extra_fields_and_stale_result(self):
        now = int(time.time())
        value = {"target": "awg2", "enrolled": True, "recovery_required": False,
                 "owned_clients": ["phone_1"]}
        job = {"state": "succeeded", "exit_code": 0, "completed_at": now,
               "output": json.dumps(value)}
        self.assertEqual(control_status(job, now)["source_status"], "ok")
        self.assertEqual(control_status(job, now + 91)["source_status"], "unavailable")
        self.assertEqual(control_status(job | {"output": json.dumps(value | {"secret": "x"})}, now)
                         ["source_status"], "unavailable")
        self.assertEqual(control_status(job | {"output": '{"target":"awg2","target":"awg2"}'}, now)
                         ["source_status"], "unavailable")
        self.assertEqual(control_status(job, now, "wireguard")["source_status"], "unavailable")


class AmneziaHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", "long-test-password")
        self.server = make_server(HubApp(self.store), 0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, body=None, token=None, request_key=None):
        headers = {}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        if token:
            headers["Authorization"] = "Bearer " + token
        if request_key:
            headers["Idempotency-Key"] = request_key
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_settings_preview_and_plan_are_admin_only_and_require_ready_target(self):
        admin = self.request("POST", "/api/v1/session",
                             {"username": "admin", "password": "long-test-password"})[1]["token"]
        self.store.create_user("viewer", "another-long-test-password", "viewer")
        self.store.create_user("operator", "another-long-test-password", "operator")
        viewer = self.request("POST", "/api/v1/session",
                              {"username": "viewer", "password": "another-long-test-password"})[1]["token"]
        operator = self.request("POST", "/api/v1/session",
                                {"username": "operator", "password": "another-long-test-password"})[1]["token"]
        created = self.request("POST", "/api/v1/servers", {"name": "vpn-host"}, admin)[1]
        sid, agent = created["id"], created["agent_token"]
        path = f"/api/v1/servers/{sid}/amnezia/actions"
        preview = {"action": "settings-preview", "target": "awg2"}
        key = "847e404f-a9fd-4a85-8e14-8199e59dfc38"
        for token in (viewer, operator):
            self.assertEqual(self.request("POST", path, preview, token, key)[0], 403)
            self.assertEqual(self.request("POST", path, PLAN, token, key)[0], 403)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/commands",
                                      {"enabled": True}, admin)[0], 200)
        self.assertEqual(self.request("POST", path, preview, admin, key)[0], 503)
        self.assertEqual(self.request("POST", path, PLAN, admin, key)[0], 503)
        probe = self.request("POST", path, {"action": "status", "target": "awg2"}, admin,
                             "778fd629-b84d-426f-b34b-21d8bac251c3")
        self.assertEqual(probe[0], 201)
        leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        self.assertEqual(leased["command"], "/usr/local/bin/sovagrid-amnezia-ctl status awg2")
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/jobs/{leased['id']}/result",
                                      {"state": "succeeded", "exit_code": 0,
                                       "output": json.dumps({"target": "awg2", "enrolled": True,
                                                             "recovery_required": False,
                                                             "owned_clients": []})}, agent)[0], 200)
        queued = self.request("POST", path, preview, admin, key)
        self.assertEqual(queued[0], 201)
        self.assertEqual(self.request("POST", path, preview, admin, key), (200, queued[1]))
        leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        self.assertEqual(leased["command"], build_amnezia_command(preview))
        self.assertEqual(leased["timeout_seconds"], 135)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/jobs/{leased['id']}/result",
                                      {"state": "failed", "exit_code": 2,
                                       "output": "settings unavailable"}, agent)[0], 200)
        plan_key = "9c09f238-3eb8-4c16-ac2f-5f461fb9ebc3"
        planned = self.request("POST", path, PLAN, admin, plan_key)
        self.assertEqual(planned[0], 201)
        self.assertEqual(self.request("POST", path, PLAN, admin, plan_key), (200, planned[1]))
        self.assertEqual(self.request("POST", path, PLAN | {"expected_generation": 8},
                                      admin, plan_key)[0], 409)
        leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        self.assertEqual(leased["command"], build_amnezia_command(PLAN))
        self.assertEqual(leased["timeout_seconds"], 135)

    def test_duplicate_settings_plan_fields_are_rejected_before_queue(self):
        admin = self.request("POST", "/api/v1/session",
                             {"username": "admin", "password": "long-test-password"})[1]["token"]
        sid = self.request("POST", "/api/v1/servers", {"name": "vpn-host"}, admin)[1]["id"]
        path = f"/api/v1/servers/{sid}/amnezia/actions"
        for raw in (
            '{"action":"settings-plan","action":"status","target":"awg2"}',
            '{"action":"settings-plan","target":"awg2","expected_config_sha256":"' +
            CONFIG_SHA + '","expected_generation":7,"parameters":{"Jc":"1","Jc":"2"}}',
        ):
            request = urllib.request.Request(self.base + path, data=raw.encode(),
                headers={"Content-Type": "application/json", "Authorization": "Bearer " + admin,
                         "Idempotency-Key": "04983c24-1d44-45e3-8c23-bf596b853e06"}, method="POST")
            with self.subTest(raw=raw), self.assertRaises(urllib.error.HTTPError) as captured:
                urllib.request.urlopen(request)
            self.assertEqual(captured.exception.code, 400)
            captured.exception.close()

    def test_settings_intent_and_apply_require_admin_ready_target_and_exact_pins(self):
        admin = self.request("POST", "/api/v1/session",
                             {"username": "admin", "password": "long-test-password"})[1]["token"]
        self.store.create_user("viewer", "another-long-test-password", "viewer")
        viewer = self.request("POST", "/api/v1/session",
                              {"username": "viewer", "password": "another-long-test-password"})[1]["token"]
        created = self.request("POST", "/api/v1/servers", {"name": "awg-host"}, admin)[1]
        sid, agent = created["id"], created["agent_token"]
        path = f"/api/v1/servers/{sid}/amnezia/actions"
        for action in (INTENT, APPLY):
            self.assertEqual(self.request("POST", path, action, viewer,
                                          "4719ed70-67a6-4c91-9b6b-c8023bdeff20")[0], 403)
            self.assertEqual(self.request("POST", path, action, admin,
                                          "4719ed70-67a6-4c91-9b6b-c8023bdeff20")[0], 403)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/commands",
                                      {"enabled": True}, admin)[0], 200)
        for action in (INTENT, APPLY):
            self.assertEqual(self.request("POST", path, action, admin,
                                          "4719ed70-67a6-4c91-9b6b-c8023bdeff20")[0], 503)
        status = {"action": "status", "target": "awg2"}
        self.assertEqual(self.request("POST", path, status, admin,
                                      "2365ff85-e409-44e0-9bfd-528d8f92e8bc")[0], 201)
        leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/jobs/{leased['id']}/result",
                                      {"state": "succeeded", "exit_code": 0,
                                       "output": json.dumps({"target": "awg2", "enrolled": True,
                                                             "recovery_required": False,
                                                             "owned_clients": []})}, agent)[0], 200)
        for action, key in ((INTENT, "efb74748-75fa-4b45-8450-26b53ea42a55"),
                            (APPLY, "37ced1e4-67b8-4ea6-a202-4c3d497fb383")):
            queued = self.request("POST", path, action, admin, key)
            self.assertEqual(queued[0], 201)
            self.assertEqual(self.request("POST", path, action, admin, key), (200, queued[1]))
            leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
            self.assertEqual(leased["command"], build_amnezia_command(action))
            self.assertEqual(leased["timeout_seconds"], 135)
            self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/jobs/{leased['id']}/result",
                                          {"state": "failed", "exit_code": 2,
                                           "output": "Amnezia control failed"}, agent)[0], 200)
        audit = self.request("GET", "/api/v1/audit", token=admin)
        self.assertEqual(audit[0], 200)
        self.assertNotIn(CONFIRMATION, json.dumps(audit[1]))

    def test_settings_intent_confirmation_is_only_in_admin_job_detail(self):
        admin = self.request("POST", "/api/v1/session",
                             {"username": "admin", "password": "long-test-password"})[1]["token"]
        self.store.create_user("viewer", "another-long-test-password", "viewer")
        viewer = self.request("POST", "/api/v1/session",
                              {"username": "viewer", "password": "another-long-test-password"})[1]["token"]
        created = self.request("POST", "/api/v1/servers", {"name": "awg-host"}, admin)[1]
        sid, agent = created["id"], created["agent_token"]
        actions = f"/api/v1/servers/{sid}/amnezia/actions"
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/commands",
                                      {"enabled": True}, admin)[0], 200)
        self.assertEqual(self.request("POST", actions, {"action": "status", "target": "awg2"},
                                      admin, "af98aa32-a030-4e3b-b2dd-f76f0a41de13")[0], 201)
        status_job = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        status_output = json.dumps({"target": "awg2", "enrolled": True,
                                    "recovery_required": False, "owned_clients": []})
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/jobs/{status_job['id']}/result",
                                      {"state": "succeeded", "exit_code": 0,
                                       "output": status_output}, agent)[0], 200)

        queued = self.request("POST", actions, INTENT, admin,
                              "49e6a204-bdd9-49f3-8171-0d972258d3ab")
        self.assertEqual(queued[0], 201)
        intent_job = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        self.assertEqual(intent_job["id"], queued[1]["job"]["id"])
        intent_output = json.dumps({"target": "awg2", "action": "settings_intent",
                                    "confirmation_id": CONFIRMATION,
                                    "expires_at": int(time.time()) + 300,
                                    "generation": 7, "config_sha256": CONFIG_SHA,
                                    "proposed_config_sha256": PROPOSED_SHA,
                                    "changed_fields": ["H1", "S2"],
                                    "configured_clients": 0})
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/jobs/{intent_job['id']}/result",
                                      {"state": "succeeded", "exit_code": 0,
                                       "output": intent_output}, agent)[0], 200)

        # A list refresh must not expose the one-use handle, even to an admin.
        listed = self.request("GET", "/api/v1/jobs", token=admin)[1]["jobs"]
        by_id = {job["id"]: job for job in listed}
        self.assertEqual(by_id[intent_job["id"]]["output"], "")
        self.assertEqual(by_id[status_job["id"]]["output"], status_output)
        self.assertNotIn(CONFIRMATION, json.dumps(listed))
        self.assertNotIn("control_kind", by_id[intent_job["id"]])
        detail = self.request("GET", f"/api/v1/jobs/{intent_job['id']}", token=admin)[1]["job"]
        self.assertEqual(detail["output"], intent_output)
        self.assertEqual(json.loads(detail["output"])["confirmation_id"], CONFIRMATION)
        self.assertEqual(self.request("GET", "/api/v1/jobs", token=viewer)[0], 403)
        self.assertEqual(self.request("GET", f"/api/v1/jobs/{intent_job['id']}",
                                      token=viewer)[0], 403)

        # Legacy or compromised output also fails closed, including an escaped JSON key.
        generic = self.request("POST", f"/api/v1/servers/{sid}/jobs",
                               {"command": "printf harmless"}, admin)[1]["job"]
        leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        self.assertEqual(leased["id"], generic["id"])
        escaped_output = r'{"\u0063onfirmation_id":"' + CONFIRMATION + '"}'
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/jobs/{leased['id']}/result",
                                      {"state": "succeeded", "exit_code": 0,
                                       "output": escaped_output}, agent)[0], 200)
        listed = self.request("GET", "/api/v1/jobs", token=admin)[1]["jobs"]
        self.assertEqual(next(job for job in listed if job["id"] == generic["id"])["output"], "")
        self.assertNotIn(CONFIRMATION, json.dumps(listed))
        self.assertEqual(self.request("GET", f"/api/v1/jobs/{generic['id']}",
                                      token=admin)[1]["job"]["output"], escaped_output)

    def test_dormant_gate_probe_enrolment_and_replay(self):
        admin = self.request("POST", "/api/v1/session",
                             {"username": "admin", "password": "long-test-password"})[1]["token"]
        created = self.request("POST", "/api/v1/servers", {"name": "vpn-host"}, admin)[1]
        sid, agent = created["id"], created["agent_token"]
        control_path = f"/api/v1/servers/{sid}/amnezia/control"
        actions_path = f"/api/v1/servers/{sid}/amnezia/actions"
        status = {"action": "status", "target": "awg2"}
        revoke = {"action": "revoke", "target": "awg2", "client": "phone"}
        key = "69acef8a-9f9c-4411-acb6-b88f3f8b6acf"

        self.assertEqual(self.request("GET", control_path)[0], 401)
        self.assertEqual(self.request("GET", control_path, token=agent)[0], 401)
        self.assertEqual(self.request("GET", control_path, token=admin)[1]
                         ["control"]["source_status"], "unavailable")
        self.assertEqual(self.request("POST", actions_path, status, admin, key)[0], 403)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/commands",
                                      {"enabled": True}, admin)[0], 200)
        self.assertEqual(self.request("POST", actions_path, revoke, admin, key)[0], 503)
        self.assertEqual(self.request("POST", actions_path, status, admin)[0], 400)
        first = self.request("POST", actions_path, status, admin, key)
        self.assertEqual(first[0], 201)
        self.assertEqual(self.request("POST", actions_path, status, admin, key), (200, first[1]))
        leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        self.assertEqual(leased["command"], build_amnezia_command(status))
        self.assertEqual(leased["timeout_seconds"], 135)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/jobs/{leased['id']}/result",
                                      {"state": "failed", "exit_code": 2,
                                       "output": "Amnezia control failed"}, agent)[0], 200)
        self.assertEqual(self.request("GET", control_path, token=admin)[1]
                         ["control"]["source_status"], "unavailable")
        self.assertEqual(self.request("POST", actions_path, revoke, admin,
                                      "451efcae-b14d-461e-bb0e-2cf1859e9c2f")[0], 503)

        probe_key = "d5be03d4-7fc5-4c75-972a-af2492253c3d"
        probe = self.request("POST", actions_path, status, admin, probe_key)
        self.assertEqual(probe[0], 201)
        leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        self.assertEqual(leased["id"], probe[1]["job"]["id"])
        success = {"target": "awg2", "enrolled": True, "recovery_required": False,
                   "owned_clients": ["phone"]}
        self.request("POST", f"/api/v1/servers/{sid}/jobs/{leased['id']}/result",
                     {"state": "succeeded", "exit_code": 0, "output": json.dumps(success)}, agent)
        self.assertEqual(self.request("GET", control_path, token=admin)[1]["control"]
                         ["owned_clients"], ["phone"])
        mutation_key = "b4131dc2-e8c4-4da9-968f-52ed72ee6391"
        mutation = self.request("POST", actions_path, revoke, admin, mutation_key)
        self.assertEqual(mutation[0], 201)
        self.assertEqual(self.request("POST", actions_path, revoke, admin, mutation_key),
                         (200, mutation[1]))
        self.assertEqual(self.request("POST", actions_path,
                                      {"action": "revoke", "target": "awg2", "client": "other"},
                                      admin, mutation_key)[0], 409)
        self.assertEqual(self.request("GET", f"/api/v1/servers/no-such/amnezia/control",
                                      token=admin)[0], 404)

    def test_wireguard_probe_and_mutation_are_target_bound(self):
        admin = self.request("POST", "/api/v1/session",
                             {"username": "admin", "password": "long-test-password"})[1]["token"]
        created = self.request("POST", "/api/v1/servers", {"name": "wg-host"}, admin)[1]
        sid, agent = created["id"], created["agent_token"]
        control_path = f"/api/v1/servers/{sid}/amnezia/control"
        actions_path = f"/api/v1/servers/{sid}/amnezia/actions"
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        self.assertEqual(self.request("GET", control_path + "?target=wireguard", token=admin)[1]
                         ["control"]["target"], "wireguard")
        self.assertEqual(self.request("GET", control_path + "?target=xray", token=admin)[0], 400)
        self.assertEqual(self.request("GET", control_path + "?target=awg2&target=wireguard",
                                      token=admin)[0], 400)
        mutation = {"action": "revoke", "target": "wireguard", "client": "phone"}
        self.assertEqual(self.request("POST", actions_path, mutation, admin,
                                      "ae0ef4b5-ff91-4ccb-b3db-9f57350e4d14")[0], 503)
        probe = {"action": "status", "target": "wireguard"}
        self.assertEqual(self.request("POST", actions_path, probe, admin,
                                      "ef14104b-9ce2-4811-9a4a-a9472fe6358a")[0], 201)
        leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        self.assertEqual(leased["command"], build_amnezia_command(probe))
        wrong = {"target": "awg2", "enrolled": True, "recovery_required": False,
                 "owned_clients": []}
        self.request("POST", f"/api/v1/servers/{sid}/jobs/{leased['id']}/result",
                     {"state": "succeeded", "exit_code": 0, "output": json.dumps(wrong)}, agent)
        self.assertEqual(self.request("GET", control_path + "?target=wireguard", token=admin)[1]
                         ["control"]["source_status"], "unavailable")
        self.assertEqual(self.request("POST", actions_path, mutation, admin,
                                      "8401977d-f8e4-4458-b651-186df2dd4921")[0], 503)
        self.assertEqual(self.request("POST", actions_path, probe, admin,
                                      "e760de0e-69fa-4f9a-bab6-1373aa325f50")[0], 201)
        leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        valid = {"target": "wireguard", "enrolled": True, "recovery_required": False,
                 "owned_clients": []}
        self.request("POST", f"/api/v1/servers/{sid}/jobs/{leased['id']}/result",
                     {"state": "succeeded", "exit_code": 0, "output": json.dumps(valid)}, agent)
        self.assertEqual(self.request("GET", control_path + "?target=wireguard", token=admin)[1]
                         ["control"]["source_status"], "ok")
        self.assertEqual(self.request("GET", control_path, token=admin)[1]
                         ["control"]["source_status"], "unavailable")
        self.assertEqual(self.request("POST", actions_path, mutation, admin,
                                      "01ef9e2c-cbec-4820-8f2e-c594b6831847")[0], 201)


if __name__ == "__main__":
    unittest.main()
