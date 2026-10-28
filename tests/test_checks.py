# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Lease races, role isolation and bounded opt-in check persistence."""
import copy
import base64
import json
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from unittest import mock

from sovagrid_hub.auth import AuthenticationError, AuthorizationError
from sovagrid_hub.checks import CheckError, migrate_checks, validate_config, validate_definition
from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store

PASSWORD = "a-long-network-check-test-password"


def test_certificate(directory, name, *, is_ca=True, can_sign=True):
    """Generate public DER X.509 test input; private keys stay in temporary files."""
    key = directory / (name + ".key")
    pem = directory / (name + ".pem")
    der = directory / (name + ".der")
    command = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
               "-days", "1", "-subj", "/CN=" + name, "-keyout", str(key), "-out", str(pem),
               "-addext", "basicConstraints=critical,CA:" + ("TRUE" if is_ca else "FALSE"),
               "-addext", "keyUsage=critical," + ("keyCertSign,cRLSign" if can_sign else "digitalSignature")]
    subprocess.run(command, check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-in", str(pem), "-outform", "DER", "-out", str(der)],
                   check=True, capture_output=True)
    return base64.b64encode(der.read_bytes()).decode("ascii"), pem.read_text(), key.read_bytes()


def definition(kind="http", **changes):
    value = {"id": str(uuid.uuid4()), "name": "Service", "kind": kind, "enabled": True,
             "interval_seconds": 60, "timeout_seconds": 5}
    value.update({"url": "https://private.example/health"} if kind == "http" else
                 {"host": "127.0.0.1", "port": 22} if kind == "tcp" else
                 {"host": "private.example", "record_type": "A", "expected_ip": None})
    return dict(value, **changes)


def result(lease, now, **changes):
    value = {"lease_id": lease["id"], "config_revision": lease["config_revision"],
             "observed_at": now, "status": "up", "latency_ms": 12,
             "http_status": 200, "tls_expires_at": now + 86400, "error_code": None}
    if lease["check"]["kind"] in ("tcp", "dns"):
        value.update(http_status=None, tls_expires_at=None)
    elif lease["check"]["url"].startswith("http:"):
        value["tls_expires_at"] = None
    return dict(value, **changes)


class CheckStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.path)
        self.store.initialize("owner", PASSWORD)
        self.server = self.store.create_server("checks-host")
        self.sid, self.token = self.server["id"], self.server["agent_token"]
        self.now = int(time.time())

    def tearDown(self):
        self.temp.cleanup()

    def config(self, values, revision=0, **kwargs):
        return self.store.save_check_config(self.sid, {"revision": revision, "checks": values}, now=self.now, **kwargs)

    def claim(self, now=None):
        return self.store.claim_check(self.sid, self.token, {"protocol": 1}, now=self.now if now is None else now)["lease"]

    def test_empty_configuration_is_opt_in_and_old_agent_is_waiting(self):
        self.assertEqual(self.store.check_config(self.sid), {"server_id": self.sid, "revision": 0, "checks": []})
        self.assertEqual(self.store.checks_summary(self.sid)["worker_seen_at"], None)
        self.assertIsNone(self.claim())
        self.assertEqual(self.store.checks_summary(self.sid)["worker_seen_at"], self.now)
        self.config([definition()])
        self.assertEqual(self.store.checks_summary(self.sid)["checks"][0]["state"], "waiting")
        self.assertFalse(self.store.server_commands_enabled(self.sid))
        self.assertIsNotNone(self.claim())  # Independent from the command opt-in.

    def test_strict_configuration_limits_and_target_validation(self):
        for host in ("127.0.0.1", "10.0.0.3", "::1", "example.org.", "EXAMPLE.org"):
            validate_definition(definition("tcp", host=host))
        for item in (definition("dns"), definition("dns", record_type="AAAA", expected_ip="2001:db8::1"),
                     definition("dns", expected_ip="203.0.113.7")):
            self.assertEqual(validate_definition(item), item)
        for change in ({"host": "127.0.0.1"}, {"host": "bad host"}, {"record_type": "TXT"},
                       {"expected_ip": "2001:db8::1"}, {"expected_ip": "not-an-ip"},
                       {"expected_ip": "0.0.0.0"}, {"expected_ip": "224.0.0.1"}, {"port": 53}):
            with self.subTest(dns=change), self.assertRaises(ValueError):
                validate_definition(definition("dns", **change))
        for host in ("0.0.0.0", "::", "224.0.0.1", "ff02::1", "::ffff:224.0.0.1", "::ffff:0.0.0.0",
                     "127.1", "2130706433", "0177.0.0.1", "0x7f000001", "0x7f.0.0.1", "name..", "foo/bar", "::1%lo", "bad host"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                validate_definition(definition("tcp", host=host))
        for url in ("https://[::1]/health", "http://127.0.0.1:80/", "https://example.org./проверка"):
            validate_definition(definition(url=url))
        for url in ("file:///etc/passwd", "http://x/?secret=a", "http://x/#secret", "http://user:pass@x/", "http://x:/",
                    "http://[::1]trailing/", "http://[::1]trailing:22/", "http://x:0/", "http://x:65536/", "http://x/\r\nx:y",
                    "http://0x7f000001/", "http://x\\y/", "http://x/" + "x" * 1024, "http://x/\ud800"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_definition(definition(url=url))
        for changes in ({"enabled": 1}, {"interval_seconds": True}, {"interval_seconds": 59}, {"timeout_seconds": 11},
                        {"name": " spaced"}, {"name": "bad\x7f"}, {"name": "\ud800"}, {"id": str(uuid.uuid4()).upper()}, {"extra": "secret"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_definition(definition(**changes))
        repeated = definition()
        for payload in ({"revision": 0, "checks": [repeated, repeated]}, {"revision": False, "checks": []},
                        {"revision": 2**63, "checks": []}, {"revision": 0, "checks": [definition() for _ in range(17)]}):
            with self.assertRaises(ValueError):
                validate_config(payload)

    def test_custom_https_ca_is_strict_bounded_and_private_to_admin_and_agent(self):
        if shutil.which("openssl") is None:
            self.skipTest("OpenSSL test fixture unavailable")
        directory = Path(self.temp.name)
        ca, ca_pem, private_key = test_certificate(directory, "trusted-ca")
        second_ca, _, _ = test_certificate(directory, "replacement-ca")
        leaf, _, _ = test_certificate(directory, "server-leaf", is_ca=False)
        bad_usage, _, _ = test_certificate(directory, "bad-usage", can_sign=False)
        item = definition(ca_cert_der_b64=ca)
        self.assertEqual(validate_definition(item), item)
        for bad in (ca_pem, base64.b64encode(private_key).decode("ascii"), leaf,
                    bad_usage, base64.b64encode(b"a" * 1537).decode("ascii"), "AAAA", ca + "\n"):
            with self.subTest(kind=bad[:24]), self.assertRaises(ValueError):
                validate_definition(definition(ca_cert_der_b64=bad))
        for bad in (definition(url="http://example.org/", ca_cert_der_b64=ca),
                    definition("tcp", ca_cert_der_b64=ca),
                    definition("dns", ca_cert_der_b64=None)):
            with self.assertRaises(ValueError):
                validate_definition(bad)
        self.config([item])
        self.assertEqual(self.store.check_config(self.sid)["checks"][0]["ca_cert_der_b64"], ca)
        lease = self.claim()
        self.assertEqual(lease["check"]["ca_cert_der_b64"], ca)
        self.assertNotIn(ca, json.dumps(self.store.checks_summary(self.sid)))
        self.store.record_check_result(self.sid, item["id"], self.token, result(lease, self.now), now=self.now)
        legacy = dict(item, name="Legacy edit")
        legacy.pop("ca_cert_der_b64")
        self.config([legacy], revision=1)
        self.assertEqual(self.store.check_config(self.sid)["checks"][0]["ca_cert_der_b64"], ca)
        self.assertEqual(len(self.store.check_history(self.sid, item["id"])["results"]), 1)
        old_lease = self.claim(self.now + 60)
        self.config([dict(item, ca_cert_der_b64=None)], revision=2)
        self.assertEqual(self.store.check_history(self.sid, item["id"])["results"], [])
        with self.assertRaises(CheckError):
            self.store.record_check_result(self.sid, item["id"], self.token,
                result(old_lease, self.now + 60), now=self.now + 60)
        self.assertNotIn("ca_cert_der_b64", self.claim()["check"])
        self.config([dict(item, ca_cert_der_b64=second_ca)], revision=3)
        self.assertEqual(self.claim()["check"]["ca_cert_der_b64"], second_ca)

    def test_concurrent_cas_and_claim_are_serialized_across_store_objects(self):
        values = [definition("tcp") for _ in range(3)]
        barrier, outcomes = threading.Barrier(2), []
        def save():
            store = Store(self.path)
            barrier.wait(3)
            try:
                store.save_check_config(self.sid, {"revision": 0, "checks": values}, now=self.now)
                outcomes.append("saved")
            except CheckError as exc:
                outcomes.append(exc.status)
        workers = [threading.Thread(target=save) for _ in range(2)]
        for worker in workers: worker.start()
        for worker in workers:
            worker.join(5)
            self.assertFalse(worker.is_alive())
        self.assertCountEqual(outcomes, ["saved", 409])
        barrier, leases = threading.Barrier(3), []
        def claim():
            barrier.wait(3)
            leases.append(Store(self.path).claim_check(self.sid, self.token, {"protocol": 1}, now=self.now)["lease"])
        workers = [threading.Thread(target=claim) for _ in range(3)]
        for worker in workers: worker.start()
        for worker in workers:
            worker.join(5)
            self.assertFalse(worker.is_alive())
        nonempty = [item for item in leases if item is not None]
        self.assertEqual(len(nonempty), 2)
        self.assertEqual(len({item["check_id"] for item in nonempty}), 2)

    def test_scoped_lease_identity_expiry_rotation_and_protocol(self):
        item = definition("tcp")
        self.config([item])
        lease = self.claim()
        self.assertEqual(lease["expires_at"], self.now + 90)
        second = self.store.create_server("other-host")
        self.store.save_check_config(second["id"], {"revision": 0, "checks": [item]}, now=self.now)
        with self.assertRaises(CheckError):
            self.store.record_check_result(second["id"], item["id"], second["agent_token"], result(lease,self.now), now=self.now)
        with self.assertRaises(AuthenticationError):
            self.store.claim_check(self.sid, second["agent_token"], {"protocol": 1})
        for payload in ({"protocol": True}, {"protocol": 2}, {"protocol": 1, "extra": 0}):
            with self.assertRaises(ValueError):
                self.store.claim_check(self.sid, self.token, payload)
        with self.assertRaises(CheckError):
            self.store.record_check_result(self.sid,item["id"],self.token,result(lease,self.now+90),now=self.now+90)
        replacement = self.claim(self.now + 90)
        self.assertNotEqual(lease["id"], replacement["id"])
        new_token = self.store.rotate_agent_token(self.sid)
        with self.assertRaises(AuthenticationError):
            self.store.record_check_result(self.sid,item["id"],self.token,result(replacement,self.now+90),now=self.now+90)
        with self.assertRaises(CheckError):
            self.store.record_check_result(self.sid,item["id"],new_token,result(replacement,self.now+90),now=self.now+90)
        self.token = new_token
        self.assertIsNotNone(self.claim(self.now+90))

    def test_identical_result_replay_is_bounded_and_cannot_reschedule_or_add_history(self):
        item = definition()
        self.config([item]); lease = self.claim(); payload = result(lease,self.now)
        self.store.record_check_result(self.sid,item["id"],self.token,payload,now=self.now)
        self.assertEqual(self.store.record_check_result(self.sid,item["id"],self.token,payload,now=self.now+10), {"accepted": True})
        self.assertEqual(len(self.store.check_history(self.sid,item["id"])["results"]), 1)
        self.assertEqual(self.store.check_history(self.sid,item["id"])["results"][0]["received_at"], self.now)
        self.assertIsNone(self.claim(self.now+59))
        self.assertIsNotNone(self.claim(self.now+60))
        with self.assertRaises(CheckError):
            self.store.record_check_result(self.sid,item["id"],self.token,dict(payload,latency_ms=13),now=self.now+10)
        with self.assertRaises(CheckError):
            self.store.record_check_result(self.sid,item["id"],self.token,payload,now=self.now+90)
        self.store.rotate_agent_token(self.sid)
        with self.assertRaises(AuthenticationError):
            self.store.record_check_result(self.sid,item["id"],self.token,payload,now=self.now+20)

    def test_config_changes_invalidate_inflight_and_reset_only_changed_targets(self):
        item = definition(); self.config([item]); lease = self.claim()
        self.store.record_check_result(self.sid,item["id"],self.token,result(lease,self.now),now=self.now)
        self.config([dict(item,name="Renamed")],revision=1)
        self.assertEqual(len(self.store.check_history(self.sid,item["id"])["results"]), 1)
        lease = self.claim(self.now+60)
        changed = definition("tcp",id=item["id"])
        self.config([changed],revision=2)
        with self.assertRaises(CheckError) as error:
            self.store.record_check_result(self.sid,item["id"],self.token,result(lease,self.now+60),now=self.now+60)
        self.assertEqual(error.exception.status,409)
        self.assertEqual(self.store.check_history(self.sid,item["id"])["results"], [])
        lease = self.claim(); self.config([dict(changed,enabled=False)],revision=3)
        with self.assertRaises(CheckError):
            self.store.record_check_result(self.sid,item["id"],self.token,result(lease,self.now),now=self.now)
        self.assertIsNone(self.claim())
        self.config([],revision=4)
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM check_results").fetchone()[0],0)
        with self.assertRaises(CheckError): self.store.check_history(self.sid,item["id"])

    def test_history_and_duplicate_metadata_prune_on_write_without_any_reader(self):
        item = definition("tcp"); self.config([item]); first = None
        for index in range(63):
            now = self.now + 60*index; lease = self.claim(now); payload = result(lease,now)
            if first is None: first = payload
            self.store.record_check_result(self.sid,item["id"],self.token,payload,now=now)
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM check_results").fetchone()[0],60)
            self.assertIsNone(db.execute("SELECT id FROM check_results WHERE lease_id=?",(first["lease_id"],)).fetchone())
        history = self.store.check_history(self.sid,item["id"])["results"]
        self.assertEqual(history[0]["observed_at"],self.now+62*60)
        self.assertEqual(history[-1]["observed_at"],self.now+3*60)

    def test_result_union_rejects_remote_text_inconsistent_types_and_untrusted_tls(self):
        item = definition(); self.config([item]); lease = self.claim(); good = result(lease,self.now)
        for change in ({"latency_ms": True}, {"latency_ms":10001}, {"observed_at":self.now+301},
                       {"error_code":"remote secret"}, {"reason":"secret"}, {"status":"up","http_status":503},
                       {"status":"down","error_code":None}, {"tls_expires_at":None},
                       {"status":"down","error_code":"tls_error"}, {"status":"down","error_code":"http_error"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.store.record_check_result(self.sid,item["id"],self.token,dict(good,**change),now=self.now)
        self.store.record_check_result(self.sid,item["id"],self.token,dict(good,status="down",error_code="http_error",http_status=503),now=self.now)
        history = self.store.check_history(self.sid,item["id"])["results"][0]
        self.assertEqual(history["tls_expires_at"],good["tls_expires_at"])
        self.assertEqual(set(history),{"observed_at","received_at","status","latency_ms","http_status","tls_expires_at","error_code"})

    def test_dns_result_is_private_and_target_change_clears_history(self):
        item = definition("dns", expected_ip="203.0.113.7")
        self.config([item]); lease = self.claim()
        good = result(lease, self.now)
        for change in ({"http_status": 200}, {"tls_expires_at": self.now + 100},
                       {"error_code": "connect_error", "status": "down"},
                       {"error_code": "dns_mismatch", "status": "up"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.store.record_check_result(self.sid, item["id"], self.token, dict(good, **change), now=self.now)
        mismatch = dict(good, status="down", error_code="dns_mismatch")
        self.store.record_check_result(self.sid, item["id"], self.token, mismatch, now=self.now)
        summary = self.store.checks_summary(self.sid, now=self.now)
        self.assertEqual(summary["checks"][0]["state"], "down")
        self.assertNotIn(item["host"], json.dumps(summary))
        self.assertNotIn(item["expected_ip"], json.dumps(summary))
        self.assertEqual(self.store.check_history(self.sid, item["id"])["results"][0]["error_code"], "dns_mismatch")
        self.config([dict(item, expected_ip="203.0.113.8")], revision=1)
        self.assertEqual(self.store.check_history(self.sid, item["id"])["results"], [])
        self.config([dict(item, expected_ip=None)], revision=2)
        no_expectation = self.claim()
        with self.assertRaises(ValueError):
            self.store.record_check_result(self.sid, item["id"], self.token,
                result(no_expectation, self.now, status="down", error_code="dns_mismatch"), now=self.now)

    def test_sanitized_summary_states_and_manual_run_throttle(self):
        item = definition(); self.config([item]); lease = self.claim()
        with self.assertRaises(CheckError) as error: self.store.run_check(self.sid,item["id"],{"revision":1},now=self.now)
        self.assertEqual(error.exception.status,409)
        self.store.record_check_result(self.sid,item["id"],self.token,result(lease,self.now),now=self.now)
        for now,state in ((self.now,"up"),(self.now+121,"stale")):
            summary=self.store.checks_summary(self.sid,now=now)
            self.assertEqual(summary["checks"][0]["state"],state)
            for secret in (item["url"],self.token,"lease_id","config_revision","agent_token_hash"):
                self.assertNotIn(secret,json.dumps(summary))
        self.store.run_check(self.sid,item["id"],{"revision":1},now=self.now)
        with self.assertRaises(CheckError) as error: self.store.run_check(self.sid,item["id"],{"revision":1},now=self.now+9)
        self.assertEqual(error.exception.status,429)
        self.assertTrue(self.store.run_check(self.sid,item["id"],{"revision":1},now=self.now+10)["scheduled"])
        self.config([dict(item,enabled=False)],revision=1)
        self.assertEqual(self.store.checks_summary(self.sid)["checks"][0]["state"],"disabled")
        self.assertNotIn(item["url"],json.dumps(self.store.audit_events()))

    def test_additive_migration_preserves_existing_data_and_rolls_back_interrupted_ddl(self):
        owner=self.store.login("owner",PASSWORD)[0]
        with self.store.connection() as db:
            for table in ("check_results","server_checks","server_check_configs"): db.execute("DROP TABLE "+table)
        def interrupted(db):
            migrate_checks(db)
            raise RuntimeError("interrupted checks migration")
        with mock.patch("sovagrid_hub.store.migrate_checks",side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError,"interrupted"):
                self.store.migrate()
        with self.store.connection() as db:
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='server_checks'").fetchone())
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(),[])
        self.store.migrate(); self.store.migrate()
        self.assertEqual(self.store.session_info(owner)["user"]["username"],"owner")
        self.assertTrue(self.store.agent_valid(self.sid,self.token))
        self.assertEqual(self.store.check_config(self.sid)["checks"],[])


class CheckHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.path=Path(self.temp.name)/"http.sqlite"
        self.store=Store(self.path); self.store.initialize("owner",PASSWORD)
        self.owner=self.store.login("owner",PASSWORD)[0]
        self.host=self.store.create_server("host"); self.sid=self.host["id"]; self.agent=self.host["agent_token"]
        self.item=definition(); self.prefix=f"/api/v1/servers/{self.sid}/checks"
        self.server=make_server(HubApp(self.store),0)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
        self.base=f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2); self.temp.cleanup()

    def request(self, method, path, token=None, payload=None, raw=None):
        headers={"Authorization":"Bearer "+token} if token else {}
        if raw is not None or payload is not None: headers["Content-Type"]="application/json"
        body=raw if raw is not None else json.dumps(payload).encode() if payload is not None else None
        request=urllib.request.Request(self.base+path,data=body,method=method,headers=headers)
        try:
            with urllib.request.urlopen(request,timeout=4) as response: return response.status,json.load(response)
        except urllib.error.HTTPError as error:
            with error: return error.code,json.load(error)

    def account(self,name,role):
        user=self.store.create_user(name,PASSWORD,role,session_token=self.owner)
        return user,self.store.login(name,PASSWORD)[0]

    def seed(self):
        self.assertEqual(self.request("POST",self.prefix+"/config",self.owner,{"revision":0,"checks":[self.item]})[0],200)
        lease=self.request("POST",self.prefix+"/claim",self.agent,{"protocol":1})[1]["lease"]
        self.assertEqual(self.request("POST",self.prefix+"/"+self.item["id"]+"/result",self.agent,result(lease,int(time.time())))[0],200)
        return lease

    def test_role_matrix_targets_and_result_metadata_never_reach_readers(self):
        self.seed()
        for role in ("viewer","operator"):
            _,token=self.account(role,role)
            for suffix in ("","/"+self.item["id"]+"/history?limit=60"):
                status,body=self.request("GET",self.prefix+suffix,token)
                self.assertEqual(status,200)
                for secret in (self.item["url"],"lease_id","agent_token_hash","definition_json"):
                    self.assertNotIn(secret,json.dumps(body))
            self.assertEqual(self.request("GET",self.prefix+"/config",token)[0],403)
            for suffix,payload in (("/config",{"revision":1,"checks":[]}),
                                   ("/"+self.item["id"]+"/run",{"revision":1})):
                self.assertEqual(self.request("POST",self.prefix+suffix,token,payload)[0],403)
            self.assertEqual(self.request("POST",self.prefix+"/claim",token,{"protocol":1})[0],401)
        self.assertEqual(self.request("GET",self.prefix,self.agent)[0],401)
        self.assertEqual(self.request("GET",self.prefix+"/config",self.owner)[1]["checks"][0]["url"],self.item["url"])

    def test_http_cas_body_caps_strict_queries_and_history_shape(self):
        self.seed()
        self.assertEqual(self.request("POST",self.prefix+"/config",self.owner,{"revision":0,"checks":[]})[0],409)
        self.assertEqual(self.request("POST",self.prefix+"/config",self.owner,raw=b" "*32769)[0],413)
        self.assertEqual(self.request("POST",self.prefix+"/claim",self.agent,raw=b" "*4097)[0],413)
        for suffix in ("?limit=0","?limit=61","?limit=1&limit=2","?extra=x","?limit=true"):
            self.assertEqual(self.request("GET",self.prefix+"/"+self.item["id"]+"/history"+suffix,self.owner)[0],400)
        body=self.request("GET",self.prefix+"/"+self.item["id"]+"/history",self.owner)[1]
        self.assertEqual(set(body),{"server_id","check_id","results"})
        self.assertEqual(len(body["results"]),1)
        missing=str(uuid.uuid4())
        self.assertEqual(self.request("GET",f"/api/v1/servers/{missing}/checks",self.owner)[0],404)

    def test_write_transaction_rechecks_role_after_body_authentication(self):
        user,token=self.account("racing-admin","admin")
        original=self.store.save_check_config
        def demote(*args,**kwargs):
            self.store.update_user(user["id"],{"revision":1,"role":"viewer"},session_token=self.owner)
            return original(*args,**kwargs)
        with mock.patch.object(self.store,"save_check_config",side_effect=demote):
            self.assertEqual(self.request("POST",self.prefix+"/config",token,{"revision":0,"checks":[self.item]})[0],401)
        self.assertEqual(self.store.check_config(self.sid)["revision"],0)

    def test_claim_and_result_transactions_recheck_agent_token_after_body(self):
        self.store.save_check_config(self.sid,{"revision":0,"checks":[self.item]})
        original=self.store.claim_check
        def rotate(*args,**kwargs):
            self.agent=self.store.rotate_agent_token(self.sid)
            return original(*args,**kwargs)
        old=self.agent
        with mock.patch.object(self.store,"claim_check",side_effect=rotate):
            self.assertEqual(self.request("POST",self.prefix+"/claim",old,{"protocol":1})[0],401)
        self.assertIsNone(self.store.checks_summary(self.sid)["worker_seen_at"])
        lease=original(self.sid,self.agent,{"protocol":1})["lease"]
        record=self.store.record_check_result
        def rotate_result(*args,**kwargs):
            self.agent=self.store.rotate_agent_token(self.sid)
            return record(*args,**kwargs)
        old=self.agent
        with mock.patch.object(self.store,"record_check_result",side_effect=rotate_result):
            self.assertEqual(self.request("POST",self.prefix+"/"+self.item["id"]+"/result",old,result(lease,int(time.time())))[0],401)
        self.assertEqual(self.store.check_history(self.sid,self.item["id"])["results"],[])

    def test_delayed_request_body_cannot_use_revoked_session_or_agent(self):
        user,admin=self.account("delayed-admin","admin")
        for kind in ("admin","agent"):
            checked=threading.Event()
            if kind=="admin":
                token=admin; route=self.prefix+"/config"; payload={"revision":0,"checks":[self.item]}
                name="session_info"; original=self.store.session_info
            else:
                token=self.agent; route=self.prefix+"/claim"; payload={"protocol":1}
                name="agent_valid"; original=self.store.agent_valid
            def observe(*args,**kwargs):
                value=original(*args,**kwargs); checked.set(); return value
            body=json.dumps(payload).encode()
            with mock.patch.object(self.store,name,side_effect=observe):
                with socket.create_connection(("127.0.0.1",self.server.server_port),timeout=3) as conn:
                    conn.sendall(f"POST {route} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()+body[:1])
                    self.assertTrue(checked.wait(2))
                    if kind=="admin": self.store.update_user(user["id"],{"revision":1,"role":"viewer"},session_token=self.owner)
                    else: self.agent=self.store.rotate_agent_token(self.sid)
                    conn.sendall(body[1:]); self.assertIn(b" 401 ",conn.recv(4096))
        self.assertEqual(self.store.check_config(self.sid)["revision"],0)
        self.assertIsNone(self.store.checks_summary(self.sid)["worker_seen_at"])


if __name__ == "__main__":
    unittest.main()
