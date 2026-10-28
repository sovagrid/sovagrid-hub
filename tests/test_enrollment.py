# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Interrupted provisioning cannot duplicate, adopt or erase another server."""
import hashlib
import json
import secrets
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from unittest import mock

from sovagrid_hub.auth import AuthenticationError
from sovagrid_hub.enrollment import EnrollmentError, migrate_enrollments
from sovagrid_hub.http_api import HubApp, HubHandler, make_server
from sovagrid_hub.store import Store

PASSWORD = "a-long-enrollment-test-password"
PUBLIC_FIELDS = {"id", "server_id", "name", "state", "revision", "created_at", "last_seen"}


def registration():
    bearer = secrets.token_urlsafe(32)
    return str(uuid.uuid4()), {"server_id": str(uuid.uuid4()), "name": "Remote owl 🦉",
                             "agent_token_sha256": hashlib.sha256(bearer.encode()).hexdigest()}, bearer


def metric():
    return {"collected_at": int(time.time()), "cpu_percent": 1, "memory_percent": 2,
            "disk_percent": 3, "network_rx_bytes": 4, "network_tx_bytes": 5,
            "load1": 0.1, "uptime_seconds": 10}


class EnrollmentFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.path)
        self.store.initialize("owner", PASSWORD)
        self.owner = self.store.login("owner", PASSWORD)[0]
        self.identifier, self.payload, self.bearer = registration()
        self.sid = self.payload["server_id"]

    def tearDown(self):
        self.temp.cleanup()

    def register(self, **kwargs):
        return self.store.register_agent_enrollment(self.identifier,self.payload,session_token=self.owner,**kwargs)

    def cancel(self, revision=1, **kwargs):
        return self.store.cancel_agent_enrollment(self.identifier,{"revision":revision},session_token=self.owner,**kwargs)


class EnrollmentStoreTests(EnrollmentFixture, unittest.TestCase):
    def test_lost_registration_response_reuses_identity_without_returning_a_secret(self):
        first, created = self.register()
        repeated, created_again = self.store.register_agent_enrollment(self.identifier,dict(reversed(list(self.payload.items()))),session_token=self.owner)
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first,repeated)
        self.assertEqual(set(first),PUBLIC_FIELDS)
        self.assertEqual(first["state"],"pending")
        self.assertEqual(first["revision"],1)
        self.assertTrue(self.store.agent_valid(self.sid,self.bearer))
        self.assertFalse(self.store.server_commands_enabled(self.sid))
        self.assertEqual(self.store.sweep_offline(now=int(time.time())+86400),[])
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM servers").fetchone()[0],1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM agent_enrollments").fetchone()[0],1)
            self.assertNotIn(self.bearer,"\n".join(db.iterdump()))
        text=json.dumps([first,self.store.servers(),self.store.audit_events()])
        for private in (self.bearer,self.payload["agent_token_sha256"],"registered_token_hash","request_hash"):
            self.assertNotIn(private,text)
        self.assertEqual(len([event for event in self.store.audit_events() if event["action"]=="agent_enrollment_registered"]),1)

    def test_replay_conflicts_never_adopt_or_change_existing_server(self):
        self.register()
        for change in ({"name":"Other"},{"server_id":str(uuid.uuid4())},{"agent_token_sha256":"f"*64}):
            with self.subTest(change=change),self.assertRaises(EnrollmentError) as error:
                self.store.register_agent_enrollment(self.identifier,dict(self.payload,**change),session_token=self.owner)
            self.assertEqual(error.exception.status,409)
        legacy=self.store.create_server("legacy")
        for identifier,payload in ((str(uuid.uuid4()),dict(self.payload,server_id=legacy["id"])),
                                   (str(uuid.uuid4()),self.payload)):
            with self.assertRaises(EnrollmentError):
                self.store.register_agent_enrollment(identifier,payload,session_token=self.owner)
        self.assertTrue(self.store.agent_valid(legacy["id"],legacy["agent_token"]))
        self.assertTrue(self.store.agent_valid(self.sid,self.bearer))
        self.store.rotate_agent_token(self.sid)
        with self.assertRaises(EnrollmentError): self.register()

    def test_all_admins_can_resume_after_creator_deletion_and_audit_creator_stays_immutable(self):
        creator=self.store.session_info(self.owner)["user"]
        self.register()
        other=self.store.create_user("other-admin",PASSWORD,"admin",session_token=self.owner)
        token=self.store.login("other-admin",PASSWORD)[0]
        self.store.delete_user(creator["id"],creator["revision"],session_token=token)
        record,created=self.store.register_agent_enrollment(self.identifier,self.payload,session_token=token)
        self.assertFalse(created)
        self.assertEqual(record["state"],"pending")
        self.store.cancel_agent_enrollment(self.identifier,{"revision":1},session_token=token)
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT creator_id FROM agent_enrollments").fetchone()[0],creator["id"])
        event=next(row for row in self.store.audit_events() if row["action"]=="agent_enrollment_cancelled")
        self.assertEqual(event["actor"],"hub:"+other["id"])

    def test_cancel_tombstone_is_idempotent_and_cannot_be_resurrected(self):
        self.register()
        # The independent check worker may poll before the first metric.
        self.assertEqual(self.store.claim_check(self.sid,self.bearer,{"protocol":1}),{"lease":None})
        cancelled=self.cancel()
        self.assertEqual(cancelled["state"],"cancelled")
        self.assertEqual(cancelled["revision"],2)
        self.assertEqual(self.cancel(),cancelled)
        self.assertEqual(self.store.agent_enrollment(self.identifier,session_token=self.owner),cancelled)
        self.assertFalse(self.store.agent_valid(self.sid,self.bearer))
        self.assertFalse(self.store.server_exists(self.sid))
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM server_check_configs").fetchone()[0],0)
        for revision in (2,3):
            with self.assertRaises(EnrollmentError): self.cancel(revision)
        with self.assertRaises(EnrollmentError): self.register()
        with self.assertRaises(EnrollmentError):
            self.store.register_agent_enrollment(str(uuid.uuid4()),self.payload,session_token=self.owner)
        self.assertEqual(len([event for event in self.store.audit_events() if event["action"]=="agent_enrollment_cancelled"]),1)

    def test_first_metric_is_active_proof_even_after_history_is_pruned(self):
        self.register()
        self.store.ingest(self.sid,metric(),agent_token=self.bearer)
        self.assertEqual(self.store.agent_enrollment(self.identifier)["state"],"active")
        self.store.prune_metrics(retention_days=0,now=int(time.time())+1)
        with self.assertRaises(EnrollmentError) as error: self.cancel()
        self.assertEqual(error.exception.status,409)
        self.assertTrue(self.store.agent_valid(self.sid,self.bearer))
        self.assertFalse(self.register()[1])

    def test_pending_limit_is_transactional_and_does_not_block_exact_replay(self):
        self.register()
        for _ in range(127):
            identifier,payload,_=registration()
            self.store.register_agent_enrollment(identifier,payload)
        identifier,payload,_=registration()
        with self.assertRaises(EnrollmentError): self.store.register_agent_enrollment(identifier,payload)
        self.assertFalse(self.register()[1])
        self.cancel()
        self.assertTrue(self.store.register_agent_enrollment(identifier,payload)[1])

    def test_cancel_preserves_each_kind_of_saved_state_including_future_cascade_tables(self):
        mutations=[
            ("commands",lambda db,sid:db.execute("UPDATE servers SET remote_commands_enabled=1 WHERE id=?",(sid,))),
            ("name",lambda db,sid:db.execute("UPDATE servers SET name='Changed' WHERE id=?",(sid,))),
            ("creation",lambda db,sid:db.execute("UPDATE servers SET created_at=created_at+1 WHERE id=?",(sid,))),
            ("credential",lambda db,sid:db.execute("UPDATE servers SET agent_token_hash=? WHERE id=?",("0"*64,sid))),
            ("metric with missing receipt marker",lambda db,sid:db.execute("""INSERT INTO metrics
                (server_id,collected_at,received_at,cpu_percent,memory_percent,disk_percent,
                 network_rx_bytes,network_tx_bytes,load1,uptime_seconds) VALUES (?,1,1,1,1,1,1,1,1,1)""",(sid,))),
            ("job",lambda db,sid:db.execute("INSERT INTO jobs(id,server_id,actor_user_id,chat_id,command,state,created_at) VALUES (?,?,0,0,'','cancelled',1)",(str(uuid.uuid4()),sid))),
            ("confirmation",lambda db,sid:db.execute("INSERT INTO pending_commands VALUES (?,?,1,1,'test',1,2)",(str(uuid.uuid4()),sid))),
            ("incident",lambda db,sid:db.execute("INSERT INTO incidents(id,server_id,kind,state,opened_at,updated_at) VALUES (?,?,'offline','resolved',1,1)",(str(uuid.uuid4()),sid))),
            ("candidate",lambda db,sid:db.execute("INSERT INTO incident_candidates VALUES (?,'high_cpu',1,1,99,90)",(sid,))),
            ("maintenance",lambda db,sid:db.execute("INSERT INTO maintenance_windows(id,server_id,starts_at,ends_at,reason) VALUES (?,?,1,2,'planned')",(str(uuid.uuid4()),sid))),
            ("empty saved checks",lambda db,sid:db.execute("INSERT INTO server_check_configs(server_id,revision) VALUES (?,1)",(sid,))),
            ("check definition",lambda db,sid:db.execute("""INSERT INTO server_checks
                (server_id,check_id,position,definition_json,next_due_at) VALUES (?,?,0,'{}',1)""",(sid,str(uuid.uuid4())))),
            ("future cascade",lambda db,sid:db.execute("INSERT INTO future_saved_state VALUES (?,?)",(sid,"do not delete"))),
        ]
        with self.store.connection() as db:
            db.execute("CREATE TABLE future_saved_state(server_id TEXT REFERENCES servers(id) ON DELETE CASCADE, value TEXT)")
        for label,mutate in mutations:
            identifier,payload,_=registration();sid=payload["server_id"]
            self.store.register_agent_enrollment(identifier,payload)
            with self.store.connection() as db: mutate(db,sid)
            with self.subTest(label=label),self.assertRaises(EnrollmentError) as error:
                self.store.cancel_agent_enrollment(identifier,{"revision":1})
            self.assertEqual(error.exception.status,409)
            self.assertTrue(self.store.server_exists(sid))
            self.assertEqual(self.store.agent_enrollment(identifier)["state"],"pending")

    def test_concurrent_registration_creates_exactly_one_mapping_and_server(self):
        barrier=threading.Barrier(2);created=[];errors=[]
        def worker():
            try:
                barrier.wait(3)
                created.append(Store(self.path).register_agent_enrollment(self.identifier,self.payload)[1])
            except Exception as error: errors.append(error)
        threads=[threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:thread.start()
        for thread in threads:thread.join(5);self.assertFalse(thread.is_alive())
        self.assertEqual(errors,[])
        self.assertCountEqual(created,[True,False])
        self.assertEqual(len(self.store.servers()),1)

    def test_cancel_and_first_metric_have_only_two_serializable_outcomes(self):
        for first in ("cancel","metric"):
            identifier,payload,bearer=registration();sid=payload["server_id"]
            self.store.register_agent_enrollment(identifier,payload)
            contender=Store(self.path);holding=threading.Event();release=threading.Event();outcomes={}
            def cancellation():
                try:
                    contender.cancel_agent_enrollment(identifier,{"revision":1});outcomes["cancel"]="ok"
                except EnrollmentError as error:outcomes["cancel"]=error.status
            def sample():
                try:
                    self.store.ingest(sid,metric(),agent_token=bearer);outcomes["metric"]="ok"
                except AuthenticationError:outcomes["metric"]=401
            if first=="cancel":
                original=contender._require_empty_enrollment_server
                def block(*args):
                    original(*args);holding.set();self.assertTrue(release.wait(3))
                patch=mock.patch.object(contender,"_require_empty_enrollment_server",side_effect=block)
                first_target,second_target=cancellation,sample
            else:
                original=self.store._check_agent
                def block(*args):
                    value=original(*args);holding.set();self.assertTrue(release.wait(3));return value
                patch=mock.patch.object(self.store,"_check_agent",side_effect=block)
                first_target,second_target=sample,cancellation
            with patch:
                one=threading.Thread(target=first_target);two=threading.Thread(target=second_target)
                one.start()
                try:
                    self.assertTrue(holding.wait(3));two.start()
                finally:release.set()
                one.join(5);two.join(5)
                self.assertFalse(one.is_alive());self.assertFalse(two.is_alive())
            expected={"cancel":"ok","metric":401} if first=="cancel" else {"cancel":409,"metric":"ok"}
            self.assertEqual(outcomes,expected)

    def test_strict_payloads_and_legacy_local_ingest_remain_compatible(self):
        for change in ({"name":" spaced"},{"name":"\ud800"},{"name":False},{"name":""},
                       {"agent_token_sha256":"A"*64},{"agent_token_sha256":True},
                       {"server_id":str(uuid.uuid4()).upper()},{"extra":"private"}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                self.store.register_agent_enrollment(self.identifier,dict(self.payload,**change))
        for revision in (True,0,-1,2**63,"1"):
            with self.assertRaises(ValueError):
                self.store.cancel_agent_enrollment(self.identifier,{"revision":revision})
        legacy=self.store.create_server("legacy")
        self.store.ingest(legacy["id"],metric())  # Existing trusted CLI API.
        with self.assertRaises(AuthenticationError):
            self.store.ingest(legacy["id"],metric(),agent_token="")
        self.assertTrue(self.store.servers()[0]["online"])

    def test_additive_migration_and_interruption_preserve_existing_sessions_and_credentials(self):
        legacy=self.store.create_server("legacy")
        with self.store.connection() as db:db.execute("DROP TABLE agent_enrollments")
        def interrupt(db):
            migrate_enrollments(db);raise RuntimeError("interrupted enrollment migration")
        with mock.patch("sovagrid_hub.store.migrate_enrollments",side_effect=interrupt):
            with self.assertRaisesRegex(RuntimeError,"interrupted"):self.store.migrate()
        with self.store.connection() as db:
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='agent_enrollments'").fetchone())
        self.store.migrate();self.store.migrate()
        self.assertTrue(self.store.session_valid(self.owner))
        self.assertTrue(self.store.agent_valid(legacy["id"],legacy["agent_token"]))
        self.assertIsNone(self.store.agent_enrollment(self.identifier))


class EnrollmentHTTPTests(EnrollmentFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.prefix="/api/v1/agent-enrollments/"+self.identifier
        self.server=make_server(HubApp(self.store),0)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.base=f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(2);super().tearDown()

    def request(self,method,path,token=None,payload=None,raw=None):
        headers={"Authorization":"Bearer "+token} if token else {}
        if raw is not None or payload is not None:headers["Content-Type"]="application/json"
        body=raw if raw is not None else json.dumps(payload).encode() if payload is not None else None
        request=urllib.request.Request(self.base+path,data=body,method=method,headers=headers)
        try:
            with urllib.request.urlopen(request,timeout=4) as response:return response.status,json.load(response)
        except urllib.error.HTTPError as error:
            with error:return error.code,json.load(error)

    def account(self,name,role="admin"):
        user=self.store.create_user(name,PASSWORD,role,session_token=self.owner)
        return user,self.store.login(name,PASSWORD)[0]

    def test_exact_public_contract_roles_and_secret_canaries(self):
        self.assertEqual(self.request("GET",self.prefix,self.owner),(200,{"protocol":1,"enrollment":None}))
        with mock.patch("logging.info") as logger:
            status,first=self.request("POST",self.prefix,self.owner,self.payload)
            self.assertEqual(status,201);self.assertEqual(set(first),{"protocol","enrollment"})
            self.assertEqual(set(first["enrollment"]),PUBLIC_FIELDS)
            self.assertEqual(self.request("POST",self.prefix,self.owner,self.payload),(200,first))
            for role in ("viewer","operator"):
                _,token=self.account(role,role)
                self.assertEqual(self.request("GET",self.prefix,token)[0],403)
                self.assertEqual(self.request("POST",self.prefix,token,self.payload)[0],403)
                self.assertEqual(self.request("POST",self.prefix+"/cancel",token,{"revision":1})[0],403)
            self.assertEqual(self.request("GET",self.prefix,self.bearer)[0],401)
            status,cancelled=self.request("POST",self.prefix+"/cancel",self.owner,{"revision":1})
            self.assertEqual(status,200);self.assertEqual(cancelled["enrollment"]["state"],"cancelled")
            self.assertEqual(self.request("POST",self.prefix+"/cancel",self.owner,{"revision":1}),(200,cancelled))
            self.assertEqual(self.request("POST",self.prefix,self.owner,self.payload)[0],409)
            text=json.dumps([first,cancelled,self.store.audit_events(),str(logger.call_args_list)])
            for secret in (self.bearer,self.payload["agent_token_sha256"],"request_hash","registered_token_hash"):
                self.assertNotIn(secret,text)

    def test_strict_json_queries_body_limits_and_http_metric_activation(self):
        self.assertEqual(self.request("POST",self.prefix,self.owner,raw=b" "*4097)[0],413)
        duplicate=json.dumps(self.payload)[:-1]+',"name":"duplicate"}'
        self.assertEqual(self.request("POST",self.prefix,self.owner,raw=duplicate.encode())[0],400)
        self.assertEqual(self.request("GET",self.prefix+"?anything=1",self.owner)[0],400)
        self.assertEqual(self.request("POST",self.prefix+"?anything=1",self.owner,self.payload)[0],400)
        self.assertEqual(self.request("GET","/api/v1/agent-enrollments/not-an-id",self.owner)[0],400)
        self.assertEqual(self.request("POST",self.prefix,self.owner,self.payload)[0],201)
        self.assertEqual(self.request("POST",f"/api/v1/servers/{self.sid}/metrics",self.bearer,metric()),
                         (202,{"accepted":True,"metric_details":["pressure","cpu_times"]}))
        self.assertEqual(self.request("GET",self.prefix,self.owner)[1]["enrollment"]["state"],"active")
        self.assertEqual(self.request("POST",self.prefix+"/cancel",self.owner,{"revision":1})[0],409)

    def test_body_to_transaction_revocation_blocks_both_enrollment_mutations(self):
        for action in ("register","cancel"):
            user,token=self.account(action)
            if action=="cancel":self.register()
            name="register_agent_enrollment" if action=="register" else "cancel_agent_enrollment"
            original=getattr(self.store,name)
            def revoke(*args,**kwargs):
                self.store.update_user(user["id"],{"revision":1,"role":"viewer"},session_token=self.owner)
                return original(*args,**kwargs)
            path=self.prefix if action=="register" else self.prefix+"/cancel"
            payload=self.payload if action=="register" else {"revision":1}
            with mock.patch.object(self.store,name,side_effect=revoke):
                self.assertEqual(self.request("POST",path,token,payload)[0],401)
            if action=="register":self.assertIsNone(self.store.agent_enrollment(self.identifier))
            else:self.assertTrue(self.store.server_exists(self.sid))

    def test_delayed_body_cannot_create_or_cancel_after_role_revocation(self):
        for action in ("register","cancel"):
            user,token=self.account("delayed-"+action)
            if action=="cancel":self.register()
            checked=threading.Event();original=HubHandler._body
            def observe(handler,*args,**kwargs):
                # Revoke only after route authorization has reached the body
                # read. Revoking during session_info can close the HTTP/1.1
                # response before the client sends the remaining bytes.
                if handler.path==path:checked.set()
                return original(handler,*args,**kwargs)
            body=json.dumps(self.payload if action=="register" else {"revision":1}).encode()
            path=self.prefix if action=="register" else self.prefix+"/cancel"
            with mock.patch.object(HubHandler,"_body",observe):
                with socket.create_connection(("127.0.0.1",self.server.server_port),timeout=3) as conn:
                    conn.sendall(f"POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()+body[:1])
                    self.assertTrue(checked.wait(2))
                    self.store.update_user(user["id"],{"revision":1,"role":"viewer"},session_token=self.owner)
                    conn.sendall(body[1:]);self.assertIn(b" 401 ",conn.recv(4096))
            if action=="register":self.assertIsNone(self.store.agent_enrollment(self.identifier))
            else:self.assertTrue(self.store.server_exists(self.sid))

    def test_http_metrics_recheck_current_token_when_cancel_or_rotation_wins_after_body(self):
        for action in ("rotate","cancel"):
            identifier,payload,bearer=registration();sid=payload["server_id"]
            self.store.register_agent_enrollment(identifier,payload)
            original=self.store.ingest
            def mutate(*args,**kwargs):
                self.assertEqual(kwargs["agent_token"],bearer)
                if action=="rotate":self.store.rotate_agent_token(sid)
                else:self.store.cancel_agent_enrollment(identifier,{"revision":1})
                return original(*args,**kwargs)
            with mock.patch.object(self.store,"ingest",side_effect=mutate):
                self.assertEqual(self.request("POST",f"/api/v1/servers/{sid}/metrics",bearer,metric())[0],401)
            self.assertEqual(self.store.history(sid),[])


if __name__=="__main__":
    unittest.main()
