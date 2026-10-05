"""P10-D-002 / P10-D-003 guards: the DovahLink consumer Bootstrap mapping vectors and audit model.

These are DovahLink consumer mapping checks, not sas-pairing protocol conformance. A small test-only
reference of the frozen mapping re-derives every byte of
docs/p10-consumer-integration/vectors/dovahlink-bootstrap-v1.json: applicationIdentity (domain,
role byte, RFC 9562 UUID bytes), keyAlgorithm, the canonical P-256 SPKI publicKey, the constant
sharedContext, the authority scopes, and the canonical type-0x20 Bootstrap frame, whose encoder is
first checked byte for byte against the core-generated frames of vectors/p3-remote-vodozemac-draft-01.json.
The E-13 strategy (exact comparison of the whole authenticated peer frame with a locally built
expected frame) and the pending-authorization model are checked as executable rules, and the
authentication-audit facts are checked against the audit document.

Test and tooling only: standard library, no cryptography beyond SHA-256 fingerprints, no
sas-pairing wire-message parsing, no Bootstrap decoder, and no production consumer code.
"""

import base64
import hashlib
import json
import os
import re
import struct
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
P10 = os.path.join(ROOT, "docs", "p10-consumer-integration")
VECTORS = os.path.join(P10, "vectors", "dovahlink-bootstrap-v1.json")
P3_VECTOR = os.path.join(ROOT, "vectors", "p3-remote-vodozemac-draft-01.json")
AUDIT_DOC = os.path.join(P10, "authentication-audit.md")
MAPPING_DOC = os.path.join(P10, "bootstrap-mapping.md")
DECISIONS_DOC = os.path.join(P10, "decisions.md")

# ---- Test-only reference of the frozen P10-D-002 mapping ----

AI_DOMAIN = b"dovahlink.application-identity.v1"
ROLE_CODES = {"host": 0x01, "client": 0x02}
KEY_ALGORITHM = b"dovahlink.ecdsa-p256.spki-der.v1"
SHARED_CONTEXT = b"dovahlink.sas-pairing.bootstrap-v1.pairing"
SCOPE_DOMAIN = b"dovahlink.pairing-authority.v1"
SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
FIELD_NAMES = ("application_identity", "key_algorithm", "public_key", "shared_context")
UUID_TEXT = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
KEY_ALGORITHM_GRAMMAR = re.compile(rb"^[a-z0-9][a-z0-9.-]*$")

# NIST P-256 (SEC 2 / FIPS 186-5) curve constants, used only to check that a test key is on the curve.
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def uuid_network_bytes(text):
    """The 16 UUID bytes in RFC 9562 network order (the order of the hex digits of the 8-4-4-4-12 form)."""
    if not UUID_TEXT.match(text):
        raise ValueError("not an 8-4-4-4-12 UUID")
    value = bytes.fromhex(text.replace("-", ""))
    if value == bytes(16):
        raise ValueError("the nil UUID is not a DovahLink identity")
    return value


def dotnet_guid_to_byte_array(text):
    """What .NET Guid.ToByteArray() returns: the first three groups little-endian. Never canonical."""
    b = uuid_network_bytes(text)
    return b[3::-1] + b[5:3:-1] + b[7:5:-1] + b[8:]


def application_identity(role, uuid_text):
    return AI_DOMAIN + bytes([ROLE_CODES[role]]) + uuid_network_bytes(uuid_text)


def authority_scope(role, uuid_text):
    return SCOPE_DOMAIN + bytes([ROLE_CODES[role]]) + uuid_network_bytes(uuid_text)


def local_shared_context(role, received_peer_shared_context=None):
    """Each endpoint's own constant. The peer's value is deliberately never an input to it."""
    if role not in ROLE_CODES:
        raise ValueError(role)
    return SHARED_CONTEXT


def is_canonical_public_key(public_key):
    """Exactly a 91-byte uncompressed-point P-256 SPKI whose point is on the curve."""
    if len(public_key) != 91 or not public_key.startswith(SPKI_PREFIX):
        return False
    x = int.from_bytes(public_key[27:59], "big")
    y = int.from_bytes(public_key[59:91], "big")
    if x >= P256_P or y >= P256_P:
        return False
    return (y * y - (x * x * x - 3 * x + P256_B)) % P256_P == 0


def bootstrap_frame(application_identity_bytes, key_algorithm, public_key, shared_context):
    """The canonical P3 section 4 Bootstrap record: SASPAIR, u16be 1, 0x20, four u32be-length fields."""
    if not 1 <= len(application_identity_bytes) <= 1024 or not 1 <= len(key_algorithm) <= 64:
        raise ValueError("field bound")
    if not KEY_ALGORITHM_GRAMMAR.match(key_algorithm) or not 1 <= len(public_key) <= 4096:
        raise ValueError("field bound")
    if len(shared_context) > 8192:
        raise ValueError("field bound")
    out = b"SASPAIR" + struct.pack(">H", 1) + bytes([0x20])
    for field in (application_identity_bytes, key_algorithm, public_key, shared_context):
        out += struct.pack(">I", len(field)) + field
    if len(out) > 16384:
        raise ValueError("frame bound")
    return out


def local_bootstrap(role, uuid_text, public_key):
    if not is_canonical_public_key(public_key):
        raise ValueError("publicKey must be the canonical P-256 SPKI")
    return bootstrap_frame(application_identity(role, uuid_text), KEY_ALGORITHM, public_key,
                           local_shared_context(role))


def expected_peer_frame(own_role, peer_uuid_text, peer_public_key):
    """E-13: the frame the peer must have supplied, built only from candidate values and own state."""
    peer_role = "client" if own_role == "host" else "host"
    if not is_canonical_public_key(peer_public_key):
        raise ValueError("candidate publicKey is not the canonical P-256 SPKI")
    return bootstrap_frame(application_identity(peer_role, peer_uuid_text), KEY_ALGORITHM,
                           peer_public_key, local_shared_context(own_role))


def accept_authenticated_peer(authenticated_result_frame, expected_frame):
    """Exact equality of the whole canonical frame; never a field subset."""
    return bytes(authenticated_result_frame) == bytes(expected_frame)


def pending_authorization_key(result):
    """A pending DovahLink authorization is identified by the exact ceremony, nothing else."""
    return bytes(result["ceremony_identity"])


class PendingAuthorizations:
    """Test model: at most one live pending authorization per peer, each bound to its ceremony."""

    def __init__(self):
        self.by_key = {}

    def create(self, result, client_id):
        for key, entry in list(self.by_key.items()):
            if entry["client_id"] == client_id:
                del self.by_key[key]  # a new ceremony for the same peer supersedes the old attempt
        self.by_key[pending_authorization_key(result)] = {"client_id": client_id, "result": result}

    def pair(self, ceremony_identity):
        return self.by_key.pop(bytes(ceremony_identity), None) is not None


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def hx(value):
    return bytes.fromhex(value)


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = load_json(VECTORS)
        cls.vectors = {vector["id"]: vector for vector in cls.doc["vectors"]}
        cls.keys = {key["name"]: key for key in cls.doc["keys"]}
        cls.uuids = {entry["name"]: entry["text"] for entry in cls.doc["uuids"]}

    def key(self, name):
        return hx(self.keys[name]["spki_der"]["hex"])


class FrameEncoderAgainstFrozenCoreVector(Fixture):
    def test_encoder_reproduces_the_core_generated_p3_bootstrap_frames(self):
        p3 = load_json(P3_VECTOR)
        for role in ("initiator", "responder"):
            record = p3["bootstraps"][role]
            fields = [hx(record["fields"][name]["hex"]) for name in FIELD_NAMES]
            self.assertEqual(bootstrap_frame(*fields).hex(), record["hex"], role)


class MappingConstants(Fixture):
    def test_constants_are_the_frozen_bytes(self):
        constants = self.doc["constants"]
        self.assertEqual(constants["application_identity_domain"]["hex"], AI_DOMAIN.hex())
        self.assertEqual(constants["role_codes"], {"host": "01", "client": "02"})
        self.assertEqual(constants["application_identity_length"], 50)
        self.assertEqual(constants["key_algorithm"]["hex"], KEY_ALGORITHM.hex())
        self.assertRegex(KEY_ALGORITHM.decode("ascii"), r"^[a-z0-9][a-z0-9.-]*$")
        self.assertEqual(constants["p256_spki_prefix"]["hex"], SPKI_PREFIX.hex())
        self.assertEqual(constants["shared_context"]["hex"], SHARED_CONTEXT.hex())
        self.assertEqual(constants["authority_scope_domain"]["hex"], SCOPE_DOMAIN.hex())

    def test_mapping_is_binary_not_a_text_serialization(self):
        uuid_text = self.uuids["host-uuid"]
        for role in ("host", "client"):
            identity = application_identity(role, uuid_text)
            self.assertEqual(len(identity), 50)
            self.assertEqual(identity[:33], AI_DOMAIN)
            self.assertEqual(identity[33], ROLE_CODES[role])
            self.assertEqual(identity[34:], uuid_network_bytes(uuid_text))
            self.assertNotIn(uuid_text.encode("ascii"), identity)
            with self.assertRaises(ValueError):
                json.loads(identity.decode("latin-1"))
        for vector_id in ("V01", "V02"):
            fields = self.vectors[vector_id]["fields"]
            for name in FIELD_NAMES:
                value = hx(fields[name]["hex"])
                self.assertFalse(value.lstrip().startswith((b"{", b"[")), (vector_id, name))


class RoleVectors(Fixture):
    def check_bootstrap(self, vector_id, role, uuid_name, key_name):
        vector = self.vectors[vector_id]
        uuid_text = self.uuids[uuid_name]
        public_key = self.key(key_name)
        expected = {
            "application_identity": application_identity(role, uuid_text),
            "key_algorithm": KEY_ALGORITHM,
            "public_key": public_key,
            "shared_context": local_shared_context(role),
        }
        for name in FIELD_NAMES:
            self.assertEqual(vector["fields"][name]["hex"], expected[name].hex(), (vector_id, name))
            self.assertEqual(vector["fields"][name]["length"], len(expected[name]))
        frame = local_bootstrap(role, uuid_text, public_key)
        self.assertEqual(vector["canonical_bootstrap_frame"]["hex"], frame.hex())
        self.assertEqual(vector["canonical_bootstrap_frame"]["length"], len(frame))
        self.assertEqual(vector["canonical_bootstrap_frame"]["sha256"], hashlib.sha256(frame).hexdigest())
        self.assertLessEqual(len(frame), 16384)

    def test_host_bootstrap_vector(self):
        self.check_bootstrap("V01", "host", "host-uuid", "host-test-key")

    def test_client_bootstrap_vector(self):
        self.check_bootstrap("V02", "client", "client-uuid", "client-test-key")

    def test_same_uuid_in_both_roles_is_role_separated(self):
        vector = self.vectors["V03"]
        host = application_identity("host", vector["uuid"])
        client = application_identity("client", vector["uuid"])
        self.assertEqual(vector["host_application_identity_hex"], host.hex())
        self.assertEqual(vector["client_application_identity_hex"], client.hex())
        self.assertNotEqual(host, client)
        self.assertFalse(vector["expected_equal"])

    def test_two_different_keys(self):
        vector = self.vectors["V05"]
        self.assertEqual(vector["host_public_key_hex"], self.key("host-test-key").hex())
        self.assertEqual(vector["client_public_key_hex"], self.key("client-test-key").hex())
        self.assertNotEqual(vector["host_public_key_hex"], vector["client_public_key_hex"])
        self.assertNotEqual(self.vectors["V01"]["canonical_bootstrap_frame"]["hex"],
                            self.vectors["V02"]["canonical_bootstrap_frame"]["hex"])


class UuidByteOrder(Fixture):
    def test_rfc9562_network_order_and_dotnet_trap(self):
        vector = self.vectors["V04"]
        for case in vector["cases"]:
            canonical = uuid_network_bytes(case["uuid"])
            mixed = dotnet_guid_to_byte_array(case["uuid"])
            self.assertEqual(case["rfc9562_network_order_hex"], canonical.hex())
            self.assertEqual(case["dotnet_guid_to_byte_array_hex"], mixed.hex())
            self.assertNotEqual(canonical, mixed)
            self.assertEqual(case["host_application_identity_hex"], application_identity("host", case["uuid"]).hex())
            mixed_identity = AI_DOMAIN + bytes([ROLE_CODES["host"]]) + mixed
            self.assertEqual(case["mixed_endian_application_identity_hex_must_not_match"], mixed_identity.hex())
            self.assertNotEqual(mixed_identity, application_identity("host", case["uuid"]))

    def test_the_trap_uuid_is_the_endianness_shape(self):
        self.assertEqual(uuid_network_bytes("00112233-4455-6677-8899-aabbccddeeff").hex(),
                         "00112233445566778899aabbccddeeff")
        self.assertEqual(dotnet_guid_to_byte_array("00112233-4455-6677-8899-aabbccddeeff").hex(),
                         "33221100554477668899aabbccddeeff")

    def test_uuid_text_case_has_one_binary_form(self):
        lower = "00112233-4455-6677-8899-aabbccddeeff"
        self.assertEqual(application_identity("client", lower), application_identity("client", lower.upper()))
        for bad in ("{00112233-4455-6677-8899-aabbccddeeff}", "00112233445566778899aabbccddeeff",
                    "00000000-0000-0000-0000-000000000000"):
            with self.assertRaises(ValueError):
                uuid_network_bytes(bad)


class SharedContextIndependence(Fixture):
    def test_each_side_builds_the_same_bytes_from_its_own_constant(self):
        vector = self.vectors["V06"]
        self.assertEqual(vector["host_local_shared_context_hex"], local_shared_context("host").hex())
        self.assertEqual(vector["client_local_shared_context_hex"], local_shared_context("client").hex())
        self.assertTrue(vector["expected_equal"])

    def test_a_received_peer_value_never_becomes_the_local_context(self):
        hostile = b"attacker-chosen-context"
        for role in ("host", "client"):
            self.assertEqual(local_shared_context(role, received_peer_shared_context=hostile), SHARED_CONTEXT)
        policy = self.doc["model"]["shared_context_policy"]
        self.assertEqual(policy["host_source"], "local_constant")
        self.assertEqual(policy["client_source"], "local_constant")
        self.assertFalse(policy["copied_from_peer"])
        self.assertFalse(policy["fresh_attempt_contribution"])
        self.assertEqual(policy["fresh_attempt_identity"], "ceremony_identity")


class ExactFrameComparison(Fixture):
    """E-13: Option A, exact expected-frame comparison."""

    def test_candidate_values_rebuild_the_authenticated_frames(self):
        host_side = self.vectors["V12"]
        expected = expected_peer_frame("host", host_side["candidate_values"]["client_uuid"],
                                       hx(host_side["candidate_values"]["client_public_key_hex"]))
        self.assertEqual(host_side["authenticated_result_frame_hex"], self.vectors["V02"]["canonical_bootstrap_frame"]["hex"])
        self.assertTrue(accept_authenticated_peer(hx(host_side["authenticated_result_frame_hex"]), expected))
        client_side = self.vectors["V13"]
        expected = expected_peer_frame("client", client_side["candidate_values"]["host_uuid"],
                                       hx(client_side["candidate_values"]["host_public_key_hex"]))
        self.assertEqual(client_side["authenticated_result_frame_hex"], self.vectors["V01"]["canonical_bootstrap_frame"]["hex"])
        self.assertTrue(accept_authenticated_peer(hx(client_side["authenticated_result_frame_hex"]), expected))

    def negatives(self):
        vectors = [v for v in self.doc["vectors"] if v["kind"] == "negative_exact_frame_comparison"]
        vectors.append(self.vectors["V11"]["extra_contribution_frame_must_not_match"])
        return vectors

    def test_every_one_field_change_is_rejected(self):
        seen = set()
        for vector in self.negatives():
            authentic = [hx(vector["authenticated_fields_hex"][name]) for name in FIELD_NAMES]
            candidate = [hx(vector["candidate_fields_hex"][name]) for name in FIELD_NAMES]
            self.assertEqual(bootstrap_frame(*authentic).hex(), vector["authenticated_result_frame_hex"], vector["id"])
            self.assertEqual(bootstrap_frame(*candidate).hex(), vector["candidate_expected_frame_hex"], vector["id"])
            differing = [name for name, a, c in zip(FIELD_NAMES, authentic, candidate) if a != c]
            self.assertEqual(differing, [vector["differs_in"]], vector["id"])
            self.assertFalse(accept_authenticated_peer(hx(vector["authenticated_result_frame_hex"]),
                                                       hx(vector["candidate_expected_frame_hex"])), vector["id"])
            self.assertFalse(vector["expected_equal"])
            seen.add(vector["differs_in"])
        self.assertEqual(seen, set(FIELD_NAMES))

    def test_one_byte_anywhere_in_the_frame_is_rejected(self):
        frame = hx(self.vectors["V02"]["canonical_bootstrap_frame"]["hex"])
        for index in range(len(frame)):
            changed = bytearray(frame)
            changed[index] ^= 0x01
            self.assertFalse(accept_authenticated_peer(bytes(changed), frame), index)
        self.assertFalse(accept_authenticated_peer(frame + b"\x00", frame))
        self.assertFalse(accept_authenticated_peer(frame[:-1], frame))

    def test_strategy_is_exact_whole_frame_comparison(self):
        consumption = self.doc["model"]["peer_bootstrap_consumption"]
        self.assertEqual(consumption["strategy"], "exact_expected_frame_comparison")
        self.assertEqual(consumption["consumer_decoder"], "none")
        self.assertEqual(consumption["wrapper_change"], "none")
        self.assertEqual(consumption["abi_change"], "none")
        self.assertFalse(consumption["partial_field_acceptance"])

    def test_attempt_context_vector_is_explicitly_not_applicable(self):
        vector = self.vectors["V11"]
        self.assertFalse(vector["applicable"])
        self.assertIn("ceremony_identity", vector["reason"])


class PublicKeyContract(Fixture):
    def test_every_bootstrap_public_key_is_the_full_canonical_spki(self):
        for vector_id in ("V01", "V02"):
            public_key = hx(self.vectors[vector_id]["fields"]["public_key"]["hex"])
            self.assertTrue(is_canonical_public_key(public_key), vector_id)
        for key in self.doc["keys"]:
            public_key = hx(key["spki_der"]["hex"])
            self.assertTrue(is_canonical_public_key(public_key), key["name"])
            digest = hashlib.sha256(public_key).digest()
            self.assertEqual(key["spki_sha256_hex"], digest.hex())
            self.assertEqual(key["fingerprint_base64url"], base64.urlsafe_b64encode(digest).rstrip(b"=").decode())
            self.assertFalse(is_canonical_public_key(digest), "a fingerprint is never a verification key")

    def test_fingerprint_or_compressed_point_is_not_a_public_key(self):
        compressed = hx(self.vectors["V15"]["compressed_spki_hex"])
        self.assertEqual(len(compressed), 59)
        self.assertFalse(is_canonical_public_key(compressed))
        self.assertFalse(self.vectors["V15"]["expected_valid"])
        with self.assertRaises(ValueError):
            local_bootstrap("client", self.uuids["client-uuid"], hashlib.sha256(self.key("client-test-key")).digest())


class NoSecretsInBootstrap(Fixture):
    BEARER_SHAPE = re.compile(rb"[0-9a-f]{32}")

    def test_bootstrap_fields_carry_no_secret_material(self):
        scalars = [hx(key["private_scalar_hex"]) for key in self.doc["keys"]]
        for vector_id in ("V01", "V02"):
            for name in FIELD_NAMES:
                value = hx(self.vectors[vector_id]["fields"][name]["hex"])
                for scalar in scalars:
                    self.assertNotIn(scalar, value, (vector_id, name))
                    self.assertNotIn(scalar.hex().encode(), value, (vector_id, name))
                if name != "public_key":
                    self.assertIsNone(self.BEARER_SHAPE.search(value), (vector_id, name))
        self.assertTrue(self.doc["model"]["bootstrap_secret_policy"]["fields_are_public"])
        self.assertIn("trusted_device_credential", self.doc["model"]["bootstrap_secret_policy"]["forbidden_contents"])


class NetworkLocationIsNotIdentity(Fixture):
    LOCATION = re.compile(rb"(\d{1,3}\.){3}\d{1,3}|localhost|::1|:\d{2,5}\b|ws{1,2}://")

    def test_identity_and_context_bytes_name_no_location(self):
        for value in (AI_DOMAIN, SHARED_CONTEXT, SCOPE_DOMAIN, KEY_ALGORITHM):
            self.assertIsNone(self.LOCATION.search(value), value)
        for vector_id in ("V01", "V02"):
            for name in ("application_identity", "shared_context"):
                self.assertIsNone(self.LOCATION.search(hx(self.vectors[vector_id]["fields"][name]["hex"])))

    def test_durable_identity_never_includes_an_endpoint(self):
        fields = self.doc["model"]["durable_identity_fields"]
        location_words = ("endpoint", "address", "port", "ip", "socket", "listener")
        for name in fields["known_device"]:
            self.assertFalse(any(word in name for word in location_words), name)
        for name in fields["known_host"]:
            if any(word in name for word in location_words):
                self.assertIn(name, fields["routing_only_fields"])
        self.assertIn("network_location", self.doc["model"]["pending_authorization"]["never_authority"])


class AuthorityScope(Fixture):
    def test_scopes_come_from_local_installation_identity_only(self):
        vector = self.vectors["V14"]
        self.assertEqual(vector["host_scope_hex"], authority_scope("host", self.uuids["host-uuid"]).hex())
        self.assertEqual(vector["client_scope_hex"], authority_scope("client", self.uuids["client-uuid"]).hex())
        self.assertNotEqual(vector["same_uuid_host_scope_hex"], vector["same_uuid_client_scope_hex"])
        self.assertNotEqual(authority_scope("host", self.uuids["host-uuid"]),
                            application_identity("host", self.uuids["host-uuid"]))


class AttemptAuthority(Fixture):
    def result(self, ceremony, request_id=b"\x00" * 16):
        return {"ceremony_identity": ceremony, "request_id": request_id}

    def test_request_id_is_never_the_authorization_key(self):
        model = self.doc["model"]["pending_authorization"]
        self.assertEqual(model["authority_key"], "ceremony_identity")
        for forbidden in ("request_id", "client_id_alone", "host_id_alone", "shared_context"):
            self.assertIn(forbidden, model["never_authority"])
        same_request = b"\x11" * 16
        first = self.result(b"\xaa" * 32, same_request)
        second = self.result(b"\xbb" * 32, same_request)
        self.assertNotEqual(pending_authorization_key(first), pending_authorization_key(second))
        pending = PendingAuthorizations()
        pending.create(first, client_id="client-a")
        pending.create(second, client_id="client-b")
        self.assertFalse(pending.pair(same_request))

    def test_a_stale_approval_cannot_authorize_a_replacement_ceremony(self):
        pending = PendingAuthorizations()
        pending.create(self.result(b"\x01" * 32), client_id="client-a")
        pending.create(self.result(b"\x02" * 32), client_id="client-a")
        self.assertFalse(pending.pair(b"\x01" * 32), "approval of the superseded ceremony")
        self.assertTrue(pending.pair(b"\x02" * 32))
        self.assertFalse(pending.pair(b"\x02" * 32), "an approval is consumed once")

    def test_pending_record_names_its_exact_evidence(self):
        fields = self.doc["model"]["pending_authorization"]["required_fields"]
        for required in ("ceremony_identity", "authenticated_peer_bootstrap_frame", "peer_public_key",
                         "proof_of_possession_verified", "security_fence_generation", "expires_at"):
            self.assertIn(required, fields)


class StateModel(Fixture):
    def setUp(self):
        self.model = self.doc["model"]["state_model"]
        self.edges = {tuple(edge) for edge in self.model["transitions"]}

    def reachable_without(self, start, goal, banned):
        frontier, seen = [start], {start}
        while frontier:
            state = frontier.pop()
            for source, target in self.edges:
                if source == state and target not in seen and target not in banned:
                    if target == goal:
                        return True
                    seen.add(target)
                    frontier.append(target)
        return False

    def test_local_result_never_becomes_trust_directly(self):
        local = self.model["local_result_state"]
        self.assertEqual(local, "SasCeremonyCompletedLocally")
        self.assertEqual(self.model["durable_trust_written_only_in"], ["Paired"])
        for gate in ("PeerBootstrapVerified", "ProofOfPossessionVerified", "PendingPairingAuthorization"):
            self.assertFalse(self.reachable_without(local, "Paired", {gate}), gate)
        self.assertNotIn((local, "Paired"), self.edges)
        self.assertIn("SasCeremonyCompletedLocally", self.model["states"])
        self.assertIn("PendingPairingAuthorization", self.model["states"])

    def test_initial_pairing_and_normal_reconnect_are_separate(self):
        initial = self.doc["model"]["initial_pairing_flow"]
        reconnect = self.doc["model"]["normal_reconnect_flow"]
        self.assertIn("sas_pairing_ceremony", initial)
        self.assertLess(initial.index("local_pairing_result"), initial.index("pending_pairing_authorization"))
        self.assertLess(initial.index("client_pairing_proof_of_possession"), initial.index("pending_pairing_authorization"))
        self.assertLess(initial.index("pair_reject_block"), initial.index("durable_trust"))
        self.assertFalse(any("sas" in step for step in reconnect))
        self.assertEqual(reconnect[0], "pinned_host_verification")
        self.assertIn("client_proof_of_possession", reconnect)
        self.assertEqual(self.doc["model"]["role_assignment"], {"initiator": "client", "responder": "host"})


def audit_matrix_rows():
    """The `| Property | Current mechanism | Evidence | Meets P10 target? | Required change |` table."""
    rows = {}
    in_table = False
    for line in read(AUDIT_DOC).splitlines():
        if line.startswith("| Property | Current mechanism | Evidence | Meets P10 target? | Required change |"):
            in_table = True
            continue
        if in_table:
            if not line.startswith("|"):
                break
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if set(cells[0]) <= {"-", ":"}:
                continue
            rows[cells[0]] = cells
    return rows


class AuthenticationAudit(Fixture):
    def test_bearer_material_is_never_proof_of_possession(self):
        for item in self.doc["authentication_audit"]["properties"]:
            if item["mechanism_class"] in ("bearer", "bearer_verifier", "unauthenticated_claim", "absent"):
                self.assertFalse(item["provides_possession_proof"], item["property"])
                self.assertFalse(item["meets_target"], item["property"])
            self.assertEqual(item["label"], "CURRENT")
        self.assertFalse(any(item["provides_possession_proof"] for item in self.doc["authentication_audit"]["properties"]))

    def test_target_design_is_not_current_implementation(self):
        audit = self.doc["authentication_audit"]
        self.assertEqual(audit["current_long_term_keys"], {"host": False, "client": False})
        for item in audit["target_design"]:
            self.assertIn(item["label"], ("TARGET-DESIGN", "P10-DECISION"))
            self.assertNotIn("implemented", item["status"].replace("unimplemented", ""), item["item"])
        text = read(AUDIT_DOC)
        self.assertGreaterEqual(text.count("DESIGN EXISTS — IMPLEMENTATION DOES NOT"), 2)

    def test_verdict_follows_from_the_matrix(self):
        audit = self.doc["authentication_audit"]
        core = ("Host authentication", "Client authentication", "Private-key possession", "Replay resistance",
                "Session freshness", "Credential cloning resistance")
        failing = [item["property"] for item in audit["properties"] if item["property"] in core and not item["meets_target"]]
        self.assertTrue(failing)
        self.assertEqual(audit["verdict"], "REPLACEMENT_REQUIRED")
        text = read(AUDIT_DOC)
        self.assertIn("**Verdict: 🔴 DOES NOT PROVIDE ADEQUATE AUTHENTICATION — REPLACEMENT REQUIRED**", text)
        self.assertNotIn("**Verdict: ✅", text)
        self.assertNotIn("**Verdict: 🟡", text)

    def test_audit_document_matrix_matches_the_model(self):
        rows = audit_matrix_rows()
        properties = self.doc["authentication_audit"]["properties"]
        self.assertEqual(set(rows), {item["property"] for item in properties})
        for item in properties:
            cells = rows[item["property"]]
            meets = cells[3]
            self.assertTrue(meets.startswith("Yes" if item["meets_target"] else "No"), item["property"])
            if item["mechanism_class"] in ("bearer", "bearer_verifier"):
                self.assertNotRegex(cells[1].lower(), r"proof[- ]of[- ]possession|signature|ecdsa")


class Documents(Fixture):
    def test_mapping_document_carries_the_exact_bytes(self):
        text = read(MAPPING_DOC)
        for value in (AI_DOMAIN.hex(), KEY_ALGORITHM.hex(), SHARED_CONTEXT.hex(), SPKI_PREFIX.hex(),
                      SCOPE_DOMAIN.hex(), self.vectors["V01"]["canonical_bootstrap_frame"]["sha256"],
                      self.vectors["V02"]["canonical_bootstrap_frame"]["sha256"]):
            self.assertIn(value, text)
        self.assertIn("DovahLink consumer mapping vectors", text)

    def test_decisions_are_recorded(self):
        text = read(DECISIONS_DOC)
        self.assertIn("## P10-D-002 — Canonical DovahLink Bootstrap v1 Mapping", text)
        self.assertIn("## P10-D-003 — DovahLink Authentication Disposition and PoP Boundary", text)

    def test_vector_file_is_labelled_consumer_mapping(self):
        metadata = self.doc["metadata"]
        self.assertEqual(metadata["kind"], "DovahLink consumer mapping vectors")
        self.assertIn("NOT sas-pairing PROTOCOL-CONFORMANCE VECTORS", metadata["status"])
        self.assertEqual(metadata["decision"], "P10-D-002")


if __name__ == "__main__":
    unittest.main()
