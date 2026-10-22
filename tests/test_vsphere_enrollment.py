"""Exercise the read-only vCenter client-certificate discovery boundary."""

from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from atlaso.app.services import vsphere_enrollment as enrollment


def _client_certificate() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vcsa.example.test")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


class _FakeVcenter:
    def __init__(
        self, certificate: str, *, endpoint: str = "kms.atlaso.example.test",
        cluster_id: str = "Atlaso-KMIP",
    ) -> None:
        """Initialize public identity and cluster responses for the fake vCenter.

        Args:
            certificate: Public certificate returned by the fake vCenter.
            endpoint: KMIP hostname registered in the fake cluster.
            cluster_id: Exact cluster name returned by the fake inventory.
        """
        self.certificate = certificate
        self.endpoint = endpoint
        self.cluster_id = cluster_id
        self.clusters = [
            {
                "clusterId": {"id": cluster_id},
                "servers": [{"address": endpoint, "port": 5696}],
            }
        ]
        self.headers: dict[str, str] = {}
        self.calls: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        """Close the fake session without suppressing exceptions.

        Args:
            *_args: Context-manager exception details ignored by the fake session.
        """
        pass

    def get(self, path: str) -> httpx.Response:
        """Return the fake managed-object service metadata.

        Args:
            path: Request or snapshot path being exercised.
        """
        self.calls.append(path)
        return httpx.Response(
            200,
            json={
                "sessionManager": {"type": "SessionManager", "value": "SessionManager"},
                "cryptoManager": {
                    "type": "CryptoManagerKmip",
                    "value": "CryptoManager",
                },
            },
        )

    def post(self, path: str, *, json=None) -> httpx.Response:
        """Emulate login, cluster discovery, certificate retrieval, and logout.

        Args:
            path: Request or snapshot path being exercised.
            json: Request payload inspected by the fake vCenter.
        """
        self.calls.append(path)
        if path.endswith("/Login"):
            assert json == {"userName": "admin", "password": "test-secret"}
            return httpx.Response(
                200, json={}, headers={"vmware-api-session-id": "opaque-session"}
            )
        if path.endswith("/ListKmsClusters"):
            assert self.headers["vmware-api-session-id"] == "opaque-session"
            return httpx.Response(
                200,
                json=self.clusters,
            )
        if path.endswith("/RetrieveClientCert"):
            assert json == {
                "cluster": {"_typeName": "KeyProviderId", "id": self.cluster_id}
            }
            return httpx.Response(200, json=self.certificate)
        if path.endswith("/Logout"):
            return httpx.Response(204)
        raise AssertionError(path)


class _FakeInventoryVcenter:
    def __init__(self, clusters: object) -> None:
        """Initialize a synthetic authenticated inventory session.

        Args:
            clusters: Synthetic cluster response returned by the fake vCenter.
        """
        self.clusters = clusters
        self.instance_options = [{
            "key": "VirtualCenter.InstanceName",
            "value": {"_typeName": "string", "_value": "Configured Lab vCenter"},
        }]
        self.headers: dict[str, str] = {}
        self.calls: list[tuple[str, object]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        """Close the synthetic inventory session.

        Args:
            *_args: Context-manager exception details ignored by the fake session.
        """
        pass

    def get(self, path: str) -> httpx.Response:
        """Return service metadata with distinct display and instance identities.

        Args:
            path: Requested service resource or session operation path.
        """
        self.calls.append((path, None))
        return httpx.Response(
            200,
            json={
                "sessionManager": {"type": "SessionManager", "value": "SessionManager"},
                "cryptoManager": {"type": "CryptoManagerKmip", "value": "CryptoManager"},
                "setting": {"type": "OptionManager", "value": "VpxSettings"},
                "about": {
                    "name": "VMware vCenter Server",
                    "instanceUuid": "stable-instance-uuid",
                },
            },
        )

    def post(self, path: str, *, json=None) -> httpx.Response:
        """Emulate authenticated inventory operations and logout.

        Args:
            path: Requested service resource or session operation path.
            json: Request body supplied by the discovery service.
        """
        self.calls.append((path, json))
        if path.endswith("/Login"):
            return httpx.Response(
                200, json={}, headers={"vmware-api-session-id": "opaque-session"}
            )
        if path.endswith("/QueryOptions"):
            assert self.headers["vmware-api-session-id"] == "opaque-session"
            assert path.endswith("/OptionManager/VpxSettings/QueryOptions")
            assert json == {"name": "VirtualCenter.InstanceName"}
            return httpx.Response(200, json=self.instance_options)
        if path.endswith("/ListKmsClusters"):
            assert self.headers["vmware-api-session-id"] == "opaque-session"
            return httpx.Response(200, json=self.clusters)
        if path.endswith("/Logout"):
            return httpx.Response(204)
        raise AssertionError(path)


def _prepare_inventory_fake(monkeypatch, fake: _FakeInventoryVcenter) -> None:
    """Replace network operations with one synthetic inventory session.

    Args:
        monkeypatch: Fixture replacing external TLS and HTTP dependencies.
        fake: Synthetic inventory session providing the test responses.
    """
    monkeypatch.setattr(
        enrollment, "vcenter_https_leaf", lambda _host, **_kwargs: b"test-https-leaf"
    )
    monkeypatch.setattr(enrollment, "_pinned_context", lambda _leaf: object())
    monkeypatch.setattr(enrollment.httpx, "Client", lambda **_kwargs: fake)


def _discover_inventory() -> enrollment.DiscoveredInventory:
    return enrollment.discover_vcenter_inventory(
        host="vcsa.example.test",
        port=8443,
        username="admin",
        password="test-secret",
        confirmed_https_fingerprint=enrollment.certificate_fingerprint(
            b"test-https-leaf"
        ),
    )


def test_inventory_returns_configured_instance_name_and_all_unfiltered_cluster_ids(monkeypatch) -> None:
    """Retain every cluster and use the configured name instead of product/host/UUID.

    Args:
        monkeypatch: Fixture replacing external TLS and HTTP dependencies.
    """
    clusters = [
        {"clusterId": {"id": "Atlaso-KMIP"}, "managementType": "VC_MANAGED"},
        {"clusterId": {"id": "External-KMIP"}, "managementType": "TRUSTED"},
        {"clusterId": {"id": "Inactive-KMIP"}, "status": "INACTIVE"},
        {"clusterId": {"id": "Cluster with spaces"}},
    ]
    fake = _FakeInventoryVcenter(clusters)
    _prepare_inventory_fake(monkeypatch, fake)

    result = _discover_inventory()

    assert result == enrollment.DiscoveredInventory(
        name="Configured Lab vCenter",
        cluster_ids=("Atlaso-KMIP", "External-KMIP", "Inactive-KMIP", "Cluster with spaces"),
    )
    list_call = next(call for call in fake.calls if call[0].endswith("/ListKmsClusters"))
    assert list_call[1] == {"includeKmsServers": False}
    assert any(path.endswith("/Logout") for path, _ in fake.calls)


def test_inventory_accepts_empty_cluster_inventory(monkeypatch) -> None:
    """Accept an explicitly empty successful inventory.

    Args:
        monkeypatch: Fixture replacing external TLS and HTTP dependencies.
    """
    fake = _FakeInventoryVcenter([])
    _prepare_inventory_fake(monkeypatch, fake)

    assert _discover_inventory().cluster_ids == ()


@pytest.mark.parametrize("options", [
    None, {}, [], [{"key": "other", "value": {"_typeName": "string", "_value": "wrong"}}],
    [{"key": "VirtualCenter.InstanceName", "value": "untyped"}],
    [{"key": "VirtualCenter.InstanceName", "value": {"_typeName": "int", "_value": 1}}],
    *[[{"key": "VirtualCenter.InstanceName", "value": {"_typeName": "string", "_value": value}}]
      for value in [None, "", "  ", "x" * 121, "bad\nname", "bad\x7fname"]],
    [{"key": "VirtualCenter.InstanceName"}] * 2,
])
def test_unavailable_instance_name_keeps_clusters_without_identity_substitution(monkeypatch, options) -> None:
    """Never substitute product, endpoint or UUID for an unavailable instance name.

    Args:
        monkeypatch: Fixture replacing external TLS and HTTP dependencies.
        options: Malformed or unavailable configured-name response.
    """
    fake = _FakeInventoryVcenter([{"clusterId": {"id": "Keep this cluster"}}])
    fake.instance_options = options
    _prepare_inventory_fake(monkeypatch, fake)
    assert _discover_inventory() == enrollment.DiscoveredInventory("", ("Keep this cluster",))
    assert fake.calls[-1][0].endswith("/Logout")


@pytest.mark.parametrize("failure", ["denied", "transport", "missing_reference"])
def test_instance_name_read_failure_preserves_cluster_discovery(monkeypatch, failure) -> None:
    """Allow honest manual naming when the settings read is unavailable.

    Args:
        monkeypatch: Fixture replacing external TLS and HTTP dependencies.
        failure: Settings failure category to exercise.
    """
    fake = _FakeInventoryVcenter([{"clusterId": {"id": "Keep"}}])
    original_post, original_get = fake.post, fake.get

    def post(path, *, json=None):
        """Fail only the optional settings query.

        Args:
            path: Requested VI JSON resource.
            json: Request body for the operation.
        """
        if path.endswith("/QueryOptions"):
            if failure == "transport":
                raise httpx.ReadTimeout("private remote error")
            return httpx.Response(403, json={"message": "private remote error"})
        return original_post(path, json=json)

    def get(path):
        """Optionally omit the settings manager reference.

        Args:
            path: Requested service metadata resource.
        """
        response = original_get(path)
        if failure == "missing_reference":
            content = response.json()
            del content["setting"]
            return httpx.Response(200, json=content)
        return response

    fake.post, fake.get = post, get
    _prepare_inventory_fake(monkeypatch, fake)
    assert _discover_inventory() == enrollment.DiscoveredInventory("", ("Keep",))
    assert fake.calls[-1][0].endswith("/Logout")


@pytest.mark.parametrize(
    "clusters",
    [
        {"clusterId": {"id": "not-a-list"}},
        [{"clusterId": {"id": "valid"}}, {"clusterId": None}],
        [{"clusterId": {"id": "bad\nid"}}],
        [{"clusterId": {"id": " "}}],
        [{"clusterId": {"id": "duplicate"}}, {"clusterId": {"id": "duplicate"}}],
    ],
)
def test_inventory_rejects_malformed_or_ambiguous_clusters(monkeypatch, clusters) -> None:
    """Reject incomplete inventory rather than returning misleading choices.

    Args:
        monkeypatch: Fixture replacing external TLS and HTTP dependencies.
        clusters: Synthetic cluster response returned by the fake vCenter.
    """
    fake = _FakeInventoryVcenter(clusters)
    _prepare_inventory_fake(monkeypatch, fake)

    with pytest.raises(enrollment.EnrollmentError, match="KMIP cluster"):
        _discover_inventory()

    assert any(path.endswith("/Logout") for path, _ in fake.calls)


def test_inventory_rejects_vcenter_api_error_and_logs_out(monkeypatch) -> None:
    """Keep API errors distinct from empty inventory and release the session.

    Args:
        monkeypatch: Fixture replacing external TLS and HTTP dependencies.
    """
    fake = _FakeInventoryVcenter([])

    def failing_post(path: str, *, json=None) -> httpx.Response:
        """Reject only the cluster inventory operation.

        Args:
            path: Requested service resource or session operation path.
            json: Request body supplied by the discovery service.
        """
        if path.endswith("/ListKmsClusters"):
            fake.calls.append((path, json))
            return httpx.Response(403, json={"value": {"message": "denied"}})
        return _FakeInventoryVcenter.post(fake, path, json=json)

    fake.post = failing_post
    _prepare_inventory_fake(monkeypatch, fake)

    with pytest.raises(enrollment.EnrollmentError, match="discovery request failed"):
        _discover_inventory()

    assert any(path.endswith("/Logout") for path, _ in fake.calls)


def test_inventory_fingerprint_mismatch_precedes_session_or_credentials(monkeypatch) -> None:
    """Reject changed TLS identity before opening an authenticated session.

    Args:
        monkeypatch: Fixture replacing external TLS and HTTP dependencies.
    """
    monkeypatch.setattr(
        enrollment, "vcenter_https_leaf", lambda _host, **_kwargs: b"new-https-leaf"
    )
    monkeypatch.setattr(
        enrollment,
        "httpx",
        type("NoHttpClient", (), {"Client": staticmethod(lambda **_kwargs: pytest.fail("authenticated"))}),
    )

    with pytest.raises(enrollment.EnrollmentError, match="fingerprint differs"):
        enrollment.discover_vcenter_inventory(
            host="vcsa.example.test",
            username="admin",
            password="test-secret",
            confirmed_https_fingerprint=enrollment.certificate_fingerprint(b"old-https-leaf"),
        )


@pytest.mark.parametrize("cluster_id", ["Atlaso-KMIP", "Cluster with spaces"])
def test_discovery_reads_only_registered_atlaso_cluster_and_logs_out(
    monkeypatch, cluster_id,
) -> None:
    """Verify discovery checks the registered Atlaso endpoint and logs out.

    Args:
        monkeypatch: Fixture replacing vCenter network calls.
        cluster_id: Exact discovered cluster identifier, including spaces.
    """
    pem = _client_certificate()
    fake = _FakeVcenter(pem, cluster_id=cluster_id)
    monkeypatch.setattr(
        enrollment, "vcenter_https_leaf", lambda _host, **_kwargs: b"test-https-leaf"
    )
    monkeypatch.setattr(enrollment, "_pinned_context", lambda _leaf: object())
    def client_factory(**kwargs):
        """Check the saved port reaches the pinned HTTP client.

        Args:
            **kwargs: HTTP client configuration.
        """
        assert kwargs["base_url"] == "https://vcsa.example.test:8443"
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        return fake

    monkeypatch.setattr(enrollment.httpx, "Client", client_factory)

    result = enrollment.discover_vcenter_client(
        host="vcsa.example.test",
        port=8443,
        cluster_id=cluster_id,
        username="admin",
        password="test-secret",
        confirmed_https_fingerprint=enrollment.certificate_fingerprint(
            b"test-https-leaf"
        ),
        atlaso_host="kms.atlaso.example.test",
        atlaso_port=5696,
    )

    assert result.certificate_pem == pem
    assert (
        result.fingerprint_sha256
        == x509.load_pem_x509_certificate(pem.encode())
        .fingerprint(hashes.SHA256())
        .hex()
    )
    assert any(path.endswith("/Logout") for path in fake.calls)


def test_discovery_rejects_wrong_atlaso_endpoint_before_client_certificate(
    monkeypatch,
) -> None:
    """Reject a cluster targeting another endpoint before reading its certificate.

    Args:
        monkeypatch: Fixture replacing vCenter network calls.
    """
    fake = _FakeVcenter(_client_certificate(), endpoint="other.example.test")
    monkeypatch.setattr(
        enrollment, "vcenter_https_leaf", lambda _host, **_kwargs: b"test-https-leaf"
    )
    monkeypatch.setattr(enrollment, "_pinned_context", lambda _leaf: object())
    monkeypatch.setattr(enrollment.httpx, "Client", lambda **_kwargs: fake)

    with pytest.raises(enrollment.EnrollmentError, match="does not point only"):
        enrollment.discover_vcenter_client(
            host="vcsa.example.test",
            cluster_id="Atlaso-KMIP",
            username="admin",
            password="test-secret",
            confirmed_https_fingerprint=enrollment.certificate_fingerprint(
                b"test-https-leaf"
            ),
            atlaso_host="kms.atlaso.example.test",
            atlaso_port=5696,
        )
    assert not any(path.endswith("/RetrieveClientCert") for path in fake.calls)
    assert fake.calls[-1].endswith("/Logout")


@pytest.mark.parametrize(
    "servers",
    [
        [], None, {"address": "kms.atlaso.example.test"}, [None],
        [{"address": "192.168.1.254", "port": 5696}],
        [{"address": "alias.example.test", "port": 5696}],
        [{"address": "kms.atlaso.example.test", "port": 5696},
         {"address": "foreign.example.test", "port": 5696}],
        [{"address": "kms.atlaso.example.test", "port": 5697}],
        [{"address": "kms.atlaso.example.test", "port": "5696"}],
        [{"address": "kms.atlaso.example.test", "port": True}],
        [{"address": "kms.atlaso.example.test", "port": None}],
        [{"address": "kms.atlaso.example.test", "port": 65536}],
        [{"address": "https://user:private-marker@other.test", "port": "private-marker",
          "name": "private-marker", "userName": "private-marker"}],
        [{"address": "<script>private-marker</script>", "port": 5696}],
        [{"address": "fe80::1%private-marker", "port": 5696}],
        [{"address": "a" * 254, "port": 5696}],
        [{"address": "private-marker.example.test", "port": 61337}],
    ],
)
def test_endpoint_diagnostics_reject_before_certificate_and_keep_logout(monkeypatch, servers) -> None:
    """Return actionable bounded errors without exposing untrusted remote fields.

    Args:
        monkeypatch: Fixture replacing the pinned vCenter session.
        servers: Selected cluster inventory exercising one rejection reason.
    """
    fake = _FakeVcenter(_client_certificate())
    fake.clusters[0]["servers"] = servers
    monkeypatch.setattr(enrollment, "vcenter_https_leaf", lambda *_args, **_kwargs: b"test-leaf")
    monkeypatch.setattr(enrollment, "_pinned_context", lambda _leaf: object())
    monkeypatch.setattr(enrollment.httpx, "Client", lambda **_kwargs: fake)
    with pytest.raises(enrollment.EnrollmentError) as error:
        enrollment.discover_vcenter_client(
            host="vcsa.example.test", cluster_id="Atlaso-KMIP", username="admin", password="test-secret",
            confirmed_https_fingerprint=enrollment.certificate_fingerprint(b"test-leaf"),
            atlaso_host="kms.atlaso.example.test", atlaso_port=5696,
        )
    message = str(error.value)
    assert "Expected configured Atlaso endpoint: kms.atlaso.example.test, port 5696" in message
    with pytest.raises(enrollment.EnrollmentError) as empty_inventory:
        enrollment._check_cluster_endpoint([], "kms.atlaso.example.test", 5696)
    assert message == str(empty_inventory.value)
    assert "then retry" in message
    assert "private-marker" not in message
    assert "61337" not in message
    assert not any(path.endswith("/RetrieveClientCert") for path in fake.calls)
    assert fake.calls[-1].endswith("/Logout")


def test_endpoint_diagnostic_does_not_vary_with_remote_inventory() -> None:
    """Withhold remote counts, positions, field choices and malformed-data details."""
    matching = {"address": "KMS.ATLASO.EXAMPLE.TEST.", "port": 5696}
    foreign = {"address": "private-marker.example.test", "port": 61337}
    enrollment._check_cluster_endpoint([matching, matching], "kms.atlaso.example.test", 5696)
    messages = []
    for servers in [None, [], {}, [None], [foreign], [matching] * 1234 + [foreign],
                    [foreign] * 1234, [foreign, matching],
                    [{"address": "kms.atlaso.example.test", "port": 61337}],
                    [{"address": "private-marker.example.test", "port": 5696}]]:
        with pytest.raises(enrollment.EnrollmentError) as error:
            enrollment._check_cluster_endpoint(servers, "kms.atlaso.example.test", 5696)
        messages.append(str(error.value))
    assert len(set(messages)) == 1
    assert "private-marker" not in messages[0]
    assert "61337" not in messages[0]
    assert "1234" not in messages[0]
    assert "member 1" not in messages[0]
    assert "address differs" not in messages[0]
    assert "port differs" not in messages[0]


@pytest.mark.parametrize("address", ["192.168.1.254", "2001:0db8:0:0:0:0:0:254"])
def test_matching_label_with_admitted_listener_ip_reads_public_client(monkeypatch, address) -> None:
    """The actual name/address split succeeds only with independent IP admission.

    Args:
        monkeypatch: Fixture replacing the vCenter TLS and HTTP connection.
        address: Registered IPv4 or noncanonical IPv6 transport address.
    """
    from ipaddress import ip_address

    fake = _FakeVcenter(_client_certificate())
    fake.clusters[0]["servers"] = [{
        "name": "kms.atlaso.example.test", "address": address, "port": 5696,
    }]
    monkeypatch.setattr(enrollment, "vcenter_https_leaf", lambda *_args, **_kwargs: b"test-leaf")
    monkeypatch.setattr(enrollment, "_pinned_context", lambda _leaf: object())
    monkeypatch.setattr(enrollment.httpx, "Client", lambda **_kwargs: fake)
    result = enrollment.discover_vcenter_client(
        host="vcsa.example.test", cluster_id="Atlaso-KMIP", username="admin", password="test-secret",
        confirmed_https_fingerprint=enrollment.certificate_fingerprint(b"test-leaf"),
        atlaso_host="kms.atlaso.example.test", atlaso_port=5696,
        listener_addresses=frozenset({str(ip_address(address))}),
    )
    assert result.cluster_id == "Atlaso-KMIP"
    assert any(path.endswith("/RetrieveClientCert") for path in fake.calls)


@pytest.mark.parametrize("servers", [
    [{"name": "kms.atlaso.example.test", "address": "192.168.1.253", "port": 5696}],
    [{"name": "kms.atlaso.example.test", "address": "192.168.1.254", "port": 5697}],
    [{"address": "192.168.1.254", "port": 5696}, {"address": "192.168.1.253", "port": 5696}],
    [{"address": "192.168.1.254", "port": 5696}, {"address": "192.168.1.254", "port": True}],
])
def test_ip_admission_never_weakens_all_member_address_and_exact_port_checks(servers) -> None:
    """A matching server name and one admitted member cannot admit foreign members.

    Args:
        servers: Remote member inventory containing a foreign address or invalid port.
    """
    with pytest.raises(enrollment.EnrollmentError, match="does not point only"):
        enrollment._check_cluster_endpoint(
            servers, "kms.atlaso.example.test", 5696, listener_addresses=frozenset({"192.168.1.254"}),
        )


@pytest.mark.parametrize("ambiguous", [False, True])
def test_discovery_keeps_missing_and_ambiguous_cluster_rejections(monkeypatch, ambiguous) -> None:
    """Never inspect a client certificate when the cluster identity is uncertain.

    Args:
        monkeypatch: Fixture replacing the pinned vCenter session.
        ambiguous: Whether to supply duplicate clusters instead of no cluster.
    """
    fake = _FakeVcenter(_client_certificate())
    fake.clusters = fake.clusters * 2 if ambiguous else []
    monkeypatch.setattr(enrollment, "vcenter_https_leaf", lambda *_args, **_kwargs: b"test-leaf")
    monkeypatch.setattr(enrollment, "_pinned_context", lambda _leaf: object())
    monkeypatch.setattr(enrollment.httpx, "Client", lambda **_kwargs: fake)
    with pytest.raises(enrollment.EnrollmentError, match="missing or ambiguous"):
        enrollment.discover_vcenter_client(
            host="vcsa.example.test", cluster_id="Atlaso-KMIP", username="admin", password="test-secret",
            confirmed_https_fingerprint=enrollment.certificate_fingerprint(b"test-leaf"),
            atlaso_host="kms.atlaso.example.test", atlaso_port=5696,
        )
    assert not any(path.endswith("/RetrieveClientCert") for path in fake.calls)
    assert fake.calls[-1].endswith("/Logout")


def test_discovery_rejects_changed_https_identity_before_authentication(
    monkeypatch,
) -> None:
    """Reject a changed HTTPS identity before sending credentials.

    Args:
        monkeypatch: Fixture replacing vCenter network calls.
    """
    monkeypatch.setattr(
        enrollment, "vcenter_https_leaf", lambda _host, **_kwargs: b"unexpected-leaf"
    )
    monkeypatch.setattr(
        enrollment.httpx,
        "Client",
        lambda **_kwargs: pytest.fail("HTTP authentication was attempted"),
    )
    with pytest.raises(enrollment.EnrollmentError, match="fingerprint differs"):
        enrollment.discover_vcenter_client(
            host="vcsa.example.test",
            cluster_id="Atlaso-KMIP",
            username="admin",
            password="test-secret",
            confirmed_https_fingerprint="00" * 32,
            atlaso_host="kms.atlaso.example.test",
            atlaso_port=5696,
        )


@pytest.mark.parametrize("colon_separated", [False, True])
def test_https_confirmation_normalizes_display_and_plain_digest(colon_separated: bool) -> None:
    """Accept either existing fingerprint representation without changing its identity.

    Args:
        colon_separated: Whether the caller supplies the displayed colon-separated form.
    """
    fingerprint = enrollment.certificate_fingerprint(b"confirmed-leaf")
    submitted = fingerprint if colon_separated else fingerprint.replace(":", "").lower()
    assert enrollment.normalize_https_fingerprint(f" {submitted} ") == fingerprint


@pytest.mark.parametrize("value", ["", "AA" * 31, "ZZ" * 32, "AA" * 33])
def test_https_confirmation_rejects_malformed_digests(value: str) -> None:
    """Require one complete SHA-256 identity and return only a safe error.

    Args:
        value: Invalid public fingerprint supplied by the caller.
    """
    with pytest.raises(enrollment.EnrollmentError, match="Confirm the current"):
        enrollment.normalize_https_fingerprint(value)


def test_pinned_https_context_uses_only_the_observed_leaf() -> None:
    """The vCenter request must not fall back to the host's system CAs."""
    pem = _client_certificate()
    leaf = x509.load_pem_x509_certificate(pem.encode()).public_bytes(
        serialization.Encoding.DER
    )
    context = enrollment._pinned_context(leaf)
    assert context.verify_mode.name == "CERT_REQUIRED"
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.cert_store_stats()["x509"] == 1


@pytest.mark.parametrize(
    "uri,expected",
    [
        ("https://VCSA.example.test/ui", ("vcsa.example.test", 443)),
        ("https://vcsa.example.test:8443", ("vcsa.example.test", 8443)),
        ("https://[2001:db8::1]:9443/ui", ("2001:db8::1", 9443)),
    ],
)
def test_saved_https_endpoint(uri, expected) -> None:
    """Resolve the saved HTTPS authority without changing its port.

    Args:
        uri: Saved HTTPS URI to resolve.
        expected: Expected normalized hostname and port.
    """
    assert enrollment.vcenter_https_endpoint(uri) == expected


@pytest.mark.parametrize(
    "uri",
    [
        "ssh://vcsa.example.test",
        "http://vcsa.example.test",
        "https://user:secret@vcsa.example.test",
        "https://vcsa.example.test:0",
        "https://vcsa.example.test:99999",
        "https://vcsa.example.test:bad",
        "https:///missing",
    ],
)
def test_invalid_saved_https_endpoint(uri) -> None:
    """Reject unsupported or credential-bearing saved endpoints.

    Args:
        uri: Invalid saved URI to reject.
    """
    with pytest.raises(enrollment.EnrollmentError):
        enrollment.vcenter_https_endpoint(uri)
