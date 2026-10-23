import hashlib
import unittest
from unittest.mock import Mock, patch

from atlaso.app.services.vcf_certificate_remote import (
    Credentials,
    NativeAdapter,
    PinnedHTTPS,
    RemoteError,
    Target,
)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.cert = b"fake cert"
        self.target = Target(
            "appliance.test", 443, hashlib.sha256(self.cert).hexdigest()
        )

    @patch("atlaso.app.services.vcf_certificate_remote._PinnedConnection")
    @patch("atlaso.app.services.vcf_certificate_remote.ssl._create_unverified_context")
    def test_pin_checked_before_credentials_or_http(self, _ctx, ctor):
        conn = ctor.return_value
        conn.sock.getpeercert.return_value = self.cert
        conn.getresponse.return_value = Mock(
            status=200, length=2, read=Mock(return_value=b"{}")
        )
        PinnedHTTPS(self.target).request(
            "GET", "/", credentials=Credentials("admin", "secret")
        )
        conn.connect.assert_called_once()
        conn.request.assert_called_once()

    @patch("atlaso.app.services.vcf_certificate_remote._PinnedConnection")
    @patch("atlaso.app.services.vcf_certificate_remote.ssl._create_unverified_context")
    def test_bad_pin_sends_no_http(self, _ctx, ctor):
        conn = ctor.return_value
        conn.sock.getpeercert.return_value = b"wrong"
        with self.assertRaises(RemoteError):
            PinnedHTTPS(self.target).request(
                "GET", "/", credentials=Credentials("admin", "secret")
            )
        conn.request.assert_not_called()

    @patch("atlaso.app.services.vcf_certificate_remote._PinnedConnection")
    @patch("atlaso.app.services.vcf_certificate_remote.ssl._create_unverified_context")
    def test_oversized_response_rejected(self, _ctx, ctor):
        conn = ctor.return_value
        conn.sock.getpeercert.return_value = self.cert
        conn.getresponse.return_value = Mock(status=200, length=2**30)
        with self.assertRaisesRegex(RemoteError, "size limit"):
            PinnedHTTPS(self.target).request("GET", "/")

    def test_product_paths(self):
        for product, endpoint in [
            ("srm", "/appliance"),
            ("vcenter", "/api/appliance/system/version"),
        ]:
            adapter = NativeAdapter(self.target, product)
            adapter._request = Mock(return_value={})
            adapter.product_info()
            self.assertEqual(adapter._request.call_args.args[1], endpoint)

    def test_srm_csr_and_install_wire_contract(self):
        adapter = NativeAdapter(self.target, "srm")
        adapter.session = "sid"
        adapter.transport.request = Mock(
            side_effect=[(200, {"value": "CSR"}), (204, None)]
        )
        self.assertEqual(adapter.generate_csr({"fqdn": "srm.test"}), "CSR")
        adapter.install_csr("LEAF", ["ROOT"])
        self.assertEqual(
            adapter.transport.request.call_args_list[0].args,
            (
                "POST",
                "/api/rest/configure/v2/appliance/certificates/actions/generate-csr",
            ),
        )
        self.assertEqual(
            adapter.transport.request.call_args_list[1].kwargs["body"],
            {"csr_format": {"certificate": "LEAF", "ca_chain": ["ROOT"]}},
        )

    def test_vcenter_csr_and_install_wire_contract(self):
        adapter = NativeAdapter(self.target, "vcenter")
        adapter.session = "sid"
        adapter.transport.request = Mock(
            side_effect=[(201, {"csr": "CSR"}), (204, None)]
        )
        self.assertEqual(adapter.generate_csr({"common_name": "vc.test"}), "CSR")
        adapter.install_csr("LEAF", [])
        self.assertEqual(
            adapter.transport.request.call_args_list[0].args,
            ("POST", "/api/vcenter/certificate-management/vcenter/tls-csr"),
        )
        self.assertEqual(
            adapter.transport.request.call_args_list[1].kwargs["body"], {"cert": "LEAF"}
        )

    def test_session_login_uses_vendor_status_and_header(self):
        for product, status, payload, endpoint in [
            ("srm", 200, {"session_id": "session"}, "/api/rest/configure/v2/session"),
            ("vcenter", 201, "session", "/api/session"),
        ]:
            adapter = NativeAdapter(self.target, product)
            adapter.transport.request = Mock(return_value=(status, payload))
            self.assertEqual(adapter.login(Credentials("user", "secret")), "session")
            self.assertEqual(
                adapter.transport.request.call_args.args[:2], ("POST", endpoint)
            )

    def test_probe_is_unauthenticated_tls_only(self):
        adapter = PinnedHTTPS(self.target)
        with patch(
            "atlaso.app.services.vcf_certificate_remote.socket.create_connection"
        ) as connect:
            tls = Mock()
            tls.getpeercert.return_value = self.cert
            with patch(
                "atlaso.app.services.vcf_certificate_remote.ssl._create_unverified_context"
            ) as context:
                context.return_value.wrap_socket.return_value.__enter__.return_value = (
                    tls
                )
                with patch(
                    "atlaso.app.services.vcf_certificate_remote.x509.load_der_x509_certificate"
                ) as load:
                    load.return_value = Mock(
                        public_bytes=Mock(return_value=b"PEM"),
                        fingerprint=Mock(
                            return_value=bytes.fromhex(self.target.fingerprint)
                        ),
                        subject=Mock(rfc4514_string=Mock(return_value="CN=x")),
                        issuer=Mock(rfc4514_string=Mock(return_value="CN=ca")),
                    )
                    result = adapter.probe()
            self.assertEqual(result["sha256"], self.target.fingerprint)
            connect.assert_called_once()

    def test_vcenter_lookup_registration_wires_and_multiple_nodes(self):
        adapter = NativeAdapter(self.target, "vcenter")
        adapter.session = "session"
        service = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns="urn:lookup"><soap:Body><RetrieveServiceContentResponse><returnval><serviceRegistration type="ServiceRegistration">reg</serviceRegistration></returnval></RetrieveServiceContentResponse></soap:Body></soap:Envelope>'
        listing = (
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns="urn:lookup"><soap:Body><ListResponse>'
            + "".join(
                f"<returnval><serviceId>{n}</serviceId><siteId>s{n}</siteId><ownerId>o{n}</ownerId><nodeId>n{n}</nodeId><serviceEndpoints><url>https://vc{n}.test/sdk</url></serviceEndpoints></returnval>"
                for n in (1, 2)
            )
            + "</ListResponse></soap:Body></soap:Envelope>"
        )
        adapter.transport.request = Mock(side_effect=[(200, service), (200, listing)])
        result = adapter.vcenter_registrations()
        self.assertEqual(len(result), 2)
        self.assertEqual(
            adapter.transport.request.call_args_list[0].args[:2],
            ("POST", "/lookupservice/sdk"),
        )
        list_xml = adapter.transport.request.call_args_list[1].kwargs["xml_body"]
        self.assertIn("com.vmware.cis", list_xml)
        self.assertIn("vcenterserver", list_xml)

    def test_lookup_rejects_fault_and_entities(self):
        from atlaso.app.services.vcf_certificate_remote import _parse_lookup_xml

        with self.assertRaises(RemoteError):
            _parse_lookup_xml(
                '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///secret">]><x/>', "ListResponse"
            )
        with self.assertRaises(RemoteError):
            _parse_lookup_xml(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Fault/></soap:Body></soap:Envelope>',
                "ListResponse",
            )

    def test_session_cleanup_even_when_logout_fails(self):
        adapter = NativeAdapter(self.target, "vcenter")
        adapter.session = "session"
        adapter._request = Mock(side_effect=RuntimeError())
        with self.assertRaises(RuntimeError):
            adapter.logout()
        self.assertIsNone(adapter.session)
        self.assertNotIn("_credentials", adapter.__dict__)

    def test_strict_tls_context_selected(self):
        with (
            patch(
                "atlaso.app.services.vcf_certificate_remote.ssl.create_default_context"
            ) as strict,
            patch(
                "atlaso.app.services.vcf_certificate_remote._PinnedConnection"
            ) as ctor,
        ):
            conn = ctor.return_value
            conn.sock.getpeercert.return_value = self.cert
            conn.getresponse.return_value = Mock(
                status=204, length=0, read=Mock(return_value=b"")
            )
            PinnedHTTPS(
                Target(
                    "appliance.test",
                    443,
                    self.target.fingerprint,
                    strict_tls=True,
                    ca_pem="PEM",
                )
            ).request("GET", "/")
            strict.assert_called_once()


if __name__ == "__main__":
    unittest.main()
