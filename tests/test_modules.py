"""Unit tests for passive detection modules (no network — fed Page objects)."""
import asyncio

from vrtmap.core import Page, Form
from vrtmap import modules as M


def run(mod, pages):
    return asyncio.run(mod.run(None, pages))


def page(url="http://t/", text="", headers=None, forms=None):
    return Page(url=url, status=200, headers=headers or {}, text=text,
                forms=forms or [], links=[])


def test_security_headers_all_missing():
    fs = run(M.SecurityHeaders(), [page(headers={})])
    assert len(fs) == 3   # CSP, HSTS, X-Content-Type-Options


def test_stack_trace_detected():
    fs = run(M.DescriptiveStackTrace(),
             [page(text="Traceback (most recent call last): boom")])
    assert len(fs) == 1
    assert fs[0].vrt_id.endswith("descriptive_stack_trace")


def test_internal_ip_disclosure():
    assert len(run(M.InternalIPDisclosure(), [page(text="host 10.0.0.5 ok")])) == 1
    assert len(run(M.InternalIPDisclosure(), [page(text="loopback 127.0.0.1")])) == 0


def test_missing_sri():
    ext = '<script src="https://cdn.x/a.js"></script>'
    ext_ok = '<script src="https://cdn.x/a.js" integrity="sha256-x"></script>'
    same = '<script src="http://t/a.js"></script>'
    assert len(run(M.MissingSubresourceIntegrity(), [page(text=ext)])) == 1
    assert len(run(M.MissingSubresourceIntegrity(), [page(text=ext_ok)])) == 0
    assert len(run(M.MissingSubresourceIntegrity(), [page(text=same)])) == 0


def test_csrf_token_missing():
    no_token = [Form(method="POST", action="http://t/x", inputs=["user", "pass"])]
    with_token = [Form(method="POST", action="http://t/x",
                       inputs=["user", "csrf_token"])]
    assert len(run(M.CSRFTokenMissing(), [page(forms=no_token)])) == 1
    assert len(run(M.CSRFTokenMissing(), [page(forms=with_token)])) == 0


def test_password_autocomplete():
    on = '<input type="password" name="p">'
    off = '<input type="password" name="p" autocomplete="off">'
    assert len(run(M.PasswordAutocomplete(), [page(text=on)])) == 1
    assert len(run(M.PasswordAutocomplete(), [page(text=off)])) == 0


def test_software_version_disclosure():
    fs = run(M.SoftwareVersionDisclosure(), [page(headers={"Server": "Apache/2.4.1"})])
    assert len(fs) == 1
    assert fs[0].param == "server"


def test_insecure_form_transport_over_http():
    forms = [Form(method="POST", action="http://t/login", inputs=["username", "password"])]
    fs = run(M.InsecureFormTransport(), [page(url="http://t/", forms=forms)])
    assert len(fs) == 1
