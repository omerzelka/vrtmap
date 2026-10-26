"""Mobile engine ZIP-layer tests (no androguard, no network)."""
import zipfile

from vrt_scanner.mobile import MobileScanner


def _apk(tmp_path, files):
    p = tmp_path / "t.apk"
    with zipfile.ZipFile(p, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return str(p)


def test_zip_layer_flags_secret_and_missing_pinning(tmp_path):
    apk = _apk(tmp_path, {
        "res/values/strings.xml":
            '<resources><string name="k">'
            'AIzaSyA1234567890abcdefghijklmnopqrstuvw</string></resources>',
    })
    ids = {f.vrt_id for f in MobileScanner(apk).scan_zip()}
    assert "insecure_data_storage.server_side_credentials_storage.plaintext" in ids
    assert "mobile_security_misconfiguration.ssl_certificate_pinning.absent" in ids


def test_zip_layer_no_secret_when_clean_and_pinned(tmp_path):
    apk = _apk(tmp_path, {
        "res/raw/network_security_config.xml":
            '<network-security-config><pin-set><pin digest="SHA-256">'
            'abc=</pin></pin-set></network-security-config>',
    })
    ids = {f.vrt_id for f in MobileScanner(apk).scan_zip()}
    assert "insecure_data_storage.server_side_credentials_storage.plaintext" not in ids
    assert "mobile_security_misconfiguration.ssl_certificate_pinning.absent" not in ids
