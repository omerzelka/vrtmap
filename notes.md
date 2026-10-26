# Geliştirme notları — modüllerin ne yaptığı

Bu dosya, `vrt_scanner/modules.py` içindeki her tespit modülünün **ne işe
yaradığını** sade dille anlatır. Kod İngilizce, notlar Türkçe. Yeni bir modül
eklerken buraya da bir paragraf ekle.

Her modül bir `Module` alt sınıfıdır: `VRT_IDS` ile hangi resmi VRT leaf'ini
otomatikleştirdiğini bildirir, `run(engine, pages)` içinde tespiti yapar ve
`self.f(...)` ile `Finding` döndürür. `priority`/`title` katalogdan otomatik
dolar; modül bunlara dokunmaz.

---

## DescriptiveStackTrace (pasif)
Leaf: `sensitive_data_exposure.visible_detailed_error_page.descriptive_stack_trace`

Sunucu bir hata verince bazen tüm **stack trace**'i (Java/Python/PHP/.NET/Node
istisna izini) sayfaya basar — bu, iç dosya yolları ve teknoloji bilgisini
sızdırır. Modül **yeni istek atmaz**; zaten crawl edilmiş `page.text`'lerde her
dilin kendine özgü hata imzasını (regex) arar. Eşleşirse bulgu üretir.

---

## DirectoryListing (aktif)
Leaf: `server_security_misconfiguration.directory_listing_enabled.non_sensitive_data_exposure`
ve `...sensitive_data_exposure`

Bir web sunucusu, bir klasör URL'si istendiğinde ve o klasörde index.html gibi
bir dosya yoksa, bazen klasörün içeriğini otomatik HTML listesi olarak döndürür
— tarayıcıda gördüğün o "Index of /uploads" sayfası. Bu bir açıktır: saldırgana
klasördeki tüm dosya adlarını sızdırır (yedekler, kaynak kod, .sql, .env, .git...).

Modülün mantığı:
1. Zaten crawl ettiğimiz her URL'nin üst klasörlerini çıkarır (ör. /a/b/c.php → /, /a/, /a/b/).
2. Her klasörü tek tek ister (bu modül yeni HTTP isteği atar — stack trace modülünden farkı bu).
3. Dönen sayfada "Index of /" türü imzayı arar.
4. İmza varsa açık var demektir. Listede hassas dosya adları (.sql, .bak, .git,
   .env, anahtarlar) geçiyorsa daha ciddi olan sensitive_data_exposure leaf'ine,
   geçmiyorsa non_sensitive_data_exposure leaf'ine bağlar.

İki VRT leaf'i birden kullanıyor.

---

## SoftwareVersionDisclosure (pasif)
Leaf: `server_security_misconfiguration.fingerprinting_banner_disclosure.software_version_in_response_headers`

Sunucu yanıt başlıklarında (`Server`, `X-Powered-By`, `X-AspNet-Version`...)
çalıştırdığı yazılımın **sürüm numarasını** açık eder. Saldırgan bu sürüme ait
bilinen açıkları (CVE) hedefler. Modül ilk sayfanın başlıklarına bakar; bu
başlıklarda sürüm deseni (`\d+\.\d+`) varsa bulgu üretir. Tamamen pasif.

---

## UnsafeHTTPMethods (aktif)
Leaf: `...potentially_unsafe_http_method_enabled.options` ve `.trace`

Sunucuya `OPTIONS` isteği atıp hangi HTTP metotlarına izin verdiğini (`Allow`
başlığı) öğrenir — PUT/DELETE/TRACE gibi tehlikeli metotlar açıksa riski açığa
çıkarır. Ayrıca `TRACE` metodu açıksa (yanıt isteği aynen geri yansıtıyorsa)
bu, Cross-Site Tracing (XST) açığıdır. İki yeni istek atar.

---

## MixedContent (pasif)
Leaf: `sensitive_data_exposure.mixed_content`

HTTPS ile sunulan bir sayfa, içinde `http://` ile başlayan kaynaklar (script,
resim, stil) yüklerse buna "mixed content" denir — şifreli sayfanın güvenliğini
kırar, araya giren saldırgan bu kaynakları değiştirebilir. Modül sadece HTTPS
sayfalarda `src`/`href="http://..."` referansı arar. Pasif.

---

## InsecureFormTransport (pasif)
Leaf: `insecure_data_transport.cleartext_transmission_of_sensitive_data`

Bir form, parola/kart/token gibi hassas bir alanı **şifresiz HTTP** üzerinden
gönderiyorsa (sayfa http:// ya da form action'ı http://), veri ağda açık gider.
Modül crawl edilen sayfalardaki formların alan adlarına bakar; hassas alan +
cleartext taşıma varsa bulgu üretir. Pasif.

---

## RobotsDisclosure (aktif)
Leaf: `sensitive_data_exposure.disclosure_of_secrets.publicly_accessible_robots`

`/robots.txt` dosyası bazen gizli kalması gereken yolları (admin, backup,
config, .git...) `Disallow` satırlarında listeleyerek ironik biçimde saldırgana
yol gösterir. Modül robots.txt'i çeker, ilginç/hassas yol içeren Disallow
satırlarını raporlar. Tek ek istek.

---

## PasswordAutocomplete (pasif)
Leaf: `external_behavior.browser_feature.autocomplete_enabled`

Bir parola alanında `autocomplete="off"` yoksa, tarayıcı parolayı kaydedebilir;
paylaşılan/ortak cihazlarda bu bir risktir. Modül sayfa HTML'inde
`type="password"` input'larını bulur, `autocomplete=off` içermeyeni raporlar.
Pasif (regex).

---

## SensitivePageCaching (pasif)
Leaf: `server_security_misconfiguration.lack_of_security_headers.cache_control_for_a_sensitive_page`

Parola alanı içeren (hassas) bir sayfa `Cache-Control: no-store`/`private`
göndermezse, tarayıcı/ara önbellek bu sayfayı diskte tutabilir — ortak cihazda
sonraki kullanıcı erişebilir. Modül hassas sayfalarda zayıf Cache-Control
başlığını yakalar. Pasif.

---

## Değişiklikler / yetenekler

**Soft-404 koruması (SensitiveFiles):** Bazı sunucular (SPA / catch-all) var
olmayan yola bile 200 + aynı sayfayı döner. Modül artık önce imkânsız bir yolu
isteyip "baseline" alır; bir dosya probu baseline ile aynı sayfayı dönüyorsa
gerçek dosya saymaz. False positive'leri engeller. Yardımcı: `_similar()`.

**Form fuzzing (ReflectedXSS + SQLInjection):** Aktif modüller artık yalnız URL
`?param=` değerlerini değil, crawl edilen sayfalardaki **form alanlarını** da
test eder. GET formları query string'e, POST formları gövdeye payload basar.
Ortak yardımcı: `_submit_form(engine, form, field, payload)`. Gerçek sitelerde
açıkların çoğu login/arama/iletişim formlarında olduğu için en değerli artış bu.

**Crawler seeding (core.Crawler._seed):** Crawl artık yalnız başlangıç
sayfasındaki linklerle sınırlı değil; `/robots.txt` (Allow/Disallow yolları +
Sitemap: adresleri) ve `/sitemap.xml` (`<loc>` URL'leri) kaynaklarından ekstra
giriş noktası toplayıp kuyruğa ekler. Sadece scope içi + aynı-origin URL'ler,
en çok 300 ile sınırlı. SPA/linksiz sitelerde kapsamı ciddi artırır.

**HTML rapor (core.report_html + cli --html):** `--html report.html` ile
bulguları öncelik renklerine göre gruplanmış, bağımsız (tek dosya) bir HTML
sayfası üretir. Tüm hedef-kaynaklı metin `html.escape` ile kaçırılır — yani
yansıyan bir XSS payload'u raporun kendisini ele geçiremez (self-XSS yok).

---

## AD engine (vrt_scanner/ad.py) — ikinci engine
Ayrı giriş noktası: `python -m vrt_scanner.ad --dc ... --domain ... --user ...
--password ... --authorized`. Kimlik bilgisiyle LDAP'a bağlanıp SALT OKUR,
sorgu tabanlı 8 kontrol yapar, hepsini `active_directory.*` VRT leaf'ine bağlar:
Kerberoastable (SPN'li hesap), AS-REP roastable (pre-auth yok), unconstrained
delegation, aşırı Domain Admin, açıklamada parola, zayıf parola politikası,
atıl aktif hesap, anonim LDAP bind. `ldap3` gerekir (yoksa zarifçe uyarır).
Web engine'den tamamen bağımsız; `core`'daki Finding/VRTCatalog/report'u
paylaşır. **ÖNEMLİ:** gerçek DC'de test EDİLMEDİ — kullanıcı kendi lab'ında
doğrulamalı. DACL/ACE parse (asıl DACL abuse) henüz TODO.

---

## 3 yeni web modülü (kapsam 23 -> 26)

**CSRFTokenMissing** (`cross_site_request_forgery_csrf.application_wide`, pasif):
POST formunda anti-CSRF token alanı (csrf/xsrf/_token/nonce...) yoksa raporlar.

**InternalIPDisclosure** (`sensitive_data_exposure.internal_ip_disclosure`,
pasif): sayfa metninde RFC1918 özel IP (10.x, 192.168.x, 172.16-31.x) sızıyorsa
raporlar. Loopback 127.x hariç.

**MissingSubresourceIntegrity** (`server_security_misconfiguration.missing_subresource_integrity`,
pasif): harici (cross-origin) `<script src=https://...>` etiketi `integrity`
olmadan yüklenmişse raporlar. Aynı-origin script'ler atlanır.
