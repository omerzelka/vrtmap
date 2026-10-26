# Senin yapman gerekenler (ortam / yetki gerektiren işler)

Bu maddeler Claude'un ortamında yapılamaz — kendi makinen, bir lab veya yazılı
izin gerektirir. Claude'un yapabildiği her şey ayrıca hallediliyor.

## 1. AD engine'i gerçek bir DC'de doğrula  (öncelik: yüksek)
AD engine (`vrt_scanner/ad.py`) yazıldı ama **çalışan bir Domain Controller
olmadan test edilemedi.** Kendi lab'ında (veya yazılı izinli bir domain'de):

- [ ] `pip install ldap3`
- [ ] Bir test AD lab'ı kur (ör. Windows Server + birkaç kullanıcı, ya da
      Samba AD DC / GOAD - "Game of Active Directory" hazır lab).
- [ ] Çalıştır:
      `python -m vrt_scanner.ad --dc <dc-ip> --domain <DOMAIN> --user <u> --password '<p>' --authorized`
- [ ] Şunları ortamına göre doğrula / ince ayar yap:
  - [ ] **Bind formatı:** kod NTLM `DOMAIN\user` kullanıyor. Ortamın simple
        bind (`user@domain.local`) isterse `ad.py > connect()`'i uyarla.
  - [ ] **base DN** otomatik bulunuyor mu (`defaultNamingContext`); bulamazsa
        `--base-dn "DC=lab,DC=local"` ver.
  - [ ] **`lastLogonTimestamp`** çözümü (dormant kontrolü) senin DC'de datetime
        mi yoksa ham FILETIME mı dönüyor — `_as_datetime` ikisini de karşılıyor,
        yine de sonucu bir bilinen hesapla doğrula.
  - [ ] Her kontrolün bulgusunu bilinen bir gerçekle karşılaştır (false
        positive/negative var mı).
- [ ] LDAPS gerekiyorsa `--ssl --port 636` ile dene.

## 2. AD DACL/ACE parse'ı doğrula  (öncelik: orta — kod YAZILDI, DENEYSEL)
Asıl "DACL Abuse" kontrolü (`ad.py > check_dacl_abuse`) eklendi: her nesnenin
nTSecurityDescriptor'ını okuyup düşük yetkili principal'lara verilen tehlikeli
hakları (GenericAll/GenericWrite/WriteDacl/WriteOwner) bulur. **Ama DC olmadan
test EDİLEMEDİ — deneysel.**
- [ ] `pip install impacket` (yoksa bu kontrol zarifçe atlanır).
- [ ] Lab DC'de çalıştırıp doğrula:
  - [ ] `nTSecurityDescriptor` SD_FLAGS control (sadece DACL) doğru geliyor mu.
  - [ ] impacket `ldaptypes` ACE alan erişimleri (`ace['Ace']['Mask']['Mask']`,
        `ace['Ace']['Sid'].formatCanonical()`) senin impacket sürümünle uyumlu mu.
  - [ ] `_privileged()` SID/RID beyaz listesi yeterli mi (false positive);
        gerekirse Domain Admins vb. ekle.
  - [ ] 500 nesne / 50 bulgu limitlerini ortamına göre ayarla.

## 3. Juice Shop / gerçek hedefte web engine'i dene  (öncelik: düşük)
- [ ] `docker run --rm -p 3000:3000 bkimminich/juice-shop`
- [ ] `python -m vrt_scanner.cli http://localhost:3000 --authorized --html r.html`
- Not: Juice Shop bir SPA — formları JS ile render ettiği için statik crawler
  az sayfa görür. Sunucu-render (klasik) bir hedefte çok daha fazla bulur.

## 4. Headless crawler'ı doğrula  (öncelik: düşük — kod YAZILDI)
JS çalıştıran crawler (`vrt_scanner/headless.py`) eklendi ve `--headless`
bayrağına bağlandı. Playwright burada kurulu olmadığı için **render test
edilemedi** (bayrak yoksa statik crawler'a düşüyor — bu kısım test edildi).
- [ ] `pip install playwright && playwright install chromium`
- [ ] `python -m vrt_scanner.cli http://localhost:3000 --authorized --headless`
      (Juice Shop açık) — statik modda 1 sayfa görülen yerde artık form/link
      dolu çok daha fazla sayfa görmeli.
- [ ] `wait_until="networkidle"` ve 15 sn timeout ağır SPA'larda yeterli mi,
      gerekirse `headless.py`'de ayarla.

## 5. Cloud (AWS) engine'ini doğrula  (öncelik: orta — kod YAZILDI, DENEYSEL)
`vrt_scanner/cloud.py` yazıldı: boto3 ile salt-okunur 5 AWS kontrolü (public
S3, şifresiz S3, internete açık yönetim portları, CloudTrail kapalı, IAM
AdministratorAccess). **AWS hesabı olmadan test EDİLEMEDİ.**
- [ ] `pip install boto3`, kimlik bilgisi/profil ayarla (`~/.aws/credentials`).
- [ ] `python -m vrt_scanner.cloud --profile <p> --region <r> --authorized`
- [ ] Yalnızca sahip olduğun / yazılı izinli hesapta çalıştır.
- [ ] Her kontrolün IAM izni yetiyor mu (yetmezse "module error" basar, zararsız).
