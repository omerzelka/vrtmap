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

## 4. (İleride) Headless tarayıcı ile crawl  (öncelik: düşük)
SPA'ları gerçekten taramak için JS çalıştıran bir crawler (Playwright) gerekir.
Bu büyük bir ekleme; istersen ayrı bir görev olarak planlayalım. (Not: bu da
yeni bir sistem bağımlılığı kurmanı gerektirir.)
