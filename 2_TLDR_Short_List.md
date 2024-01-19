# Kişisel Siber Güvenlik | TLDR [![Awesome](https://awesome.re/badge-flat2.svg)](https://awesome.re) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com) [![License](https://img.shields.io/badge/LICENSE-CC_BY_4.0-00a2ff?&style=flat-square)](https://creativecommons.org/licenses/by/4.0/)[![Contributors](https://img.shields.io/github/contributors/lissy93/personal-security-checklist?color=%23ffa900&style=flat-square)](/ATTRIBUTIONS.md#contributors-)

#### İçindekiler
- [Kişisel Güvenlik Kontrol Listesi](#kişisel-güvenlik-kontrol-listesi)
- [Gizlilik Odaklı Yazılımlar](#açık-kaynak-gizlilik-odaklı-yazılımlar)
- [Güvenlik Donanımı](#güvenlik-donanımı)

## KİŞİSEL GÜVENLİK KONTROL LİSTESİ

> Bu gizlilik ve güvenlik ipuçları kontrol listesi, [Tam Kişisel Güvenlik Kontrol Listesi](https://github.com/Lissy93/personal-security-checklist/blob/master/README.md) adlı belgenin özetidir. Dijital yaşamınızı korumak için atmanız gereken en temel adımları ortaya koyar.

### Kimlik Doğrulama
- Her bir hesabınız için uzun, güçlü ve benzersiz bir şifre kullanın ([HowSecureIsMyPassword.net](https://howsecureismypassword.net) adresini ziyaret edin)
- Şifrelerinizi şifrelemek, saklamak ve doldurmak için güvenli bir [şifre yöneticisi](https://github.com/Lissy93/awesome-privacy#password-managers) kullanın, örneğin [BitWarden](https://bitwarden.com) veya [KeePass](https://keepass.info) / [KeePassXC](https://keepassxc.org)
- Mümkünse 2-Faktörlü kimlik doğrulamayı etkinleştirin ve [authenticator uygulaması](https://github.com/Lissy93/awesome-privacy#2-factor-authentication) veya [hardware token](/6_Privacy_and-Security_Gadgets.md#fido-u2f-keys) kullanın
- Çoklu faktör kimlik doğrulamayı etkinleştirdiğinizde, genellikle 2FA yönteminiz kaybolursa, bozulursa veya kullanılamazsa kullanabileceğiniz birkaç kod verilir. Bu kodları kağıt üzerinde veya diskte güvenli bir yerde saklayın (örneğin çevrimdışı depolama veya şifreli bir dosya/sürücü içinde).
- [Firefox Monitor](https://monitor.firefox.com) veya [HaveIBeenPwned](https://haveibeenpwned.com) ile sızıntı uyarılarına kaydolun ve etkilenen hesapların şifrelerini güncelleyin


### İnternet Tarayıcısı Kullanımı
- Gizliliğe Saygı Gösteren bir Tarayıcı Kullanın, [Brave](https://brave.com) ve [Firefox](https://www.mozilla.org/en-US/exp/firefox/new) iyi seçeneklerdir. Varsayılan arama motorunuzu takip etmeyen bir motor olarak ayarlayın, örneğin [DuckDuckGo](https://duckduckgo.com).
- Herhangi bir bilgiyi non-HTTPS bir web sitesine girmeyin (kilit simgesine bakın). Firefox, Chrome, Edge ve Safari artık entegre HTTPS güvenlik özelliklerine sahiptir; etkin olup olmadığını bilmiyorsanız, bunu nereden kontrol edeceğinizi öğrenmek için bu [rehberi](https://www.eff.org/deeplinks/2021/09/https-actually-everywhere) inceleyin.
- İnsan haklarına saygı göstermeyen 3. parti takipçileri ve reklamları engellemek için [Privacy Badger](https://privacybadger.org) veya [uBlock](https://github.com/gorhill/uBlock) gibi bir eklenti kullanın.
- Tarayıcınızı güncel tutun, gizlilik ayarlarını keşfedin ve gereksiz eklentileri kaldırın.
- İnternet gezinmenizin farklı alanlarını (örneğin iş, sosyal, alışveriş vb.) ayırmak için bölümlendirmeyi düşünün. Bu, [Firefox Containers](https://support.mozilla.org/en-US/kb/containers) ile veya ayrı tarayıcılar veya tarayıcı profilleri kullanarak yapılabilir.
- Tarayıcınıza şifrelerinizi kaydetmesine veya kişisel bilgilerinizi otomatik doldurmasına izin vermeyin (bunun yerine bir [şifre yöneticisi](https://github.com/Lissy93/awesome-privacy#password-managers) kullanın ve tarayıcınızın kendi otomatik doldurma özelliğini [devre dışı bırakın](https://www.computerhope.com/issues/ch001377.htm)).
- Çerezleri, oturum verilerini ve önbelleği düzenli olarak temizleyin. [Cookie-Auto-Delete](https://github.com/Cookie-AutoDelete/Cookie-AutoDelete) gibi bir eklenti bunu otomatikleştirmek için kullanılabilir.
- Tarayıcınıza giriş yapmasına izin vermeyin, çünkü bu daha fazla veriyi kimliğinizle bağdaştırabilir. İhtiyacınız varsa, açık kaynaklı bir [yer işareti senkronizasyon](https://github.com/Lissy93/awesome-privacy#browser-sync) uygulaması kullanabilirsiniz.
- [Decentraleyes](https://decentraleyes.org) kullanarak cihazınızın izlenebilir CDN istek sayısını azaltmayı düşünün.
- Tarayıcınızı [Panopticlick](https://panopticlick.eff.org) gibi bir araçla test ederek büyük sorun olmadığından emin olun. [BrowserLeaks](https://browserleaks.com) ve [Am I Unique](https://amiunique.org/fp) web sitelerine hangi cihaz bilgilerini açığa çıkardığınızı incelemek için faydalıdır.

### Telefon
- Cihaz PIN'i ayarlayın, ideal olarak uzun bir şifre kullanın. Destekleniyorsa parmak izi kimlik doğrulamasını yapılandırın, ancak yüz kilidinden kaçının.
- Cihazınızı şifreleyin, böylece verileriniz fiziksel erişimden korunur. Android için etkinleştirmek için: `Ayarlar --> Güvenlik --> Şifreleme`, iOS için: `Ayarlar --> TouchID ve Parola --> Veri Koruma`.
- Cihazınızı güncel tutun. Sistem güncellemeleri genellikle yakın zamanda keşfedilen güvenlik açıkları için yamalar içerir. Güncellemeleri yapmanız gerektiğinde yüklemeniz önemlidir.
- Uygulama izinlerini gözden geçirin. İhtiyaç duymayan uygulamalara erişim izni vermeyin. (Android için, [Bouncer](https://play.google.com/store/apps/details?id=com.samruston.permission&hl=en_US) - geçici izinler vermenizi sağlayan bir uygulama)
- Kullanılmayan bağlantı özelliklerini devre dışı bırakın ve artık ihtiyacınız olmayan WiFi ağlarını 'unutun'.
- Konum takibini devre dışı bırakın. Varsayılan olarak, hem Android hem de iOS GPS konum geçmişinizi kaydeder. Android için bu özelliği kapatmak için: `Haritalar --> Ayarlar --> Konum Geçmişi`, iOS için: `Ayarlar --> Gizlilik --> Konum Servisleri --> Sistem Servisleri --> Yerler`. Unutmayın ki üçüncü taraf uygulamalar hala konumunuzu kaydedebilir ve GPS dışında da konumunuzu belirleme yöntemleri bulunmaktadır (Hücresel kule, WiFi, Bluetooth vb.).
- İnternet bağlantısı gerekmeyen uygulamalar için bir uygulama duvarını kullanın. Örneğin [NetGuard](https://www.netguard.me/) (Android) veya [Lockdown](https://apps.apple.com/in/app/lockdown-apps/id1469783711) (iOS).
- Uygulamaların verilerinizi topladığını, sakladığını ve bazen paylaştığını anlayın. Android için yüklü uygulamalarınızın hangi izleyicileri kullandığını ortaya çıkarmak için [Exodus](https://exodus-privacy.eu.org/en/page/what/) kullanabilirsiniz.

### E-Posta
E-posta hesabınızı korumak önemlidir; çünkü bir hacker erişim sağlarsa, siz gibi davranabilir ve diğer online hesaplarınızın şifrelerini sıfırlayabilirler. Dijital güvenliğe yönelik en büyük tehditlerden biri hala "phishing"dir ve bazen inanılmaz derecede ikna edici olabilir. Bu nedenle dikkatli olun ve [zararlı e-postaları nasıl tespit edeceğinizi](https://heimdalsecurity.com/blog/abcs-detecting-preventing-phishing) anlayın ve e-posta adresinizi herkese açık bir şekilde paylaşmaktan kaçının.

- Uzun, güçlü ve benzersiz bir şifre kullanın ve 2FA'yi etkinleştirin.
- Güvenli ve şifreli bir posta sağlayıcısına geçmeyi düşünün, örneğin [ProtonMail](https://protonmail.com) veya [Tutanota](https://tutanota.com).
- Gerçek e-posta adresinizi korumak için e-posta alias kullanın, [Anonaddy](https://anonaddy.com) veya [SimpleLogin](https://simplelogin.io/?slref=bridsqrgvrnavso) gibi bir sağlayıcı ile. Bu, gerçek adresinizi gizli tutmanıza olanak tanır, ancak tüm iletilerin ana gelen kutunuzda karışmasına izin verir.
- Uzaktan içeriği otomatik yüklemeyi devre dışı bırakın, çünkü bu genellikle ayrıntılı izleme için kullanılır ancak aynı zamanda zararlı olabilir.
- Özel bir alan adı kullanmak, mevcut sağlayıcınız kaybolduğunda e-posta adresinize erişim kaybetmeyeceğiniz anlamına gelir. Mesajları yedeklemeniz gerekiyorsa, güvenli bir IMAP istemcisi kullanın [Thunderbird](https://www.thunderbird.net).

### Güvenli Mesajlaşma
- Tamamen açık kaynak ve uçtan uca şifreli, ileriye dönük mükemmel gizlilikle bir [güvenli mesajlaşma uygulaması](https://github.com/Lissy93/awesome-privacy#encrypted-messaging) kullanın (örneğin [Signal](https://www.signal.org/)).
- Hem cihazınızın hem de alıcının güvenli olduğundan emin olun (kötü amaçlı yazılımdan, şifrelenmiş ve güçlü bir şifreye sahip).
- Web uygulama eşlik veya bulut yedekleme özelliği gibi bulut hizmetlerini devre dışı bırakın, her ikisi de saldırı yüzeyini artırır.
- Ortam paylaşmadan önce medya dosyalarından meta verileri kaldırın, çünkü bu istemeden daha fazla veriyi ortaya çıkarabilir.
- Alıcınızın iddia ettiği kişi olduğunu doğrulayın, fiziksel olarak veya iletişim doğrulaması sunan bir uygulama kullanarak.
- SMS'den kaçının, ancak kullanmanız gerekiyorsa mesajlarınızı şifreleyin, örneğin [Silence](https://silence.im/) uygulamasını kullanarak.
- Güvenilir geliştiriciler tarafından desteklenen, şeffaf bir gelir modeline sahip olan veya finansmanın nereden geldiğini hesaplayabilen bir platformu tercih edin. İdeal olarak, güvenilir bir yargı alanında bulunmalı ve bağımsız bir güvenlik denetiminden geçmiş olmalıdır. [Matrix](https://matrix.org/), [Session](https://getsession.org/), [Tox](https://tox.chat/) veya [Briar](https://briarproject.org/) gibi [merkezi olmayan bir platform](https://github.com/Lissy93/awesome-privacy#p2p-messaging) bazı durumlarda ek güvenlik ve gizlilik avantajları sunabilir.


### Ağ
- IP'nizi korumak ve ISS'nizin kaydedebileceği gezinme verisi miktarını azaltmak için saygın bir VPN kullanın, ancak [sınırlamalarını](5_Privacy_Respecting_Software.md#word-of-warning-4) anlayın. İyi seçenekler arasında [ProtonVPN](https://protonvpn.com) ve [Mullvad](https://mullvad.net) bulunmaktadır; ayrıntılı karşılaştırmalar için [thatoneprivacysite.net](https://thatoneprivacysite.net/)'e bakın.
- Yönlendiricinizin varsayılan şifresini değiştirin. WiFi'ye bağlı herkes ağ trafiğini dinleyebilir, bu nedenle bilmediğiniz kişilerin bağlanmasını önlemek için WPA2 kullanın ve güçlü bir şifre ayarlayın.
- İzlemeyi azaltmak için [Cloudflare'ın 1.1.1.1'i](https://1.1.1.1/dns/) gibi [güvenli bir DNS](https://github.com/Lissy93/awesome-privacy#dns) sağlayıcısı kullanın. İdeali bunu yönlendiricinizde yapılandırmaktır, ancak mümkün değilse her cihazda yapılabilir.

**📜 Daha Fazlasını Gör**: [Tam Kişisel Güvenlik Kontrol Listesi](https://github.com/Lissy93/personal-security-checklist/blob/master/README.md)

----

## AÇIK KAYNAKLI, GİZLİLİK ODAKLI YAZILIM
Verilerinizi toplamayan, sizi takip etmeyen ve hedefe yönelik reklamlar göstermeyen alternatif açık kaynaklı, gizliliğe saygılı uygulamalara ve hizmetlere geçin.

#### Güvenlik
- Şifre Yöneticileri: [BitWarden] | [1Password] *(ticari)* | [KeePassXC] *(çevrimdışı)* | [LessPass] *(durumsuz)*
- 2-Faktörlü Kimlik Doğrulama: [Aegis] *(Android)* | [Authenticator] *(iOS)* | [AndOTP] *(Android)*
- Dosya Şifreleme: [VeraCrypt] | [Cryptomator] *(bulut için)*
- Şifreli Mesajlaşma: [Signal] | [KeyBase] *(gruplar/topluluklar için)*
- Şifreli E-Posta: [ProtonMail] | [MailFence] | [Tutanota] | (+ ayrıca [33Mail] | [anonaddy] aliasing için)
- Gizlilik Odaklı Tarayıcılar: [Brave Browser] | [Firefox] *([bazı düzenlemelerle](https://restoreprivacy.com/firefox-privacy/))* | [Tor]
- İzlemeyen Arama Motorları: [DuckDuckGo] | [StartPage] | [SearX] *(kendi barındırma)* | [Qwant]
- VPN: [Mullvad] | [ProtonVPN]  | [Windscribe] | [IVPN] *(daha iyi olanı, anonimlik için [Tor'u](https://www.torproject.org/) kullanın)*. Ayrıca [VPN Uyarı Notu]'na bakın.
- Uygulama Duvarı: [NetGuard] (Android) | [Lockdown] (iOS) | [OpenSnitch] (Linux) | [LuLu] (MacOS)

#### Tarayıcı Eklentileri
- [Privacy Badger] - İzleyicileri engeller.
- [HTTPS Everywhere] - İstekleri HTTPS'ye yükseltir.
- [uBlock Origin] - Reklamları, izleyicileri ve kötü amaçlı yazılımları engeller.
- [ScriptSafe] - Belirli betiklerin yürütülmesini engeller.
- [WebRTC Leak Prevent] - IP sızıntılarını önler.
- [Vanilla Cookie Manager] - İstenmeyen çerezleri otomatik olarak kaldırır.
- [Privacy Essentials] - Hangi sitelerin güvensiz olduğunu gösterir

#### Mobil Uygulamalar
- [Exodus] - Cihazınızdaki izleyicileri gösterir.
- [Orbot]- Sistem genelinde Tor Proxy.
- [Island] - Uygulamalar için kum kutusu ortamı.
- [NetGuard] - Hangi uygulamaların ağ erişimine sahip olduğunu kontrol edin.
- [Bouncer] - Geçici izinler vermenizi sağlar.
- [Greenify] - Arka planda çalışabilen uygulamaları kontrol edin.
- [1.1.1.1] - CloudFlare'ın DNS üzerinden HTTPS kullanın.
- [Fing App] - Ev WiFi ağınızı yabancılara karşı izleyin.

#### Çevrimiçi Araçlar
- [εxodus] - Bir uygulamanın hangi izleyicilere sahip olduğunu gösterir.
- [';--have i been pwned?] - Bilgilerinizin bir ihlalde ortaya çıkıp çıkmadığını kontrol edin.
- [EXIF Remover] - Bir resim veya dosyadan meta verileri kaldırır.
- [Redirect Detective] - Bağlantının nereye yönlendirildiğini gösterir.
- [Virus Total] - Dosya veya URL'yi kötü amaçlı yazılım için tarar.
- [Panopticlick], [Browser Leak Test] ve [IP Leak Test] - Sistem ve tarayıcı sızıntılarını kontrol edin

#### Üretkenlik Araçları
- Dosya Depolama: [NextCloud].
- Dosya Senkronizasyonu: [Syncthing].
- Dosya Bırakma: [FilePizza].
- Notlar: [Standard Notes], [Cryptee], [Joplin].
- Blog Yazma: [Write Freely].
- Takvim/İletişim Senkronizasyonu: [ETE Sync]

📜 **Daha Fazlasını Gör**: [Gizliliğe Saygılı Yazılımların Tam Listesi](https://github.com/Lissy93/awesome-privacy)

----

## GÜVENLİK DONANIMI

Fiziksel ve dijital güvenliğinizi artırmaya yardımcı olan bazı cihazlar da bulunmaktadır.

- **Engelleyiciler ve Kalkanlar**: [PortaPow] - USB Veri Engelleyici | [Mic Block] - Mikrofonu fiziksel olarak devre dışı bırakır | [Silent-Pocket] - Sinyal engelleyen faraday torbaları | [Lindy] - Fiziksel port engelleyiciler | [RFID Kalkanları] | [Webcam Kapakları] | [Gizlilik Ekranı]
- **Kripto Cüzdanları**: [Trezor] - Donanım cüzdan | [CryptoSteel] - Dayanıklı çelik kripto cüzdan
- **FIDO U2F Anahtarları**: [Solo Key] | [Nitro Key] | [Librem Key]
- **Veri Engelleyiciler**: [PortaPow] - Malware yükleme saldırılarına karşı veriyi engeller, FastCharge'i etkinleştirir.
- **Donanım şifreli depolama**:  [iStorage]- PIN doğrulamalı 256-bit donanım şifreli depolama | [Şifreli Sürücü Kasağı]
- **Ağ**: [Anonabox] - Tak ve çalıştır Tor yönlendirici | [FingBox] - Kolay ev ağı otomatik güvenlik izleme
- **Paranoid Cihazlar!** [Orwl]- Kendini imha eden bilgisayar | [Hunter-Cat]- Kart skimmer dedektörü | [Adversarial Fashion]- Yüz tanıma karşıtı giyim | [DSTIKE Deauth Detector] - [Spacehuhn]'dan deauth saldırılarını tespit et | [Reflectacles]- Gözetleme karşıtı gözlükler | [Armourcard]- Aktif RFID karıştırma | [Bug-Detector]- RF etkin dinleme ekipmanı kontrol et | [Ultrasonic Microphone Jammer] - İnsanlar için sessiz sinyaller yayar, ancak kayıt ekipmanı ile müdahale eder.

Paranızı harcamaya gerek yok - Bu ürünlerin çoğu açık kaynaklı yazılım kullanılarak evde yapılabilir. İşte [Kendi Yapabileceğiniz Güvenlik Cihazları](/6_Privacy_and-Security_Gadgets.md#diy-security-products) listesi.

📜 **Daha Fazlasını Gör**: [Gizlilik ve Güvenlik Cihazları](/6_Privacy_and-Security_Gadgets.md)

----

*Ziyaretiniz için teşekkür ederim, umarım burada faydalı bir şey bulmuşsunuzdur :) Katkılar hoş geldiniz ve çok takdir edilir - bir düzenleme önermek için [bir sorun oluşturun](https://github.com/Lissy93/personal-security-checklist/issues/new/choose) veya [PR açın](https://github.com/Lissy93/personal-security-checklist/pull/new/master). Bakın: [`CONTRIBUTING.md`](/.github/CONTRIBUTING.md).*

----

Bu bilgiyi yararlı buldunuz mu? Başkalarının dijital güvenliğini iyileştirmelerine yardımcı olmak için paylaşmayı düşünün 😇

[![Share on Twitter](https://img.shields.io/badge/Share-Twitter-17a2f3?style=flat-square&logo=Twitter)](http://twitter.com/share?text=Check%20out%20the%20Personal%20Cyber%20Security%20Checklist-%20an%20ultimate%20list%20of%20tips%20for%20protecting%20your%20digital%20security%20and%20privacy%20in%202020%2C%20with%20%40Lissy_Sykes%20%F0%9F%94%90%20%20%F0%9F%9A%80&url=https://github.com/Lissy93/personal-security-checklist)
[![Share on LinkedIn](https://img.shields.io/badge/Share-LinkedIn-0077b5?style=flat-square&logo=LinkedIn)](
http://www.linkedin.com/shareArticle?mini=true&url=https://github.com/Lissy93/personal-security-checklist&title=The%20Ultimate%20Personal%20Cyber%20Security%20Checklist&summary=%F0%9F%94%92%20A%20curated%20list%20of%20100%2B%20tips%20for%20protecting%20digital%20security%20and%20privacy%20in%202020&source=https://github.com/Lissy93)
[![Share on Facebook](https://img.shields.io/badge/Share-Facebook-4267b2?style=flat-square&logo=Facebook)](https://www.linkedin.com/shareArticle?mini=true&url=https%3A//github.com/Lissy93/personal-security-checklist&title=The%20Ultimate%20Personal%20Cyber%20Security%20Checklist&summary=%F0%9F%94%92%20A%20curated%20list%20of%20100%2B%20tips%20for%20protecting%20digital%20security%20and%20privacy%20in%202020&source=)
[![Share on Mastodon](https://img.shields.io/badge/Share-Mastodon-56a7e1?style=flat-square&logo=Mastodon)](https://mastodon.social/web/statuses/new?text=Check%20out%20the%20Ultimate%20Personal%20Cyber%20Security%20Checklist%20by%20%40Lissy93%20on%20%23GitHub%20%20%F0%9F%94%90%20%E2%9C%A8)





*Licensed under [Creative Commons, CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), © [Alicia Sykes](https://aliciasykes.com) 2020*

<a href="https://twitter.com/intent/follow?screen_name=Lissy_Sykes">
  <img src="https://img.shields.io/twitter/follow/Lissy_Sykes?style=social&logo=twitter" alt="Follow Alicia Sykes on Twitter">
</a>


[//]: # (Güvenlik Yazılımı linkleri)
[BitWarden]: https://bitwarden.com
[1Password]: https://1password.com
[KeePassXC]: https://keepassxc.org
[LessPass]: https://lesspass.com
[Aegis]: https://getaegis.app
[AndOTP]: https://github.com/andOTP/andOTP
[Authenticator]: https://mattrubin.me/authenticator
[VeraCrypt]: https://www.veracrypt.fr
[Cryptomator]: https://cryptomator.org
[Tor]: https://www.torproject.org
[Pi-Hole]: https://pi-hole.net
[Mullvad]: https://mullvad.net
[ProtonVPN]: https://protonvpn.com
[Windscribe]: https://windscribe.com/?affid=6nh59z1r
[IVPN]: https://www.ivpn.net
[NetGuard]: https://www.netguard.me
[Lockdown]: https://lockdownhq.com
[OpenSnitch]: https://github.com/evilsocket/opensnitch
[LuLu]: https://objective-see.com/products/lulu.html
[SimpleWall]: https://github.com/henrypp/simplewall
[33Mail]: http://33mail.com/Dg0gkEA
[anonaddy]: https://anonaddy.com
[Signal]: https://signal.org
[KeyBase]: https://keybase.io
[ProtonMail]: https://protonmail.com
[MailFence]: https://mailfence.com
[Tutanota]: https://tutanota.com
[Brave Browser]: https://brave.com/?ref=ali721
[Firefox]: https://www.mozilla.org/
[DuckDuckGo]: https://duckduckgo.com
[StartPage]: https://www.startpage.com
[Qwant]: https://www.qwant.com
[SearX]: https://asciimoo.github.io/searx

[VPN Warning Note]: https://github.com/Lissy93/personal-security-checklist/blob/master/5_Privacy_Respecting_Software.md#word-of-warning-8

[//]: # (PRODUCTIVITY Yazılım Linkleri)
[NextCloud]: https://nextcloud.com
[Standard Notes]: https://standardnotes.org/?s=chelvq36
[Cryptee]: https://crypt.ee
[Joplin]: https://joplinapp.org
[ETE Sync]: https://www.etesync.com/accounts/signup/?referrer=QK6g
[FilePizza]: https://file.pizza/
[Syncthing]: https://syncthing.net
[Write Freely]: https://writefreely.org

[//]: # (Tarayıcı Eklentileri)
[Privacy Badger]: https://www.eff.org/privacybadger
[HTTPS Everywhere]: https://eff.org/https-everywhere
[uBlock Origin]: https://github.com/gorhill/uBlock
[ScriptSafe]: https://github.com/andryou/scriptsafe
[WebRTC Leak Prevent]: https://github.com/aghorler/WebRTC-Leak-Prevent
[Vanilla Cookie Manager]: https://github.com/laktak/vanilla-chrome
[Privacy Essentials]: https://duckduckgo.com/app

[//]: # (ONLİNE GÜVENLİK ARAÇLARI)
[';--have i been pwned?]: https://haveibeenpwned.com
[εxodus]: https://reports.exodus-privacy.eu.org
[Panopticlick]: https://panopticlick.eff.org
[Browser Leak Test]: https://browserleaks.com
[IP Leak Test]: https://ipleak.net
[EXIF Remover]: https://www.exifremove.com
[Redirect Detective]: https://redirectdetective.com
[Virus Total]: https://www.virustotal.com

[//]: # (ANDROID APPS)
[Island]: https://play.google.com/store/apps/details?id=com.oasisfeng.island
[Orbot]: https://play.google.com/store/apps/details?id=org.torproject.android
[Orbot]: https://play.google.com/store/apps/details?id=org.torproject.android
[Bouncer]: https://play.google.com/store/apps/details?id=com.samruston.permission
[Crypto]: https://play.google.com/store/apps/details?id=com.kokoschka.michael.crypto
[Cryptomator]: https://play.google.com/store/apps/details?id=org.cryptomator
[Daedalus]: https://play.google.com/store/apps/details?id=org.itxtech.daedalus
[Brevent]: https://play.google.com/store/apps/details?id=me.piebridge.brevent
[Greenify]: https://play.google.com/store/apps/details?id=com.oasisfeng.greenify
[Secure Task]: https://play.google.com/store/apps/details?id=com.balda.securetask
[Tor Browser]: https://play.google.com/store/apps/details?id=org.torproject.torbrowser 
[PortDroid]: https://play.google.com/store/apps/details?id=com.stealthcopter.portdroid
[Packet Capture]: https://play.google.com/store/apps/details?id=app.greyshirts.sslcapture
[SysLog]: https://play.google.com/store/apps/details?id=com.tortel.syslog
[Dexplorer]: https://play.google.com/store/apps/details?id=com.dexplorer
[Check and Test]: https://play.google.com/store/apps/details?id=com.inpocketsoftware.andTest
[Tasker]: https://play.google.com/store/apps/details?id=net.dinglisch.android.taskerm
[Haven]: https://play.google.com/store/apps/details?id=org.havenapp.main
[NetGaurd]: https://www.netguard.me/
[Exodus]: https://exodus-privacy.eu.org/en/page/what/#android-app
[XUMI Security]: https://xumi.ca/xumi-security/
[Fing App]: https://www.fing.com/products/fing-app
[FlutterHole]: https://github.com/sterrenburg/flutterhole
[1.1.1.1]: https://1.1.1.1/
[The Guardian Project]: https://play.google.com/store/apps/dev?id=6502754515281796553
[The Tor Project]: https://play.google.com/store/apps/developer?id=The+Tor+Project
[Oasis Feng]: https://play.google.com/store/apps/dev?id=7664242523989527886
[Marcel Bokhorst]: https://play.google.com/store/apps/dev?id=8420080860664580239

[//]: # (GÜVENLİK DONANIM BAĞLANTILARI)
[Encrypted Drive Enclosure]: https://www.startech.com/HDD/Enclosures/encrypted-sata-enclosure-2-5in-hdd-ssd-usb-3~S2510BU33PW
[iStorage]: https://istorage-uk.com
[PortaPow]: https://portablepowersupplies.co.uk/product/usb-data-blocker
[Lindy]: https://lindy.com/en/technology/port-blockers
[Mic Block]: https://www.aliexpress.com/item/4000542324471.html
[RFID Shields]: https://www.aliexpress.com/item/32976382478.html
[Webcam Covers]: https://www.aliexpress.com/item/4000393683866.html
[Privacy Screen]: https://www.aliexpress.com/item/32906889317.html
[Trezor]: https://trezor.io
[CryptoSteel]: https://cryptosteel.com/product/cryptosteel/?v=79cba1185463
[Solo Key]: https://solokeys.com
[Nitro Key]: https://www.nitrokey.com
[Librem Key]: https://puri.sm/products/librem-key
[Anonabox]: https://www.anonabox.com
[FingBox]: https://www.fing.com/products/fingbox
[Orwl]: https://orwl.org
[Hunter-Cat]: https://lab401.com/products/hunter-cat-card-skimmer-detector
[DSTIKE Deauth Detector]: https://www.tindie.com/products/lspoplove/dstike-deauth-detector-pre-flashed-with-detector
[Bug-Detector]: https://www.brickhousesecurity.com/counter-surveillance/multi-bug
[Ultrasonic Microphone Jammer]: https://uspystore.com/silent-ultrasonic-microphone-defeater
[Silent-Pocket]: https://silent-pocket.com
[Armourcard]: https://armourcard.com
[Adversarial Fashion]: https://adversarialfashion.com
[Reflectacles]: https://www.reflectacles.com
[Spacehuhn]: https://github.com/spacehuhn/DeauthDetector

