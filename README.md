# RE Workbench

Ubuntu üzerinde tarayıcıdan kullanılan yerel dosya analizi ve tersine mühendislik aracı. Dosyanı seç, analiz yöntemini belirle ve sonuçları sekmelerden incele.

## Özellikler

- **Statik Analiz:** dosya türü, SHA-256/SHA-1/MD5, strings, ELF bilgileri ve entropi.
- **Tersine Mühendislik:** ELF sembolleri, bölümler, bağımlılıklar, disassembly ve hex görünümü.
- Sonuçlarda arama, filtreleme, sayfalama ve kopyalama.
- Analiz ilerlemesi, iptal, yerel geçmiş ve JSON/Markdown raporları.
- İsteğe bağlı MCP bağlantısı; araçlar sunucudan keşfedilir ve çağrılar açık onay ister.
- İsteğe bağlı, deneysel rootless Podman dinamik analizi.

## Kurulum

Python 3.10+ gerekir. Ubuntu 22.04 ve 24.04 hedeflenir.

```bash
sudo apt-get update
sudo apt-get install python3 git file binutils

git clone https://github.com/efekanacar/reworkbench.git
cd reworkbench
./start.sh
```

Temel uygulama için pip, Node veya bir frontend derlemesi gerekmez. Başlatma betiği tarayıcıyı açmayı dener. Açılmazsa terminalde gösterilen **tam bağlantıyı** kopyala:

```text
http://127.0.0.1:8780/#token=HER_BASLATMADA_URETILEN_ANAHTAR
```

Anahtar örnekteki metin değil, terminalde üretilen değerdir. Bağlantıyı paylaşma. Sunucuyu durdurmak için **Ctrl+C** kullan.

Port değiştirmek veya tarayıcıyı elle açmak için:

```bash
./start.sh --port 8790 --no-browser
```

### Ek analiz paketleri ve MCP

GNU `readelf` ve `objdump` temel ELF incelemesini sağlar. Capstone, pyelftools ve MCP desteğini de kurmak için:

```bash
sudo apt-get install python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
./start.sh
```

Eksik veya desteklenmeyen özellikler arayüzde açıkça belirtilir.

## Kullanım

1. **Statik Analiz** veya **Tersine Mühendislik** seç.
2. Dosyanı sürükleyip bırak veya bilgisayarından seç. Boyut sınırı **64 MiB**.
3. **Analizi başlat** düğmesine bas. İstediğin zaman iptal edebilirsin.
4. **Genel bakış** ile dosya türünü, hash değerlerini ve mimariyi incele.
5. **Strings/Göstergeler** ile metin, URL, IP ve dosya yollarını ara.
6. **Semboller/Bölümler/Disassembly** ile ELF yapısını incele. **Hex** adresleri dosya ofsetidir.
7. JSON veya Markdown raporunu indir. Önceki sonuçlar **Analiz geçmişi** bölümündedir.

İki ana mod da örneği çalıştırmaz. İlk deneme için zararsız bir ELF oluşturabilirsin:

```bash
sudo apt-get install gcc
gcc -g -O0 -o /tmp/rewb-hello tests/fixtures/hello.c
```

Arayüzden `/tmp/rewb-hello` dosyasını seç. Sembollerde `main`, strings içinde örnek metinler ve disassembly çıktısı görünür.

## MCP bağlantısı

```bash
cp .env.example .env
chmod 600 .env
```

`.env` dosyasında kendi sunucu adresini `REWB_MCP_URL` alanına yaz. Taşıma `streamable-http` veya `sse`; kimlik doğrulama `none` veya `bearer` olabilir. Bearer kullanıyorsan `REWB_MCP_AUTH=bearer` ve `REWB_MCP_TOKEN` değerlerini ayarla. Ardından:

```bash
set -a
. ./.env
set +a
./start.sh
```

`.env` otomatik okunmaz ve Git'e eklenmez. Arayüzde **MCP araçları → Sunucuya bağlan** seç. Çağrı öncesinde alıcı ve tam parametreler gösterilir. Dosya içeriği otomatik gönderilmez. Uzak bağlantılarda HTTPS gerekir; OAuth ve stdio bu sürümde desteklenmez.

## Sınırlar ve güvenlik

- Yalnızca analiz etmeye yetkili olduğun dosyaları kullan. Bulgular tek başına zararlılık hükmü değildir.
- Ayrıntılı yapı/disassembly **ELF** içindir. PE/Mach-O/PDF/arşivlerde tanıma, hash, strings ve hex kullanılabilir; arşivler açılmaz.
- Statik ayrıştırıcılar kaynak sınırları olan yerel süreçlerde çalışır; tam izolasyon sağlamaz. Şüpheli dosyalar için ayrı analiz VM'i kullan.
- Sunucu yalnızca **127.0.0.1** üzerinde dinler; API oturum anahtarı ve aynı kaynak denetimi kullanır. İnternete açık veya çok kullanıcılı sunucu olarak tasarlanmamıştır.
- Karantina ve raporlar `~/.local/share/reworkbench` altında kalır. Hassas veri içerebilir; depo şifrelenmez.
- Dinamik analiz kapalı başlar. Yerel **rootless Podman ≥4.6**, cgroup v2/controller'ları ve `REWB_SANDBOX_IMAGE` içinde sabit yerel `sha256:…` image ID gerekir. Ağ kapalıdır; örnek ana sistemde doğrudan çalıştırılmaz ve komut açık onay ister.
- `sandbox/Containerfile`, Python ve strace içeren imaj için hazırlık şablonudur. Denetlenmiş Ubuntu digest'i `BASE` olarak verilmelidir. Apt revizyonları şablonda sabit değildir; hazır/doğrulanmış bir sandbox imajı teslim edilmez. Dinamik akış deneyseldir.
- Ubuntu 22.04/24.04 temiz kurulum, canlı tarayıcı, gerçek MCP HTTP/SSE ve Podman kabul testleri geliştirme ortamı kısıtları nedeniyle henüz tamamlanmadı.

## Testler

```bash
python3 -m unittest discover -s tests -v
```

İsteğe bağlı geliştirme paketleri:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.lock
./scripts/validate.sh
```

Doğrulama betiği testleri, varsa Node frontend kontrollerini ve ruff biçim/lint denetimini çalıştırır. Eksik bağımlılık, ekran veya socket izni gerektiren testler atlanabilir; atlanan test başarı sayılmaz. Testlerde gerçek zararlı örnek bulunmaz.

## Lisans

[MIT](LICENSE)
