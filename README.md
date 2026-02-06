# Oracle Cloud Ücretsiz Instance Otomatik Oluşturucu

Oracle Cloud Always Free Tier için instance oluşturmayı, kapasite bulunana kadar otomatik olarak tekrar deneyen Flask web uygulaması.

## Özellikler

- OCI kimlik bilgileriyle web arayüzünden task başlatma
- Kapasite yoksa (`Out of host capacity`) otomatik retry
- Canlı durum ekranı (polling, progress, stop)
- Güvenli durdurma (task gerçekten kesilir)
- Otomatik eski task temizleme
- Docker + Gunicorn ile üretim çalıştırma
- GitHub Actions CI (syntax + test)

## Ortam Değişkenleri

`.env.example` içeriği:

```env
SESSION_SECRET=change-me
FLASK_DEBUG=false
PORT=5000
```

## Yerelde Çalıştırma

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Uygulama varsayılan olarak `http://127.0.0.1:5000` adresinde açılır.

## Docker ile Çalıştırma

```bash
docker compose up --build
```

## GitHub Web Üzerinden Çalıştırma (Codespaces)

Bu repo `.devcontainer/devcontainer.json` içerir. GitHub Codespaces üzerinde:

En hızlı yol:

- Doğrudan bu linki aç: `https://codespaces.new/cenkgevgili/oracle-cloud-auto-creator`
- Açılan sayfada `Create codespace` ile başlat

Alternatif adımlar:

1. GitHub repo sayfasında `Code` -> `Codespaces` -> `Create codespace on master`
2. Container açıldığında bağımlılıklar otomatik kurulur
3. Terminalde çalıştır:

```bash
python app.py
```

4. `5000` portunu public/preview olarak açıp web arayüzüne eriş

## CI (GitHub Actions)

`.github/workflows/ci.yml` her push/PR için:

- bağımlılık kurulumu
- `python -m py_compile app.py`
- `python -m unittest discover -s tests -v`

## Güvenlik Notları

- `SESSION_SECRET` üretimde mutlaka güçlü bir değer olmalıdır.
- `private_key` tarayıcı `localStorage` içine artık yazılmaz.
- Task durumu bellekte tutulduğu için çoklu process worker desteklenmez; bu yüzden `gunicorn --workers 1` kullanılır.
