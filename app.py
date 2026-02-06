#!/usr/bin/env python3
"""
Oracle Cloud Ücretsiz Instance Otomatik Oluşturucu - Web Arayüzü
"""

import logging
import os
import threading
import time
import uuid
from datetime import datetime

import oci
from flask import Flask, jsonify, render_template, request
from flask_session import Session

# Log ayarları
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("oci_web_creator.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

TERMINAL_STATES = {"success", "failed", "error", "stopped"}
VALID_SHAPES = {"VM.Standard.E2.1.Micro", "VM.Standard.A1.Flex"}
TASK_CLEANUP_SECONDS = int(os.environ.get("TASK_CLEANUP_SECONDS", "10800"))
TASK_CLEANUP_INTERVAL_SECONDS = int(os.environ.get("TASK_CLEANUP_INTERVAL_SECONDS", "3600"))
REQUIRED_FIELDS = [
    "user_ocid",
    "tenancy_ocid",
    "compartment_ocid",
    "subnet_ocid",
    "availability_domain",
    "image_ocid",
    "ssh_public_key",
    "fingerprint",
    "private_key",
]
SUPPORTED_SSH_KEY_TYPES = {
    "ssh-rsa",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
}

# Flask uygulamasını oluştur
app = Flask(__name__)
session_secret = os.environ.get("SESSION_SECRET")
if not session_secret:
    session_secret = uuid.uuid4().hex
    logger.warning(
        "SESSION_SECRET ortam değişkeni ayarlı değil. Geçici bir key üretildi; prod ortamında sabit bir SESSION_SECRET ayarlayın."
    )

app.secret_key = session_secret
app.config["SESSION_TYPE"] = "filesystem"
app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 saat
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if os.environ.get("SESSION_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}:
    app.config["SESSION_COOKIE_SECURE"] = True
Session(app)

# Çalışan task'ları saklamak için global sözlük
active_tasks = {}
active_tasks_lock = threading.Lock()
cleanup_thread_started = False
cleanup_thread_lock = threading.Lock()


def parse_int(value, default, minimum=None, maximum=None):
    """Güvenli int parse et."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default

    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def get_missing_required_fields(data):
    """Eksik veya boş zorunlu alanları döndür."""
    missing_fields = []
    for field in REQUIRED_FIELDS:
        value = data.get(field)
        if not isinstance(value, str) or not value.strip():
            missing_fields.append(field)
    return missing_fields


def build_oci_config(data):
    """OCI SDK için config oluştur."""
    return {
        "user": data.get("user_ocid", "").strip(),
        "key_content": data.get("private_key", "").strip(),
        "fingerprint": data.get("fingerprint", "").strip(),
        "tenancy": data.get("tenancy_ocid", "").strip(),
        "region": data.get("region", "us-ashburn-1").strip(),
    }


def validate_ssh_public_key_format(ssh_public_key):
    """SSH public key formatını kontrol et."""
    if not isinstance(ssh_public_key, str):
        return False, "SSH Public Key metin olmalıdır."

    parts = ssh_public_key.strip().split()
    if len(parts) < 2:
        return False, "SSH Public Key eksik görünüyor. Format: ssh-ed25519 AAAA... kullanıcı@cihaz"

    key_type, key_value = parts[0], parts[1]
    if key_type not in SUPPORTED_SSH_KEY_TYPES:
        return False, (
            "SSH Public Key tipi desteklenmiyor. Desteklenen tipler: "
            "ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256/384/521"
        )

    if len(key_value) < 16:
        return False, "SSH Public Key değeri eksik veya bozuk görünüyor."

    return True, "SSH Public Key formatı geçerli."


def classify_oci_service_error(error, step):
    """OCI ServiceError için alan bazlı kullanıcı mesajı üret."""
    status = getattr(error, "status", None)
    code = getattr(error, "code", "") or "unknown"
    message = str(getattr(error, "message", error))
    status_text = f"HTTP {status}" if status is not None else "HTTP bilinmiyor"
    suffix = f" ({status_text}, code: {code})"

    if step == "auth":
        fields = ["user_ocid", "tenancy_ocid", "fingerprint", "private_key", "region"]
        if status == 401:
            detail = "Kimlik doğrulama başarısız."
        elif status in {403, 404}:
            detail = "Tenancy/User/Region bilgileriyle yetki doğrulanamadı."
        else:
            detail = "OCI kimlik doğrulama sırasında hata oluştu."
        return fields, f"{detail}{suffix}"

    if step == "subnet":
        fields = ["subnet_ocid", "compartment_ocid", "region"]
        if status == 404:
            detail = "Subnet bulunamadı veya bu kullanıcı tarafından erişilemiyor."
        elif status in {401, 403}:
            detail = "Subnet için yetki doğrulaması başarısız."
        else:
            detail = "Subnet kontrolünde hata oluştu."
        return fields, f"{detail}{suffix}"

    if step == "image":
        fields = ["image_ocid", "region"]
        if status == 404:
            detail = "Image OCID bulunamadı."
        elif status in {401, 403}:
            detail = "Image bilgisine erişim yetkisi yok."
        else:
            detail = "Image kontrolünde hata oluştu."
        return fields, f"{detail}{suffix}"

    return [], f"Beklenmeyen OCI hatası: {message[:200]}{suffix}"


def build_connection_test_failure(message, invalid_fields, checks, status_code=400):
    """Connection test için standart başarısız payload."""
    unique_fields = sorted(set(invalid_fields))
    return (
        jsonify(
            {
                "success": False,
                "connected": False,
                "message": message,
                "invalid_fields": unique_fields,
                "checks": checks,
            }
        ),
        status_code,
    )


def validate_start_payload(data):
    """API payload doğrulaması."""
    missing_fields = get_missing_required_fields(data)
    if missing_fields:
        return f"Eksik veya geçersiz alan: {missing_fields[0]}"

    shape = data.get("shape", "VM.Standard.E2.1.Micro")
    if shape not in VALID_SHAPES:
        return f"Desteklenmeyen shape: {shape}"

    max_attempts = parse_int(data.get("max_attempts"), 50, minimum=1, maximum=5000)
    retry_interval = parse_int(data.get("retry_interval"), 300, minimum=5, maximum=86400)
    if max_attempts < 1:
        return "max_attempts en az 1 olmalıdır"
    if retry_interval < 5:
        return "retry_interval en az 5 saniye olmalıdır"

    if shape == "VM.Standard.A1.Flex":
        shape_config = data.get("shape_config") or {}
        ocpus = parse_int(shape_config.get("ocpus", data.get("ocpus")), 1, minimum=1, maximum=4)
        memory_gb = parse_int(
            shape_config.get("memory_in_gbs", data.get("memory_gb")),
            ocpus * 6,
            minimum=6,
            maximum=24,
        )
        if memory_gb != ocpus * 6:
            return "A1.Flex için memory_in_gbs, ocpus * 6 olmalıdır"

    return None


class OCIInstanceCreator:
    def __init__(self, config_data, task_id):
        """
        OCI Instance Creator başlatıcı
        """
        self.task_id = task_id
        self.status = "initializing"
        self.progress = 0
        self.message = "Başlatılıyor..."
        self.instance_id = None
        self.attempts = 0
        self.last_update = datetime.now()
        self.init_error = None
        self.stop_event = threading.Event()
        self.state_lock = threading.Lock()

        # OCI konfigürasyonu
        self.config = {
            "user": config_data.get("user_ocid", "").strip(),
            "key_content": config_data.get("private_key", "").strip(),
            "fingerprint": config_data.get("fingerprint", "").strip(),
            "tenancy": config_data.get("tenancy_ocid", "").strip(),
            "region": config_data.get("region", "us-ashburn-1").strip(),
        }

        selected_shape = config_data.get("shape", "VM.Standard.E2.1.Micro")
        if selected_shape not in VALID_SHAPES:
            selected_shape = "VM.Standard.E2.1.Micro"

        # Instance ayarları
        self.instance_config = {
            "compartment_id": config_data.get("compartment_ocid", "").strip(),
            "subnet_id": config_data.get("subnet_ocid", "").strip(),
            "availability_domain": config_data.get("availability_domain", "").strip(),
            "shape": selected_shape,
            "image_id": config_data.get("image_ocid", "").strip(),
            "ssh_key": config_data.get("ssh_public_key", "").strip(),
            "instance_name": (config_data.get("instance_name") or "free-tier-instance").strip(),
        }

        # Shape config
        self.ocpus = 1
        self.memory_gb = 1
        shape_config_data = config_data.get("shape_config") or {}
        if self.instance_config["shape"] == "VM.Standard.A1.Flex":
            self.ocpus = parse_int(shape_config_data.get("ocpus", config_data.get("ocpus")), 1, minimum=1, maximum=4)
            self.memory_gb = parse_int(
                shape_config_data.get("memory_in_gbs", config_data.get("memory_gb")),
                self.ocpus * 6,
                minimum=6,
                maximum=24,
            )
            # A1.Flex oranı sabit: 1 OCPU = 6 GB RAM
            self.memory_gb = self.ocpus * 6

        # Deneme ayarları
        self.max_attempts = parse_int(config_data.get("max_attempts"), 50, minimum=1, maximum=5000)
        self.retry_interval = parse_int(config_data.get("retry_interval"), 300, minimum=5, maximum=86400)

        # OCI client'ları
        try:
            self.compute_client = oci.core.ComputeClient(self.config)
            self.virtual_network_client = oci.core.VirtualNetworkClient(self.config)
            self.status = "ready"
            self.message = "OCI bağlantısı başarılı"
        except Exception as error:
            self.init_error = str(error)
            self.status = "error"
            self.message = f"OCI bağlantı hatası: {self.init_error}"
            logger.error("OCI bağlantı hatası: %s", error)

    def update_status(self, status, message, progress=None):
        """Durumu güncelle."""
        with self.state_lock:
            self.status = status
            self.message = message
            if progress is not None:
                self.progress = progress
            self.last_update = datetime.now()
        logger.info("Task %s: %s - %s", self.task_id, status, message)

    def stop(self, message="Kullanıcı tarafından durduruldu"):
        """Task'ı güvenli şekilde durdur."""
        self.stop_event.set()
        self.update_status("stopped", message)

    def is_stopped(self):
        """Task'ın durdurulup durdurulmadığını kontrol et."""
        return self.stop_event.is_set()

    def snapshot(self):
        """Task durumunun thread-safe kopyasını döndür."""
        with self.state_lock:
            return {
                "status": self.status,
                "message": self.message,
                "progress": self.progress,
                "attempts": self.attempts,
                "max_attempts": self.max_attempts,
                "instance_id": self.instance_id,
                "last_update": self.last_update.strftime("%Y-%m-%d %H:%M:%S"),
                "shape": self.instance_config["shape"],
                "ocpus": self.ocpus,
                "memory_gb": self.memory_gb,
            }

    def sleep_with_stop(self, total_seconds):
        """Bekleme sırasında stop isteğini dinle."""
        for _ in range(max(0, int(total_seconds))):
            if self.is_stopped():
                return False
            time.sleep(1)
        return True

    def create_instance(self, attempt_number):
        """Instance oluşturma denemesi."""
        if self.is_stopped():
            return False

        instance_name = f"{self.instance_config['instance_name']}-{attempt_number}-{int(time.time())}"
        launch_kwargs = {
            "display_name": instance_name,
            "compartment_id": self.instance_config["compartment_id"],
            "availability_domain": self.instance_config["availability_domain"],
            "shape": self.instance_config["shape"],
            "subnet_id": self.instance_config["subnet_id"],
            "source_details": oci.core.models.InstanceSourceViaImageDetails(
                source_type="image",
                image_id=self.instance_config["image_id"],
            ),
            "metadata": {
                "ssh_authorized_keys": self.instance_config["ssh_key"],
            },
            "create_vnic_details": oci.core.models.CreateVnicDetails(
                subnet_id=self.instance_config["subnet_id"],
                assign_public_ip=True,
            ),
        }

        if self.instance_config["shape"] == "VM.Standard.A1.Flex":
            launch_kwargs["shape_config"] = oci.core.models.LaunchInstanceShapeConfigDetails(
                ocpus=self.ocpus,
                memory_in_gbs=self.memory_gb,
            )

        instance_details = oci.core.models.LaunchInstanceDetails(**launch_kwargs)

        try:
            self.update_status(
                "trying",
                (
                    f"Deneme #{attempt_number}: {instance_name} oluşturuluyor...\n"
                    f"Shape: {self.instance_config['shape']}\n"
                    f"OCPU: {self.ocpus}, RAM: {self.memory_gb} GB"
                ),
                progress=min(95, int((attempt_number / self.max_attempts) * 100)),
            )

            response = self.compute_client.launch_instance(instance_details)
            if response.status in {200, 201}:
                with self.state_lock:
                    self.instance_id = response.data.id
                self.update_status(
                    "success",
                    (
                        "✓ BAŞARILI! Instance oluşturuldu!\n"
                        f"Instance ID: {self.instance_id}\n"
                        f"Instance Adı: {instance_name}\n"
                        f"Shape: {self.instance_config['shape']} ({self.ocpus} OCPU, {self.memory_gb} GB RAM)\n"
                        f"Durum: {response.data.lifecycle_state}"
                    ),
                    progress=100,
                )
                return True

            self.update_status("warning", f"Beklenmeyen yanıt: {response.status}")
            return False

        except oci.exceptions.ServiceError as error:
            error_message = str(getattr(error, "message", error))
            if error.status == 500 and "Out of host capacity" in error_message:
                self.update_status(
                    "retrying",
                    (
                        f"X Kapasite yok (Deneme #{attempt_number})\n"
                        f"Bir sonraki deneme için {self.retry_interval} saniye bekleniyor..."
                    ),
                )
                return False
            if error.status == 429:
                self.update_status(
                    "retrying",
                    (
                        f"X Rate limit aşıldı (Deneme #{attempt_number})\n"
                        "60 saniye bekleniyor..."
                    ),
                )
                self.sleep_with_stop(60)
                return False

            self.update_status("error", f"! OCI Hatası (Deneme #{attempt_number}): {str(error)[:160]}")
            return False
        except Exception as error:
            self.update_status("error", f"! Genel hata (Deneme #{attempt_number}): {str(error)[:160]}")
            return False

    def check_existing_instances(self):
        """Mevcut ücretsiz instance'ları kontrol et."""
        try:
            list_instances_response = self.compute_client.list_instances(
                compartment_id=self.instance_config["compartment_id"]
            )

            free_instances = []
            for instance in list_instances_response.data:
                if "VM.Standard.E2.1.Micro" in instance.shape or "VM.Standard.A1.Flex" in instance.shape:
                    free_instances.append(
                        {
                            "name": instance.display_name,
                            "id": instance.id,
                            "status": instance.lifecycle_state,
                            "shape": instance.shape,
                            "created": str(instance.time_created),
                        }
                    )

            return free_instances
        except Exception as error:
            logger.error("Instance kontrol hatası: %s", error)
            return []

    def run(self):
        """Ana çalıştırma fonksiyonu."""
        if self.init_error:
            return

        success = False
        try:
            if self.is_stopped():
                self.update_status("stopped", "Task başlatılmadan durduruldu")
                return

            # Mevcut instance'ları kontrol et
            self.update_status("checking", "Mevcut instance'lar kontrol ediliyor...", progress=5)
            existing_instances = self.check_existing_instances()

            if existing_instances:
                self.update_status(
                    "info",
                    (
                        f"Mevcut {len(existing_instances)} ücretsiz instance bulundu:\n"
                        + "\n".join(
                            [f"  - {instance['name']} ({instance['status']})" for instance in existing_instances[:3]]
                        )
                    ),
                    progress=10,
                )

            # Deneme döngüsü
            for attempt in range(1, self.max_attempts + 1):
                if self.is_stopped():
                    self.update_status("stopped", "Kullanıcı tarafından durduruldu")
                    return

                with self.state_lock:
                    self.attempts = attempt

                self.update_status(
                    "trying",
                    f"Deneme #{attempt}/{self.max_attempts}\nBaşlangıç: {datetime.now().strftime('%H:%M:%S')}",
                    progress=min(90, int((attempt / self.max_attempts) * 90)),
                )
                success = self.create_instance(attempt)
                if success:
                    return

                if attempt >= self.max_attempts:
                    break

                for elapsed in range(self.retry_interval):
                    if self.is_stopped():
                        self.update_status("stopped", "Kullanıcı tarafından durduruldu")
                        return

                    if elapsed % 30 == 0 or elapsed == 0:
                        self.update_status(
                            "waiting",
                            (
                                f"Bekleniyor... ({elapsed}/{self.retry_interval} saniye)\n"
                                "Sonraki deneme: "
                                + datetime.fromtimestamp(time.time() + self.retry_interval - elapsed).strftime("%H:%M:%S")
                            ),
                        )
                    time.sleep(1)

            if not success and self.snapshot()["status"] not in TERMINAL_STATES:
                self.update_status(
                    "failed",
                    (
                        f"X Maksimum deneme sayısına ulaşıldı ({self.max_attempts})\n"
                        "Lütfen daha sonra tekrar deneyin veya başka bir bölge seçin."
                    ),
                    progress=100,
                )
        except Exception as error:
            self.update_status("error", f"! Çalıştırma hatası: {str(error)[:200]}")
            logger.error("Task %s çalıştırma hatası: %s", self.task_id, error)


def cleanup_expired_tasks():
    """Süresi dolan task kayıtlarını temizle."""
    now = datetime.now()
    removed = 0
    with active_tasks_lock:
        expired_ids = [
            task_id
            for task_id, creator in active_tasks.items()
            if (now - creator.last_update).total_seconds() > TASK_CLEANUP_SECONDS
        ]
        for task_id in expired_ids:
            del active_tasks[task_id]
            removed += 1
    return removed


def cleanup_loop():
    """Periyodik task temizleme döngüsü."""
    while True:
        time.sleep(TASK_CLEANUP_INTERVAL_SECONDS)
        try:
            removed_count = cleanup_expired_tasks()
            if removed_count:
                logger.info("Eski %s task temizlendi", removed_count)
        except Exception as error:
            logger.error("Temizleme hatası: %s", error)


def ensure_cleanup_thread():
    """Cleanup thread'i sadece bir kez başlat."""
    global cleanup_thread_started
    with cleanup_thread_lock:
        if cleanup_thread_started:
            return
        cleanup = threading.Thread(target=cleanup_loop, daemon=True, name="task-cleanup")
        cleanup.start()
        cleanup_thread_started = True


if os.environ.get("ENABLE_TASK_CLEANUP_THREAD", "true").lower() in {"1", "true", "yes"}:
    ensure_cleanup_thread()


# Web Routes
@app.route("/")
def index():
    """Ana sayfa."""
    return render_template("index.html")


@app.route("/configure", methods=["GET"])
def configure():
    """Konfigürasyon sayfası."""
    return render_template("configure.html")


@app.route("/status")
def status_page():
    """Durum sayfası."""
    task_id = request.args.get("task_id")
    return render_template("status.html", task_id=task_id)


@app.route("/health")
def health():
    """Basit health endpoint."""
    return jsonify({"success": True, "status": "ok"})


@app.route("/api/test_connection", methods=["POST"])
def test_connection():
    """Girilen OCI bilgileriyle bağlantı testi yap."""
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type application/json olmalıdır"}), 415

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "Geçersiz JSON payload"}), 400

    checks = []
    missing_fields = get_missing_required_fields(data)
    if missing_fields:
        checks.append(
            {
                "name": "Zorunlu alan kontrolü",
                "success": False,
                "message": "Bazı zorunlu alanlar boş veya geçersiz.",
            }
        )
        return build_connection_test_failure(
            "Bağlantı testi başlatılamadı. Eksik alanları doldurun.",
            invalid_fields=missing_fields,
            checks=checks,
            status_code=400,
        )

    ssh_ok, ssh_message = validate_ssh_public_key_format(data.get("ssh_public_key", ""))
    if not ssh_ok:
        checks.append({"name": "SSH Public Key formatı", "success": False, "message": ssh_message})
        return build_connection_test_failure(
            "SSH Public Key formatı hatalı.",
            invalid_fields=["ssh_public_key"],
            checks=checks,
            status_code=400,
        )
    checks.append({"name": "SSH Public Key formatı", "success": True, "message": ssh_message})

    config = build_oci_config(data)

    # 1) Kimlik doğrulama + region/tenancy kontrolü
    try:
        identity_client = oci.identity.IdentityClient(config)
        ad_response = identity_client.list_availability_domains(compartment_id=config["tenancy"])
        available_ad_names = {item.name for item in ad_response.data}
        checks.append(
            {
                "name": "OCI kimlik doğrulama",
                "success": True,
                "message": "Oracle API bağlantısı başarılı.",
            }
        )
    except oci.exceptions.ServiceError as error:
        invalid_fields, error_message = classify_oci_service_error(error, "auth")
        checks.append({"name": "OCI kimlik doğrulama", "success": False, "message": error_message})
        return build_connection_test_failure(
            "Oracle bağlantısı doğrulanamadı.",
            invalid_fields=invalid_fields,
            checks=checks,
            status_code=400,
        )
    except Exception as error:
        error_message = f"OCI kimlik doğrulama sırasında beklenmeyen hata: {str(error)[:200]}"
        checks.append({"name": "OCI kimlik doğrulama", "success": False, "message": error_message})
        return build_connection_test_failure(
            "Oracle bağlantısı doğrulanamadı.",
            invalid_fields=["user_ocid", "tenancy_ocid", "fingerprint", "private_key", "region"],
            checks=checks,
            status_code=400,
        )

    # 2) Availability Domain kontrolü
    availability_domain = data.get("availability_domain", "").strip()
    if availability_domain not in available_ad_names:
        checks.append(
            {
                "name": "Availability Domain kontrolü",
                "success": False,
                "message": "Girilen Availability Domain bu tenancy/region altında bulunamadı.",
            }
        )
        return build_connection_test_failure(
            "Availability Domain doğrulaması başarısız.",
            invalid_fields=["availability_domain", "region"],
            checks=checks,
            status_code=400,
        )
    checks.append(
        {
            "name": "Availability Domain kontrolü",
            "success": True,
            "message": "Availability Domain bilgisi geçerli.",
        }
    )

    # 3) Subnet kontrolü
    subnet_compartment_id = ""
    try:
        virtual_network_client = oci.core.VirtualNetworkClient(config)
        subnet_response = virtual_network_client.get_subnet(data.get("subnet_ocid", "").strip())
        subnet_compartment_id = (getattr(subnet_response.data, "compartment_id", "") or "").strip()
        checks.append(
            {
                "name": "Subnet OCID kontrolü",
                "success": True,
                "message": "Subnet erişilebilir.",
            }
        )
    except oci.exceptions.ServiceError as error:
        invalid_fields, error_message = classify_oci_service_error(error, "subnet")
        checks.append({"name": "Subnet OCID kontrolü", "success": False, "message": error_message})
        return build_connection_test_failure(
            "Subnet doğrulaması başarısız.",
            invalid_fields=invalid_fields,
            checks=checks,
            status_code=400,
        )
    except Exception as error:
        error_message = f"Subnet kontrolü sırasında beklenmeyen hata: {str(error)[:200]}"
        checks.append({"name": "Subnet OCID kontrolü", "success": False, "message": error_message})
        return build_connection_test_failure(
            "Subnet doğrulaması başarısız.",
            invalid_fields=["subnet_ocid", "compartment_ocid", "region"],
            checks=checks,
            status_code=400,
        )

    # 4) Subnet ile compartment eşleşmesi
    compartment_ocid = data.get("compartment_ocid", "").strip()
    if subnet_compartment_id and compartment_ocid and subnet_compartment_id != compartment_ocid:
        checks.append(
            {
                "name": "Compartment/Subnet eşleşmesi",
                "success": False,
                "message": "Subnet farklı bir compartment içinde görünüyor.",
            }
        )
        return build_connection_test_failure(
            "Compartment ve subnet bilgileri birbiriyle uyuşmuyor.",
            invalid_fields=["compartment_ocid", "subnet_ocid"],
            checks=checks,
            status_code=400,
        )
    checks.append(
        {
            "name": "Compartment/Subnet eşleşmesi",
            "success": True,
            "message": "Compartment ve subnet bilgileri uyumlu.",
        }
    )

    # 5) Image kontrolü
    try:
        compute_client = oci.core.ComputeClient(config)
        image_response = compute_client.get_image(data.get("image_ocid", "").strip())
        image_state = getattr(image_response.data, "lifecycle_state", None)
        image_message = "Image OCID erişilebilir."
        if image_state:
            image_message = f"Image OCID erişilebilir (durum: {image_state})."
        checks.append(
            {
                "name": "Image OCID kontrolü",
                "success": True,
                "message": image_message,
            }
        )
    except oci.exceptions.ServiceError as error:
        invalid_fields, error_message = classify_oci_service_error(error, "image")
        checks.append({"name": "Image OCID kontrolü", "success": False, "message": error_message})
        return build_connection_test_failure(
            "Image doğrulaması başarısız.",
            invalid_fields=invalid_fields,
            checks=checks,
            status_code=400,
        )
    except Exception as error:
        error_message = f"Image kontrolü sırasında beklenmeyen hata: {str(error)[:200]}"
        checks.append({"name": "Image OCID kontrolü", "success": False, "message": error_message})
        return build_connection_test_failure(
            "Image doğrulaması başarısız.",
            invalid_fields=["image_ocid", "region"],
            checks=checks,
            status_code=400,
        )

    return jsonify(
        {
            "success": True,
            "connected": True,
            "message": "Oracle bağlantı testi başarılı. Girilen bilgiler doğrulandı.",
            "invalid_fields": [],
            "checks": checks,
        }
    )


@app.route("/api/start_task", methods=["POST"])
def start_task():
    """Yeni bir task başlat."""
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type application/json olmalıdır"}), 415

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "Geçersiz JSON payload"}), 400

    validation_error = validate_start_payload(data)
    if validation_error:
        return jsonify({"success": False, "error": validation_error}), 400

    try:
        # Yeni task ID oluştur
        task_id = str(uuid.uuid4())[:8]
        creator = OCIInstanceCreator(data, task_id)
        if creator.init_error:
            return jsonify({"success": False, "error": creator.message}), 400

        # Task'ı aktif listeye ekle
        with active_tasks_lock:
            active_tasks[task_id] = creator

        # Thread'de çalıştır
        worker = threading.Thread(target=creator.run, daemon=True, name=f"task-{task_id}")
        worker.start()

        return jsonify(
            {
                "success": True,
                "task_id": task_id,
                "message": "Task başlatıldı",
            }
        )
    except Exception as error:
        logger.error("Task başlatma hatası: %s", error)
        return jsonify({"success": False, "error": "Task başlatılamadı"}), 500


@app.route("/api/task_status/<task_id>")
def get_task_status(task_id):
    """Task durumunu getir."""
    with active_tasks_lock:
        creator = active_tasks.get(task_id)

    if creator is None:
        return jsonify({"success": False, "error": "Task bulunamadı"}), 404

    payload = creator.snapshot()
    payload["success"] = True
    return jsonify(payload)


@app.route("/api/stop_task/<task_id>", methods=["POST"])
def stop_task(task_id):
    """Task'ı durdur."""
    with active_tasks_lock:
        creator = active_tasks.get(task_id)

    if creator is None:
        return jsonify({"success": False, "error": "Task bulunamadı"}), 404

    creator.stop()
    return jsonify({"success": True})


@app.route("/api/cleanup_old_tasks", methods=["POST"])
def cleanup_old_tasks():
    """Eski task'ları temizle."""
    try:
        removed_count = cleanup_expired_tasks()
        with active_tasks_lock:
            remaining_count = len(active_tasks)
        return jsonify({"success": True, "removed": removed_count, "remaining": remaining_count})
    except Exception as error:
        logger.error("Manual cleanup hatası: %s", error)
        return jsonify({"success": False, "error": "Task temizleme başarısız"}), 500


@app.route("/api/get_regions")
def get_regions():
    """OCI bölgelerini getir."""
    regions = [
        {"id": "us-ashburn-1", "name": "US East (Ashburn)"},
        {"id": "us-phoenix-1", "name": "US West (Phoenix)"},
        {"id": "eu-frankfurt-1", "name": "Germany Central (Frankfurt)"},
        {"id": "uk-london-1", "name": "UK South (London)"},
        {"id": "ca-toronto-1", "name": "Canada Southeast (Toronto)"},
        {"id": "ap-sydney-1", "name": "Australia East (Sydney)"},
        {"id": "ap-mumbai-1", "name": "India West (Mumbai)"},
        {"id": "ap-tokyo-1", "name": "Japan East (Tokyo)"},
        {"id": "ap-seoul-1", "name": "South Korea Central (Seoul)"},
        {"id": "me-jeddah-1", "name": "Saudi Arabia West (Jeddah)"},
        {"id": "sa-saopaulo-1", "name": "Brazil East (Sao Paulo)"},
    ]
    return jsonify({"success": True, "regions": regions})


@app.route("/api/get_free_shapes")
def get_free_shapes():
    """Ücretsiz shape'leri getir."""
    shapes = [
        {
            "id": "VM.Standard.E2.1.Micro",
            "name": "VM.Standard.E2.1.Micro (1 OCPU, 1 GB RAM - Always Free)",
        },
        {
            "id": "VM.Standard.A1.Flex",
            "name": "VM.Standard.A1.Flex (1-4 OCPU, 6-24 GB RAM - Always Free Monthly Limit)",
        },
    ]
    return jsonify({"success": True, "shapes": shapes})


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = parse_int(os.environ.get("PORT"), 5050, minimum=1, maximum=65535)
    debug = os.environ.get("FLASK_DEBUG", "false").lower() in {"1", "true", "yes"}
    app.run(host=host, port=port, debug=debug)
