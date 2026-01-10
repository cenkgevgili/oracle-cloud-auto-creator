#!/usr/bin/env python3
"""
Oracle Cloud Ücretsiz Instance Otomatik Oluşturucu - Web Arayüzü
"""

import os
import json
import time
import threading
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_session import Session
import oci
import uuid

# Flask uygulamasını oluştur
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "oracle-cloud-secret-key-2024")
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 saat
Session(app)

# Log ayarları
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('oci_web_creator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Çalışan task'ları saklamak için global sözlük
active_tasks = {}

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
        
        # OCI konfigürasyonu
        self.config = {
            "user": config_data.get("user_ocid"),
            "key_content": config_data.get("private_key"),
            "fingerprint": config_data.get("fingerprint"),
            "tenancy": config_data.get("tenancy_ocid"),
            "region": config_data.get("region", "us-ashburn-1")
        }
        
        # Instance ayarları
        self.instance_config = {
            "compartment_id": config_data.get("compartment_ocid"),
            "subnet_id": config_data.get("subnet_ocid"),
            "availability_domain": config_data.get("availability_domain"),
            "shape": config_data.get("shape", "VM.Standard.E2.1.Micro"),
            "image_id": config_data.get("image_ocid"),
            "ssh_key": config_data.get("ssh_public_key"),
            "instance_name": config_data.get("instance_name", "free-tier-instance")
        }
        
        # Deneme ayarları
        self.max_attempts = int(config_data.get("max_attempts", 50))
        self.retry_interval = int(config_data.get("retry_interval", 300))
        
        # OCI client'ları
        try:
            self.compute_client = oci.core.ComputeClient(self.config)
            self.virtual_network_client = oci.core.VirtualNetworkClient(self.config)
            self.status = "ready"
            self.message = "OCI bağlantısı başarılı"
        except Exception as e:
            self.status = "error"
            self.message = f"OCI bağlantı hatası: {str(e)}"
            logger.error(f"OCI bağlantı hatası: {e}")
    
    def update_status(self, status, message, progress=None):
        """Durumu güncelle"""
        self.status = status
        self.message = message
        if progress is not None:
            self.progress = progress
        self.last_update = datetime.now()
        logger.info(f"Task {self.task_id}: {status} - {message}")
    
    def create_instance(self, attempt_number):
        """Instance oluşturma denemesi"""
        instance_name = f"{self.instance_config['instance_name']}-{attempt_number}-{int(time.time())}"
        
        # Instance detayları
        instance_details = oci.core.models.LaunchInstanceDetails(
            display_name=instance_name,
            compartment_id=self.instance_config['compartment_id'],
            availability_domain=self.instance_config['availability_domain'],
            shape=self.instance_config['shape'],
            subnet_id=self.instance_config['subnet_id'],
            source_details=oci.core.models.InstanceSourceViaImageDetails(
                source_type="image",
                image_id=self.instance_config['image_id']
            ),
            metadata={
                "ssh_authorized_keys": self.instance_config['ssh_key']
            },
            shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
                ocpus=1,
                memory_in_gbs=1
            ),
            create_vnic_details=oci.core.models.CreateVnicDetails(
                subnet_id=self.instance_config['subnet_id'],
                assign_public_ip=True
            )
        )
        
        try:
            self.update_status("trying", f"Deneme #{attempt_number}: {instance_name} oluşturuluyor...", 
                              progress=int((attempt_number/self.max_attempts)*100))
            
            response = self.compute_client.launch_instance(instance_details)
            
            if response.status == 200:
                self.instance_id = response.data.id
                self.update_status("success", 
                    f"✓ BAŞARILI! Instance oluşturuldu!\n"
                    f"Instance ID: {self.instance_id}\n"
                    f"Instance Adı: {instance_name}\n"
                    f"Durum: {response.data.lifecycle_state}",
                    progress=100)
                return True
            else:
                self.update_status("warning", f"Beklenmeyen yanıt: {response.status}")
                return False
                
        except oci.exceptions.ServiceError as e:
            if e.status == 500 and "Out of host capacity" in str(e.message):
                self.update_status("retrying", 
                    f"X Kapasite yok (Deneme #{attempt_number})\n"
                    f"Bir sonraki deneme için {self.retry_interval} saniye bekleniyor...")
                return False
            elif e.status == 429:
                self.update_status("retrying", 
                    f"X Rate limit aşıldı (Deneme #{attempt_number})\n"
                    f"60 saniye bekleniyor...")
                time.sleep(60)
                return False
            else:
                self.update_status("error", f"! OCI Hatası (Deneme #{attempt_number}): {str(e)[:100]}")
                return False
        except Exception as e:
            self.update_status("error", f"! Genel hata (Deneme #{attempt_number}): {str(e)[:100]}")
            return False
    
    def check_existing_instances(self):
        """Mevcut ücretsiz instance'ları kontrol et"""
        try:
            list_instances_response = self.compute_client.list_instances(
                compartment_id=self.instance_config['compartment_id']
            )
            
            free_instances = []
            for instance in list_instances_response.data:
                if "VM.Standard.E2.1.Micro" in instance.shape:
                    free_instances.append({
                        "name": instance.display_name,
                        "id": instance.id,
                        "status": instance.lifecycle_state,
                        "shape": instance.shape,
                        "created": str(instance.time_created)
                    })
            
            return free_instances
        except Exception as e:
            logger.error(f"Instance kontrol hatası: {e}")
            return []
    
    def run(self):
        """Ana çalıştırma fonksiyonu"""
        try:
            # Mevcut instance'ları kontrol et
            self.update_status("checking", "Mevcut instance'lar kontrol ediliyor...", progress=5)
            existing_instances = self.check_existing_instances()
            
            if existing_instances:
                self.update_status("info", 
                    f"Mevcut {len(existing_instances)} ücretsiz instance bulundu:\n" +
                    "\n".join([f"  - {inst['name']} ({inst['status']})" for inst in existing_instances[:3]]),
                    progress=10)
            
            # Deneme döngüsü
            for attempt in range(1, self.max_attempts + 1):
                self.attempts = attempt
                self.update_status("trying", 
                    f"Deneme #{attempt}/{self.max_attempts}\n"
                    f"Başlangıç: {datetime.now().strftime('%H:%M:%S')}",
                    progress=int((attempt/self.max_attempts)*90))
                
                success = self.create_instance(attempt)
                
                if success:
                    break
                else:
                    if attempt < self.max_attempts:
                        # Bekleme süresi
                        for i in range(self.retry_interval):
                            if i % 30 == 0:
                                self.update_status("waiting",
                                    f"Bekleniyor... ({i}/{self.retry_interval} saniye)\n"
                                    f"Sonraki deneme: {datetime.fromtimestamp(time.time() + self.retry_interval - i).strftime('%H:%M:%S')}")
                            time.sleep(1)
            
            if not success and self.status != "success":
                self.update_status("failed",
                    f"X Maksimum deneme sayısına ulaşıldı ({self.max_attempts})\n"
                    f"Lütfen daha sonra tekrar deneyin veya başka bir bölge seçin.",
                    progress=100)
                
        except Exception as e:
            self.update_status("error", f"! Çalıştırma hatası: {str(e)[:200]}")
            logger.error(f"Task {self.task_id} çalıştırma hatası: {e}")

# Web Routes
@app.route('/')
def index():
    """Ana sayfa"""
    return render_template('index.html')

@app.route('/configure', methods=['GET'])
def configure():
    """Konfigürasyon sayfası"""
    return render_template('configure.html')

@app.route('/status')
def status_page():
    """Durum sayfası"""
    task_id = request.args.get('task_id')
    return render_template('status.html', task_id=task_id)

@app.route('/api/start_task', methods=['POST'])
def start_task():
    """Yeni bir task başlat"""
    try:
        data = request.json
        
        # Gerekli alanları kontrol et
        required_fields = [
            'user_ocid', 'tenancy_ocid', 'compartment_ocid',
            'subnet_ocid', 'availability_domain', 'image_ocid',
            'ssh_public_key'
        ]
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'error': f'Eksik alan: {field}'
                }), 400
        
        # Yeni task ID oluştur
        task_id = str(uuid.uuid4())[:8]
        
        # Task'ı oluştur ve başlat
        creator = OCIInstanceCreator(data, task_id)
        
        # Thread'de çalıştır
        thread = threading.Thread(target=creator.run)
        thread.daemon = True
        thread.start()
        
        # Task'ı aktif listeye ekle
        active_tasks[task_id] = creator
        
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Task başlatıldı'
        })
        
    except Exception as e:
        logger.error(f"Task başlatma hatası: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/task_status/<task_id>')
def get_task_status(task_id):
    """Task durumunu getir"""
    if task_id not in active_tasks:
        return jsonify({
            'success': False,
            'error': 'Task bulunamadı'
        }), 404
    
    creator = active_tasks[task_id]
    
    return jsonify({
        'success': True,
        'status': creator.status,
        'message': creator.message,
        'progress': creator.progress,
        'attempts': creator.attempts,
        'max_attempts': creator.max_attempts,
        'instance_id': creator.instance_id,
        'last_update': creator.last_update.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/api/stop_task/<task_id>', methods=['POST'])
def stop_task(task_id):
    """Task'ı durdur"""
    if task_id in active_tasks:
        creator = active_tasks[task_id]
        creator.update_status("stopped", "Kullanıcı tarafından durduruldu")
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Task bulunamadı'}), 404

@app.route('/api/cleanup_old_tasks', methods=['POST'])
def cleanup_old_tasks():
    """Eski task'ları temizle"""
    try:
        current_time = datetime.now()
        to_remove = []
        
        for task_id, creator in active_tasks.items():
            # 2 saatten eski task'ları temizle
            if (current_time - creator.last_update).total_seconds() > 7200:
                to_remove.append(task_id)
        
        for task_id in to_remove:
            del active_tasks[task_id]
        
        return jsonify({
            'success': True,
            'removed': len(to_remove),
            'remaining': len(active_tasks)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/get_regions')
def get_regions():
    """OCI bölgelerini getir"""
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
        {"id": "sa-saopaulo-1", "name": "Brazil East (São Paulo)"}
    ]
    
    return jsonify({'success': True, 'regions': regions})

@app.route('/api/get_free_shapes')
def get_free_shapes():
    """Ücretsiz shape'leri getir"""
    shapes = [
        {"id": "VM.Standard.E2.1.Micro", "name": "VM.Standard.E2.1.Micro (Always Free)"},
        {"id": "VM.Standard.A1.Flex", "name": "VM.Standard.A1.Flex (4 OCPU, 24 GB RAM - Always Free)"}
    ]
    
    return jsonify({'success': True, 'shapes': shapes})

if __name__ == '__main__':
    # Eski task'ları temizleme thread'i
    def cleanup_thread():
        while True:
            time.sleep(3600)  # Her saatte bir
            try:
                current_time = datetime.now()
                to_remove = []
                
                for task_id, creator in active_tasks.items():
                    # 3 saatten eski task'ları temizle
                    if (current_time - creator.last_update).total_seconds() > 10800:
                        to_remove.append(task_id)
                
                for task_id in to_remove:
                    del active_tasks[task_id]
                
                if to_remove:
                    logger.info(f"Eski {len(to_remove)} task temizlendi")
                    
            except Exception as e:
                logger.error(f"Temizleme hatası: {e}")
    
    # Temizleme thread'ini başlat
    cleanup = threading.Thread(target=cleanup_thread)
    cleanup.daemon = True
    cleanup.start()
    
    # Flask uygulamasını başlat
    app.run(host='0.0.0.0', port=5000, debug=True)
