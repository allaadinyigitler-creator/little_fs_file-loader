import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import subprocess
import threading
import serial.tools.list_ports

class LittleFSUploader:
    def __init__(self, root):
        self.root = root
        self.root.title("ESP32 LittleFS Uploader")
        self.root.geometry("600x500")
        
        # Değişkenler
        self.data_folder = tk.StringVar()
        self.port = tk.StringVar()
        self.baud_rate = tk.StringVar(value="921600")
        self.flash_address = tk.StringVar(value="0x00210000")
        self.file_system_size = tk.StringVar(value="0x1E0000")
        self.page_size = tk.StringVar(value="512")
        
        # Arayüz oluştur
        self.create_widgets()
        
        # Portları tara
        self.scan_ports()
    
    def create_widgets(self):
        # Data Folder Seçimi
        folder_frame = ttk.Frame(self.root, padding="10")
        folder_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        ttk.Label(folder_frame, text="Data Klasörü:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(folder_frame, textvariable=self.data_folder, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(folder_frame, text="Gözat", command=self.browse_folder).grid(row=0, column=2)
        
        # Port Seçimi
        port_frame = ttk.Frame(self.root, padding="10")
        port_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        ttk.Label(port_frame, text="Port:").grid(row=0, column=0, sticky=tk.W)
        port_combo = ttk.Combobox(port_frame, textvariable=self.port, width=20)
        port_combo.grid(row=0, column=1, padx=5, sticky=tk.W)
        ttk.Button(port_frame, text="Portları Tara", command=self.scan_ports).grid(row=0, column=2)
        
        # Baud Rate
        ttk.Label(port_frame, text="Baud Rate:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(port_frame, textvariable=self.baud_rate, width=20).grid(row=1, column=1, padx=5, sticky=tk.W, pady=5)
        
        # Flash Adresi
        ttk.Label(port_frame, text="Flash Adresi:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Entry(port_frame, textvariable=self.flash_address, width=20).grid(row=2, column=1, padx=5, sticky=tk.W, pady=5)
        
        # Dosya Sistemi Boyutu
        ttk.Label(port_frame, text="Dosya Sistemi Boyutu:").grid(row=3, column=0, sticky=tk.W, pady=5)
        ttk.Entry(port_frame, textvariable=self.file_system_size, width=20).grid(row=3, column=1, padx=5, sticky=tk.W, pady=5)
        
        # Page Size
        ttk.Label(port_frame, text="Sayfa Boyutu:").grid(row=4, column=0, sticky=tk.W, pady=5)
        ttk.Entry(port_frame, textvariable=self.page_size, width=20).grid(row=4, column=1, padx=5, sticky=tk.W, pady=5)
        
        # İlerleme Çubuğu
        progress_frame = ttk.Frame(self.root, padding="10")
        progress_frame.grid(row=2, column=0, sticky=(tk.W, tk.E))
        
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=10)
        
        # Butonlar
        button_frame = ttk.Frame(self.root, padding="10")
        button_frame.grid(row=3, column=0, sticky=(tk.W, tk.E))
        
        ttk.Button(button_frame, text="LittleFS Oluştur ve Yükle", command=self.start_upload).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Sadece LittleFS Oluştur", command=self.create_only).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="Sadece Yükle", command=self.upload_only).grid(row=0, column=2, padx=5)
        
        # Log Alanı
        log_frame = ttk.Frame(self.root, padding="10")
        log_frame.grid(row=4, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.log_text = tk.Text(log_frame, height=15, width=70)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.log_text['yscrollcommand'] = scrollbar.set
        
        # Grid yapılandırması
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(4, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
    
    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.data_folder.set(folder)
    
    def scan_ports(self):
        ports = [port.device for port in serial.tools.list_ports.comports()]
        port_combo = self.root.nametowidget('.!frame2.!combobox')
        port_combo['values'] = ports
        if ports:
            self.port.set(ports[0])
    
    def log_message(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def run_command(self, command):
        self.log_message(f"Çalıştırılıyor: {' '.join(command)}")
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.log_message(result.stdout)
            if result.stderr:
                self.log_message("HATA: " + result.stderr)
            return True
        except subprocess.CalledProcessError as e:
            self.log_message(f"HATA: Komut başarısız oldu (çıkış kodu {e.returncode})")
            self.log_message(e.stderr)
            return False
        except FileNotFoundError:
            self.log_message("HATA: mklittlefs veya esptool bulunamadı. Lütfen yolunu kontrol edin.")
            return False
    
    def create_littlefs(self):
        data_folder = self.data_folder.get()
        if not data_folder or not os.path.exists(data_folder):
            messagebox.showerror("Hata", "Geçerli bir data klasörü seçin.")
            return False
        
        output_file = "littlefs.bin"
        command = [
            "mklittlefs",
            "-c", data_folder,
            "-s", self.file_system_size.get(),
            "-p", self.page_size.get(),
            output_file
        ]
        
        return self.run_command(command)
    
    def upload_littlefs(self):
        port = self.port.get()
        if not port:
            messagebox.showerror("Hata", "Bir port seçin.")
            return False
        
        output_file = "littlefs.bin"
        if not os.path.exists(output_file):
            messagebox.showerror("Hata", "littlefs.bin dosyası bulunamadı. Önce LittleFS oluşturun.")
            return False
        
        command = [
                "esptool.exe",
                "--chip", "esp32s3",
                "--port", port,
                "--baud", self.baud_rate.get(),
                "--before", "default_reset",  # 📌 Cihazı işlem öncesi resetler
                "--after", "hard_reset",     # 📌 İşlem sonrası hard reset yapar
                "write_flash",
                "-z",  # Sıkıştırma için ayrı bir parametre
                "--flash_mode", "dio",
                "--flash_freq", "80m",
                "--flash_size", "detect",
                self.flash_address.get(),  # Örnek: "0x210000"
                output_file                 # Örnek: "littlefs.bin"
        ]
        
        return self.run_command(command)
    
    def start_upload(self):
        self.progress.start()
        self.log_text.delete(1.0, tk.END)
        
        def upload_thread():
            success = self.create_littlefs()
            if success:
                success = self.upload_littlefs()
            
            self.progress.stop()
            if success:
                self.log_message("İşlem başarıyla tamamlandı!")
                messagebox.showinfo("Başarılı", "LittleFS başarıyla oluşturuldu ve yüklendi.")
            else:
                messagebox.showerror("Hata", "İşlem başarısız oldu. Detaylar için logları kontrol edin.")
        
        threading.Thread(target=upload_thread, daemon=True).start()
    
    def create_only(self):
        self.progress.start()
        self.log_text.delete(1.0, tk.END)
        
        def create_thread():
            success = self.create_littlefs()
            self.progress.stop()
            if success:
                self.log_message("LittleFS başarıyla oluşturuldu!")
                messagebox.showinfo("Başarılı", "LittleFS başarıyla oluşturuldu.")
            else:
                messagebox.showerror("Hata", "LittleFS oluşturulamadı. Detaylar için logları kontrol edin.")
        
        threading.Thread(target=create_thread, daemon=True).start()
    
    def upload_only(self):
        self.progress.start()
        self.log_text.delete(1.0, tk.END)
        
        def upload_thread():
            success = self.upload_littlefs()
            self.progress.stop()
            if success:
                self.log_message("LittleFS başarıyla yüklendi!")
                messagebox.showinfo("Başarılı", "LittleFS başarıyla yüklendi.")
            else:
                messagebox.showerror("Hata", "LittleFS yüklenemedi. Detaylar için logları kontrol edin.")
        
        threading.Thread(target=upload_thread, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = LittleFSUploader(root)
    root.mainloop()