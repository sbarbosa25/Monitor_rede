import tkinter as tk
from tkinter import ttk
import psutil
import scapy.all as scapy
from scapy.layers.l2 import ARP
import threading
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.animation as animation
import json
import time
from scapy.layers.http import HTTPRequest
import requests

class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Monitor de Tráfego de Rede")
        
        
        # Flags de controle
        self.is_monitoring = False
        self.log_file = None
        self.device_scan_job = None

        # Configuração da interface do usuário
        self.setup_ui()
        
    def setup_ui(self):
        # Criação do frame principal
        self.frame = ttk.Frame(self.root)
        self.frame.pack(fill=tk.BOTH, expand=True)
        
        # Rótulo e combobox para seleção de interfaces de rede
        self.interface_label = ttk.Label(self.frame, text="Selecione a Interface de Rede:")
        self.interface_label.pack(pady=5)

        # Rótulo e combobox desenvolvimento
        self.interface_label = ttk.Label(self.frame, text="Desenvolvido por: Samuel Santos (v 1.0)")
        self.interface_label.pack(pady=5)
        
        self.interface_combo = ttk.Combobox(self.frame, state="readonly")
        self.interface_combo.pack(pady=5)
        
        # Botão para iniciar o monitoramento
        self.start_button = ttk.Button(self.frame, text="Iniciar Monitoramento", command=self.start_monitoring)
        self.start_button.pack(pady=5)
        
        # Botão para parar o monitoramento
        self.stop_button = ttk.Button(self.frame, text="Encerrar", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        # Rótulo para exibir a quantidade de dispositivos conectados
        self.devices_label = ttk.Label(self.frame, text="Dispositivos Conectados: 0")
        self.devices_label.pack(pady=5)

        # Treeview para exibir informações dos dispositivos conectados
        self.tree = ttk.Treeview(self.frame, columns=("Nome", "Tipo de Dispositivo", "IP", "MB Consumidos"), show="headings")
        self.tree.heading("Nome", text="Nome (Sistema Operacional)")
        self.tree.heading("Tipo de Dispositivo", text="Tipo de Dispositivo")
        self.tree.heading("IP", text="IP")
        self.tree.heading("MB Consumidos", text="MB Consumidos")
        self.tree.pack(pady=5, fill=tk.BOTH, expand=True)

             
        # Configuração do gráfico
        self.fig = Figure(figsize=(8, 4), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_title("Tráfego de Rede em Tempo Real")
        self.ax.set_xlabel("Tempo")
        self.ax.set_ylabel("Pacotes por Segundo")
        self.line, = self.ax.plot([], [], lw=2)
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Inicialização dos dados do gráfico
        self.packet_times = []
        self.packet_counts = []
        self.start_time = time.time()
        
        # Carregar interfaces de rede disponíveis
        self.load_interfaces()

        # Dicionário para armazenar o consumo de dados
        self.data_consumption = {}

    def load_interfaces(self):
        # Obter as interfaces de rede disponíveis
        interfaces = psutil.net_if_addrs().keys()
        self.interface_combo['values'] = list(interfaces)
        if interfaces:
            self.interface_combo.current(0)
    
    def start_monitoring(self):
        iface = self.interface_combo.get()
        if not iface:
            return
        
        self.is_monitoring = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Abrir o arquivo de log
        self.log_file = open("network_log.json", "w")
        
        # Resetar os dados do gráfico
        self.packet_times = []
        self.packet_counts = []
        self.start_time = time.time()
        
        # Iniciar o agendamento da varredura de dispositivos
        self.device_scan_job = self.root.after(1000, self.update_devices)
        
        # Iniciar a captura de tráfego em uma thread separada
        self.monitor_thread = threading.Thread(target=self.capture_traffic, args=(iface,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Inicializar a animação do gráfico
        self.ani = animation.FuncAnimation(self.fig, self.update_plot, init_func=self.init_plot, blit=False)
        self.canvas.draw()
        
    def stop_monitoring(self):
        self.is_monitoring = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        # Fechar o arquivo de log
        if self.log_file:
            self.log_file.close()
            self.log_file = None
        
        # Cancelar o agendamento da varredura de dispositivos
        if self.device_scan_job:
            self.root.after_cancel(self.device_scan_job)
            self.device_scan_job = None
        
        # Fechar a aplicação
        self.root.quit()
        self.root.destroy()

    def capture_traffic(self, iface):
        # Capturar pacotes da interface especificada
        scapy.sniff(iface=iface, prn=self.process_packet, store=False)

    def process_packet(self, packet):
        if not self.is_monitoring:
            return
        
        # Registrar o pacote
        self.log_packet(packet)
        
        # Atualizar dados do gráfico
        current_time = time.time() - self.start_time
        self.packet_times.append(current_time)
        self.packet_counts.append(len(packet))
        
        self.packet_times = self.packet_times[-100:]
        self.packet_counts = self.packet_counts[-100:]

        # Atualizar o consumo de dados
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            packet_length = len(packet)
            
            if src_ip in self.data_consumption:
                self.data_consumption[src_ip] += packet_length
            else:
                self.data_consumption[src_ip] = packet_length
            
            if dst_ip in self.data_consumption:
                self.data_consumption[dst_ip] += packet_length
            else:
                self.data_consumption[dst_ip] = packet_length

    def log_packet(self, packet):
        # Criar uma entrada de log
        log_entry = {
            "time": time.time(),
            "packet_summary": packet.summary(),
            "packet_type": type(packet).__name__
        }
        
        if packet.haslayer(HTTPRequest):
            log_entry["host"] = packet[HTTPRequest].Host.decode()
            log_entry["path"] = packet[HTTPRequest].Path.decode()
        
        # Escrever a entrada de log no arquivo
        if self.log_file:
            self.log_file.write(json.dumps(log_entry) + "\n")

    def update_plot(self, frame):
        # Atualizar os dados do gráfico
        self.line.set_data(self.packet_times, self.packet_counts)
        self.ax.relim()
        self.ax.autoscale_view()
        self.canvas.draw()
        return self.line,

    def init_plot(self):
        # Inicializar o gráfico
        self.line.set_data([], [])
        return self.line,

    def update_devices(self):
        if not self.is_monitoring:
            return
        
        iface = self.interface_combo.get()
        if not iface:
            return
        
        # Varredura de dispositivos na rede
        devices = self.scan_network(iface)
        self.devices_label.config(text=f"Dispositivos Conectados: {len(devices)}")
        
        # Limpar a tabela de dispositivos
        for row in self.tree.get_children():
            self.tree.delete(row)
        
        # Preencher a tabela com informações dos dispositivos
        for device in devices:
            ip = device['ip']
            data_consumed_mb = self.data_consumption.get(ip, 0) / (1024 * 1024)
            self.tree.insert("", tk.END, values=(device['name'], device['type'], device['ip'], f"{data_consumed_mb:.2f} MB"))
        
        # Agendar a próxima varredura de dispositivos
        self.device_scan_job = self.root.after(5000, self.update_devices)

    def scan_network(self, iface):
        # Criar e enviar requisição ARP para descobrir dispositivos na rede
        arp_request = scapy.ARP(pdst='192.168.0.1/24')
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False, iface=iface)[0]
        
        devices = []
        for element in answered_list:
            device_info = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
            device_info['type'] = self.get_device_type(device_info['mac'])
            device_info['name'] = self.get_device_name(device_info['mac'])
            devices.append(device_info)
        
        return devices

    def get_device_type(self, mac):
        # Obter o tipo de dispositivo baseado no MAC address
        try:
            response = requests.get(f"https://api.macvendors.com/{mac}")
            vendor = response.text
            if "Apple" in vendor:
                return "Apple Device (iPhone/MacBook)"
            elif "Samsung" in vendor:
                return "Samsung Device"
            else:
                return "Unknown Device"
        except:
            return "Unknown Device"

    def get_device_name(self, mac):
        # Obter o nome do dispositivo baseado no MAC address
        return "Device"

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.mainloop()

