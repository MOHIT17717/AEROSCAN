import os
import subprocess
import platform
import nmap
import time
import logging
import socket
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Download the background image
def download_background_image(url, save_path):
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(save_path, "wb") as file:
            file.write(response.content)
        logging.info(f"Background image downloaded and saved to {save_path}")
    except Exception as e:
        logging.error(f"Failed to download background image: {e}")

# Path to save the downloaded image
background_image_path = "cyber_bg.jpg"
background_image_url = "https://wallpaperaccess.com/full/2407100.jpg"

# Download the image if it doesn't already exist
if not os.path.exists(background_image_path):
    download_background_image(background_image_url, background_image_path)

class CybersecurityTool:
    def __init__(self, target_ip=None, interface=None):
        self.target_ip = target_ip
        self.interface = interface
    
    def scan_ports(self, progress_callback):
        if not self.target_ip:
            logging.error("No target IP provided. Skipping port scan.")
            return "Port Scan Failed", []

        logging.info(f"Scanning target IP: {self.target_ip}")
        progress_callback("Scanning Ports...")
        try:
            nm = nmap.PortScanner()
            nm.scan(self.target_ip, arguments="-p 1-65535 --open")
            result = "Port Scan Results:\n"
            vulnerabilities = ["21", "22", "23", "80", "443"]  # Example vulnerable ports
            for host in nm.all_hosts():
                result += f"Host: {host}\n"
                for proto in nm[host].all_protocols():
                    result += f"Protocol: {proto}\n"
                    for port in nm[host][proto].keys():
                        state = nm[host][proto][port]['state']
                        color = "red" if str(port) in vulnerabilities else "white"
                        result += f"Port: {port} - State: {state}\n"
                        progress_callback(f"Port {port} scanned")
            return result, vulnerabilities
        except Exception as e:
            logging.error(f"Error during port scanning: {e}")
            return "Error during port scanning", []

    def monitor_wifi(self, progress_callback):
        if not self.interface:
            logging.error("No network interface provided. Skipping Wi-Fi monitoring.")
            return "Wi-Fi Monitoring Failed"
        
        logging.info(f"Putting {self.interface} into monitor mode...")
        progress_callback("Monitoring Wi-Fi...")
        try:
            # Example logic: Monitor for safe state (just a placeholder, customize this as needed)
            wifi_status = "secured"  # This could be based on specific conditions
            if wifi_status == "secured":
                return "Wi-Fi is Secured"
            else:
                return "Wi-Fi has vulnerabilities"
        except Exception as e:
            logging.error(f"Unexpected error during Wi-Fi monitoring: {e}")
            return "Error during Wi-Fi monitoring"

    def capture_packets(self, progress_callback):
        if not self.interface or not self.target_ip:
            logging.error("No network interface or target IP provided. Skipping packet capture.")
            return "Packet Capture Failed"
        
        logging.info("Capturing packets...")
        progress_callback("Capturing Packets...")

        try:
            # If the target IP is a domain name, resolve it to IP
            if not self.is_valid_ip(self.target_ip):
                logging.info(f"Resolving domain: {self.target_ip}")
                self.target_ip = socket.gethostbyname(self.target_ip)
                logging.info(f"Resolved IP: {self.target_ip}")
            
            # Correcting the filter syntax
            capture_filter = f"host {self.target_ip}"

            # Run Wireshark with the correct capture filter
            subprocess.run(
                ["wireshark", "-i", self.interface, "-k", "-f", capture_filter],
                check=True
            )
            return f"Packet Capture Completed. Capture filter: {capture_filter}"
        except subprocess.CalledProcessError as e:
            logging.error(f"Error during packet capture: {e}")
            return "Error during packet capture"
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            return "Unexpected error during packet capture"

    def is_valid_ip(self, ip):
        """Validate if the input is a valid IP address."""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

class CyberSecurityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AEROSCAN")
        self.root.geometry("600x400")
        
        # Load cyber-themed background image
        try:
            self.bg_image = Image.open(background_image_path)
            self.bg_image = self.bg_image.resize((600, 400), Image.ANTIALIAS)
            self.bg_image = ImageTk.PhotoImage(self.bg_image)
            
            self.bg_label = tk.Label(root, image=self.bg_image)
            self.bg_label.place(relwidth=1, relheight=1)
        except Exception as e:
            logging.error(f"Failed to load background image: {e}")
            self.bg_label = tk.Label(root, text="AEROSCAN", bg="black", fg="cyan")
            self.bg_label.place(relwidth=1, relheight=1)
        
        # Title and Developer Label
        self.title_label = tk.Label(root, text="AEROSCAN", font=("Arial", 24, "bold"), bg="black", fg="cyan")
        self.title_label.pack(pady=20)
        
        self.developer_label = tk.Label(root, text="Developed by CYBER CASTLE", font=("Arial", 10), bg="black", fg="white")
        self.developer_label.pack(pady=5)
        
        # Custom style for ttk.Entry
        self.style = ttk.Style()
        self.style.configure("White.TEntry", foreground="white", background="black", fieldbackground="black", 
                            insertcolor="white", bordercolor="white", lightcolor="white", darkcolor="white")
        
        # Target IP Entry with Placeholder
        self.target_ip_entry = ttk.Entry(root, width=30, style="White.TEntry")
        self.target_ip_entry.insert(0, "Enter Target IP Address or HTTPS Link")  # Placeholder text
        self.target_ip_entry.bind("<FocusIn>", self.clear_placeholder)
        self.target_ip_entry.bind("<FocusOut>", self.restore_placeholder)
        self.target_ip_entry.pack(pady=10)
        
        # Interface Entry
        self.interface_entry = ttk.Entry(root, width=30, style="White.TEntry")
        self.interface_entry.insert(tk.END, "wlan0")  # Default interface
        self.interface_entry.pack(pady=10)
        
        # Tool Instance
        self.tool = CybersecurityTool(target_ip=self.target_ip_entry.get(), interface=self.interface_entry.get())
        
        # Progress Label
        self.progress_label = tk.Label(root, text="Status: Idle", font=("Arial", 12), bg="black", fg="white")
        self.progress_label.pack(pady=10)
        
        # Buttons
        self.auto_scan_button = ttk.Button(root, text="Auto Scan", command=self.run_automated_scan)
        self.auto_scan_button.pack(pady=10)
        
        self.manual_scan_button = ttk.Button(root, text="Manual Scan", command=self.open_manual_scan)
        self.manual_scan_button.pack(pady=10)
        
        # Result Text Box
        self.result_text = tk.Text(root, height=10, width=70, bg="black", fg="white")
        self.result_text.pack(pady=10)
        
        # Configure text styles for red color
        self.result_text.tag_config("red", foreground="red")
    
    def clear_placeholder(self, event):
        """Clear the placeholder text when the entry is clicked."""
        if self.target_ip_entry.get() == "Enter Target IP Address or HTTPS Link":
            self.target_ip_entry.delete(0, tk.END)
            self.target_ip_entry.config(foreground="white")  # Change text color to white
    
    def restore_placeholder(self, event):
        """Restore the placeholder text if the entry is left empty."""
        if not self.target_ip_entry.get():
            self.target_ip_entry.insert(0, "Enter Target IP Address or HTTPS Link")
            self.target_ip_entry.config(foreground="white")  # Change text color to white
    
    def update_progress(self, message):
        self.progress_label.config(text=f"Status: {message}")
        self.root.update()
    
    def run_automated_scan(self):
        self.result_text.delete(1.0, tk.END)
        
        self.update_progress("Starting Automated Scan...")
        self.tool.target_ip = self.target_ip_entry.get()
        self.tool.interface = self.interface_entry.get()
        
        port_result, vulnerabilities = self.tool.scan_ports(self.update_progress)
        
        for line in port_result.split("\n"):
            color = "red" if any(vuln in line for vuln in vulnerabilities) else "white"
            self.result_text.insert(tk.END, line + "\n", color)
        
        wifi_result = self.tool.monitor_wifi(self.update_progress)
        wifi_color = "red" if "Secured" in wifi_result else "white"
        self.result_text.insert(tk.END, wifi_result + "\n\n", wifi_color)
        
        packet_result = self.tool.capture_packets(self.update_progress)
        self.result_text.insert(tk.END, packet_result + "\n\n")
        
        self.update_progress("Automated Scan Completed Successfully")
    
    def open_manual_scan(self):
        self.manual_window = tk.Toplevel(self.root)
        self.manual_window.title("Manual Scan")
        self.manual_window.geometry("600x400")
        
        # Target IP Entry with Placeholder
        self.target_ip_entry_manual = ttk.Entry(self.manual_window, width=30, style="White.TEntry")
        self.target_ip_entry_manual.insert(0, self.target_ip_entry.get())  # Use the value from the main page
        self.target_ip_entry_manual.bind("<FocusIn>", self.clear_placeholder)
        self.target_ip_entry_manual.bind("<FocusOut>", self.restore_placeholder)
        self.target_ip_entry_manual.pack(pady=10)
        
        # Interface Entry
        self.interface_entry_manual = ttk.Entry(self.manual_window, width=30, style="White.TEntry")
        self.interface_entry_manual.insert(tk.END, self.interface_entry.get())  # Use the value from the main page
        self.interface_entry_manual.pack(pady=10)
        
        # Manual Scan Buttons
        self.manual_frame = tk.Frame(self.manual_window)
        self.manual_frame.pack(pady=10)
        
        ttk.Button(self.manual_frame, text="Port Scan", command=self.run_port_scan).grid(row=0, column=0, padx=5)
        ttk.Button(self.manual_frame, text="Wi-Fi Monitor", command=self.run_wifi_monitor).grid(row=0, column=1, padx=5)
        ttk.Button(self.manual_frame, text="Packet Capture", command=self.run_packet_capture).grid(row=0, column=2, padx=5)
        
        # Result Text Box
        self.result_text_manual = tk.Text(self.manual_window, height=10, width=70, bg="black", fg="white")
        self.result_text_manual.pack(pady=10)
        
        # Configure text styles for red color
        self.result_text_manual.tag_config("red", foreground="red")
    
    def run_port_scan(self):
        self.result_text_manual.delete(1.0, tk.END)
        self.update_progress("Running Port Scan...")
        self.tool.target_ip = self.target_ip_entry_manual.get()
        result, vulnerabilities = self.tool.scan_ports(self.update_progress)
        
        for line in result.split("\n"):
            color = "red" if any(vuln in line for vuln in vulnerabilities) else "white"
            self.result_text_manual.insert(tk.END, line + "\n", color)
        
        self.update_progress("Port Scan Completed")
    
    def run_wifi_monitor(self):
        self.result_text_manual.delete(1.0, tk.END)
        self.update_progress("Running Wi-Fi Monitoring...")
        result = self.tool.monitor_wifi(self.update_progress)
        
        wifi_color = "red" if "Secured" in result else "white"
        self.result_text_manual.insert(tk.END, result + "\n\n", wifi_color)
        
        self.update_progress("Wi-Fi Monitoring Completed")
    
    def run_packet_capture(self):
        self.result_text_manual.delete(1.0, tk.END)
        self.update_progress("Running Packet Capture...")
        result = self.tool.capture_packets(self.update_progress)
        self.result_text_manual.insert(tk.END, result + "\n\n")
        self.update_progress("Packet Capture Completed")

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberSecurityGUI(root)
    root.mainloop()
