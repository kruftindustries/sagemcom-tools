import sys, os, subprocess

# Prompt user to install missing packages upon import error
packages = ["pathlib", "PySide6", "requests"]

for package in packages:
    try:
        __import__(package)
    except ImportError:
        # Ask user if they want to install (in console)
        response = input(
            f"The package '{package}' needed to run this utility is not installed. Do you want to install it now? (y/n): "
        )
        if response.lower() == "y":
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            #__import__(package)  # Try importing again after installation


import requests
from PySide6.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, \
    QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox, QTabWidget, \
    QPlainTextEdit, QComboBox, QCheckBox, QGroupBox, QFormLayout, QScrollArea
from pathlib import Path

testing = "False"

# These two files may be created by this script
temp_wifi_input = Path("x-wifi-input.txt")
temp_wifi_out = Path("x-wifi-output.txt")

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Arcadyan/Sagemcom Router Utility")
        self.admin_pass = ""
        self.token = ""
        
        self.refresh_signal_button = QPushButton("Refresh")
        self.device_button = QPushButton("Refresh")
        
        self.create_connection_tab()
        self.create_wifi_settings_tab()
        self.create_signal_strength_tab()
        self.create_device_tab()
        self.create_system_info_tab()

        tab_widget = QTabWidget()
        tab_widget.addTab(self.connection_tab, "Connection")
        tab_widget.addTab(self.wifi_settings_tab, "WiFi Settings")
        tab_widget.addTab(self.device_tab, "DHCP Clients")
        tab_widget.addTab(self.signal_strength_tab, "Signal Strength")
        tab_widget.addTab(self.system_info_tab, "System Info")

        main_layout = QVBoxLayout()
        main_layout.addWidget(tab_widget)
        self.setLayout(main_layout)

    def create_connection_tab(self):
        self.connection_tab = QWidget()
        layout = QVBoxLayout()

        self.password_label = QLabel("Router Admin Password:")
        self.password_input = QLineEdit()
        #self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setText("XXX") # Set default password here
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.connect_to_router)

        self.connection_status_label = QLabel("Connection Status:")
        self.connection_status = QLabel("Not connected")

        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.connect_button)
        layout.addWidget(self.connection_status_label)
        layout.addWidget(self.connection_status)

        # Add reboot button
        self.reboot_button = QPushButton("Reboot Router")
        self.reboot_button.clicked.connect(self.reboot_router)
        self.reboot_button.setEnabled(False)  # Disabled until connected
        layout.addWidget(self.reboot_button)

        self.connection_tab.setLayout(layout)

    def create_wifi_settings_tab(self):
        self.wifi_settings_tab = QWidget()
        
        # Create scroll area for the WiFi settings
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)

        # WiFi Configuration Group
        wifi_config_group = QGroupBox("WiFi Configuration")
        wifi_form = QFormLayout()
        
        # SSID Name
        self.ssid_input = QLineEdit()
        self.ssid_input.setMaxLength(28)
        self.ssid_input.setPlaceholderText("Enter SSID (max 28 characters)")
        wifi_form.addRow("SSID Name:", self.ssid_input)
        
        # WiFi Password
        self.wifi_password_input = QLineEdit()
        self.wifi_password_input.setMaxLength(63)
        self.wifi_password_input.setPlaceholderText("Enter password (8-63 characters)")
        self.wifi_password_input.setEchoMode(QLineEdit.Password)
        wifi_form.addRow("WiFi Password:", self.wifi_password_input)
        
        # Show password checkbox
        self.show_password_check = QCheckBox("Show Password")
        self.show_password_check.toggled.connect(self.toggle_password_visibility)
        wifi_form.addRow("", self.show_password_check)
        
        # Encryption Type
        self.encryption_combo = QComboBox()
        self.encryption_combo.addItems(["WPA2/WPA3", "WPA/WPA2", "WPA2"])
        wifi_form.addRow("Encryption:", self.encryption_combo)
        
        # 2.4 GHz Radio
        self.radio_24_check = QCheckBox("Enable 2.4 GHz Radio")
        wifi_form.addRow("", self.radio_24_check)
        
        # 5.0 GHz Radio
        self.radio_50_check = QCheckBox("Enable 5.0 GHz Radio")
        wifi_form.addRow("", self.radio_50_check)
        
        # Broadcast SSID
        self.broadcast_check = QCheckBox("Broadcast SSID")
        wifi_form.addRow("", self.broadcast_check)
        
        wifi_config_group.setLayout(wifi_form)
        layout.addWidget(wifi_config_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.load_wifi_button = QPushButton("Load Current Settings")
        self.load_wifi_button.clicked.connect(self.load_wifi_config)
        self.load_wifi_button.setEnabled(False)
        
        self.save_wifi_button = QPushButton("Save Settings")
        self.save_wifi_button.clicked.connect(self.save_wifi_config)
        self.save_wifi_button.setEnabled(False)
        
        button_layout.addWidget(self.load_wifi_button)
        button_layout.addWidget(self.save_wifi_button)
        layout.addLayout(button_layout)
        
        # Status label
        self.wifi_status_label = QLabel("Not connected. Please connect first.")
        layout.addWidget(self.wifi_status_label)
        
        # Current WiFi Info Display (read-only)
        info_group = QGroupBox("Current WiFi Information")
        info_layout = QVBoxLayout()
        self.wifi_info = QPlainTextEdit()
        self.wifi_info.setReadOnly(True)
        self.wifi_info.setMaximumHeight(200)
        info_layout.addWidget(self.wifi_info)
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        layout.addStretch()
        
        scroll.setWidget(scroll_content)
        tab_layout = QVBoxLayout()
        tab_layout.addWidget(scroll)
        self.wifi_settings_tab.setLayout(tab_layout)
        
        # Store the current WiFi config
        self.current_wifi_config = None

    def create_signal_strength_tab(self):
        self.signal_strength_tab = QWidget()
        layout = QVBoxLayout()

        self.signal_strength_label = QLabel("Signal Strength:")
        self.signal_strength_info = QPlainTextEdit("Not connected")
        self.signal_strength_info.setReadOnly(True)
        self.signal_strength_info.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.signal_strength_info.setMaximumHeight(200)  # Limit height

        self.refresh_signal_button = QPushButton("Refresh")
        self.refresh_signal_button.clicked.connect(self.get_signal_strength)

        layout.addWidget(self.signal_strength_label)
        layout.addWidget(self.signal_strength_info)
        layout.addWidget(self.refresh_signal_button)
        self.signal_strength_tab.setLayout(layout)

    def create_device_tab(self):
        self.device_tab = QWidget()
        layout = QVBoxLayout()

        self.device_label = QLabel("Devices:")
        self.device_info = QPlainTextEdit("Not connected")
        self.device_info.setReadOnly(True)
        self.device_info.setLineWrapMode(QPlainTextEdit.WidgetWidth)

        self.device_button = QPushButton("Refresh")
        self.device_button.clicked.connect(self.get_devices)

        layout.addWidget(self.device_label)
        layout.addWidget(self.device_info)
        layout.addWidget(self.device_button)
        self.device_tab.setLayout(layout)

    def create_system_info_tab(self):
        """Create a tab for system information including SIM, cell, and version info"""
        self.system_info_tab = QWidget()
        layout = QVBoxLayout()

        self.system_info_label = QLabel("System Information:")
        self.system_info_display = QPlainTextEdit("Not connected")
        self.system_info_display.setReadOnly(True)
        self.system_info_display.setLineWrapMode(QPlainTextEdit.WidgetWidth)

        self.system_info_button = QPushButton("Refresh System Info")
        self.system_info_button.clicked.connect(self.get_system_info)
        self.system_info_button.setEnabled(False)

        layout.addWidget(self.system_info_label)
        layout.addWidget(self.system_info_display)
        layout.addWidget(self.system_info_button)
        self.system_info_tab.setLayout(layout)

    def connect_to_router(self):
        try:
            self.admin_pass = self.password_input.text()
            if not self.admin_pass:
                QMessageBox.warning(self, "Error", "Please enter the router admin password.")
                return

            self.token = self.get_token()
            self.connection_status.setText("Connected")
            self.device_info.setPlainText("Connected")
            self.reboot_button.setEnabled(True)  # Enable reboot button after successful connection
            self.load_wifi_button.setEnabled(True)  # Enable WiFi buttons
            self.save_wifi_button.setEnabled(True)
            self.system_info_button.setEnabled(True)  # Enable system info button
            #self.enable_buttons()
            #self.get_wifi_info_str()
            #self.get_signal_strength()
            #self.get_devices()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to router: {e}")

    def reboot_router(self):
        """Reboot the router using the reset endpoint"""
        # Confirm reboot action
        reply = QMessageBox.question(
            self, 
            "Confirm Reboot", 
            "Are you sure you want to reboot the router? This will temporarily disconnect all devices.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
            
        try:
            url = "http://192.168.12.1/TMI/v1/gateway/reset?set=reboot" #Not working on F5688W
            headers = {'Authorization': f'Bearer {self.token}'}
            
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            
            QMessageBox.information(
                self, 
                "Reboot Initiated", 
                "Router reboot has been initiated. The router will be offline for a few minutes."
            )
            
            # Reset connection status
            self.connection_status.setText("Router rebooting...")
            self.reboot_button.setEnabled(False)
            
        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Error", f"Failed to reboot router: {e}")

    def get_token(self):
        url = "http://192.168.12.1/TMI/v1/auth/login"
        data = {
            "username": "admin",
            "password": self.admin_pass
        }
        headers = {'Content-Type': 'application/json'}

        try:
            response = requests.post(url, json=data, headers=headers)
            response.raise_for_status()  # Raise exception for HTTP errors
            #print(response.json()["auth"])

            # Extract token from response
            token = response.json()["auth"].get("token")
            if token is None:
                raise ValueError("Token not found in response")
            return token 
        
        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Error", f"Failed to get token: {e}")
            raise  # Re-raise to stop further execution

    def get_wifi_info(self):
        url = "http://192.168.12.1/TMI/v1/network/configuration?get=ap"
        headers = {'Authorization': f'Bearer {self.token}'}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.text 
        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Error", f"Failed to get wifi info: {e}")
            raise  

    def toggle_password_visibility(self, checked):
        """Toggle password visibility in the WiFi password input"""
        if checked:
            self.wifi_password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.wifi_password_input.setEchoMode(QLineEdit.Password)

    def load_wifi_config(self):
        """Load current WiFi configuration from router using v2 API"""
        try:
            url = "http://192.168.12.1/TMI/v1/network/configuration/v2?get=ap"
            headers = {'Authorization': f'Bearer {self.token}'}
            
            self.wifi_status_label.setText("Loading WiFi configuration...")
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            self.current_wifi_config = response.json()
            
            # Get the first SSID configuration (index 0)
            if self.current_wifi_config and 'ssids' in self.current_wifi_config:
                ssid_config = self.current_wifi_config['ssids'][0]
                
                # Populate form fields
                self.ssid_input.setText(ssid_config.get('ssidName', ''))
                self.wifi_password_input.setText(ssid_config.get('wpaKey', ''))
                self.encryption_combo.setCurrentText(ssid_config.get('encryptionVersion', 'WPA2/WPA3'))
                self.radio_24_check.setChecked(ssid_config.get('2.4ghzSsid', False))
                self.radio_50_check.setChecked(ssid_config.get('5.0ghzSsid', False))
                self.broadcast_check.setChecked(ssid_config.get('isBroadcastEnabled', False))
                
                # Display full config in info area
                info_text = f"""WiFi Configuration Loaded:

SSID: {ssid_config.get('ssidName', 'N/A')}
Encryption: {ssid_config.get('encryptionVersion', 'N/A')}
2.4 GHz Radio: {'Enabled' if ssid_config.get('2.4ghzSsid', False) else 'Disabled'}
5.0 GHz Radio: {'Enabled' if ssid_config.get('5.0ghzSsid', False) else 'Disabled'}
Broadcast: {'Enabled' if ssid_config.get('isBroadcastEnabled', False) else 'Disabled'}

Radio Settings:
2.4GHz - Channel: {self.current_wifi_config['2.4ghz'].get('channel', 'N/A')}, Mode: {self.current_wifi_config['2.4ghz'].get('mode', 'N/A')}
5.0GHz - Channel: {self.current_wifi_config['5.0ghz'].get('channel', 'N/A')}, Mode: {self.current_wifi_config['5.0ghz'].get('mode', 'N/A')}
"""
                self.wifi_info.setPlainText(info_text)
                self.wifi_status_label.setText("WiFi configuration loaded successfully!")
            else:
                QMessageBox.warning(self, "Warning", "No SSID configuration found in response")
                self.wifi_status_label.setText("Failed to load WiFi configuration")
                
        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Error", f"Failed to load WiFi configuration: {e}")
            self.wifi_status_label.setText("Error loading WiFi configuration")

    def save_wifi_config(self):
        """Save WiFi configuration to router using v2 API"""
        # Validate inputs
        ssid = self.ssid_input.text()
        password = self.wifi_password_input.text()
        
        if len(ssid) < 1:
            QMessageBox.warning(self, "Validation Error", "SSID must be at least 1 character long")
            return
            
        if len(password) < 8 or len(password) > 63:
            QMessageBox.warning(self, "Validation Error", "Password must be between 8 and 63 characters")
            return
        
        # Confirm save action
        reply = QMessageBox.question(
            self,
            "Confirm Save",
            "Are you sure you want to save these WiFi settings? This will update your router configuration.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
        
        try:
            url = "http://192.168.12.1/TMI/v1/network/configuration/v2?set=ap"
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json'
            }
            
            # Build the configuration payload
            # Update the first SSID (index 0) with new values
            if self.current_wifi_config and 'ssids' in self.current_wifi_config:
                # Create updated SSID configuration
                updated_ssids = []
                for idx, ssid_config in enumerate(self.current_wifi_config['ssids']):
                    if idx == 0:  # Update the first SSID
                        updated_ssid = {
                            **ssid_config,
                            'ssidName': ssid,
                            'wpaKey': password,
                            'encryptionVersion': self.encryption_combo.currentText(),
                            'encryptionMode': 'AES',
                            '2.4ghzSsid': self.radio_24_check.isChecked(),
                            '5.0ghzSsid': self.radio_50_check.isChecked(),
                            'isBroadcastEnabled': self.broadcast_check.isChecked(),
                            'guest': False
                        }
                        updated_ssids.append(updated_ssid)
                    else:
                        updated_ssids.append(ssid_config)
                
                # Create full payload
                payload = {
                    **self.current_wifi_config,
                    'ssids': updated_ssids
                }
                
                self.wifi_status_label.setText("Saving WiFi configuration...")
                
                response = requests.post(url, json=payload, headers=headers, timeout=10)
                response.raise_for_status()
                
                QMessageBox.information(
                    self,
                    "Success",
                    "WiFi configuration saved successfully!"
                )
                self.wifi_status_label.setText("WiFi configuration saved!")
                
                # Reload the configuration to show updated values
                self.load_wifi_config()
            else:
                QMessageBox.warning(
                    self,
                    "Error",
                    "Please load current WiFi configuration first before saving."
                )
                
        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Error", f"Failed to save WiFi configuration: {e}")
            self.wifi_status_label.setText("Error saving WiFi configuration")  

    def get_wifi_info_str(self):
        with open(temp_wifi_input, "w") as file_f:
            file_f.write(self.get_wifi_info())

        in_file = open(temp_wifi_input)
        # 2.4 GHz radio information
        in_file.seek(2)
        wifi_info = in_file.readline(11)  # show 2.4 GHz
        for _ in range(5):
            in_file.readline()
        wifi_info += in_file.readline(27)  # show radio status
        for _ in range(7):
            in_file.readline()
        wifi_info += in_file.readline(33)  # show broadcast status
        in_file.readline()
        wifi_info += in_file.readline()  # show ssid name
        in_file.readline()
        wifi_info += in_file.readline()  # show password
        for _ in range(18):
            in_file.readline()
        # 5.0 GHz information
        wifi_info += in_file.readline(11)  # show 5.0 GHz
        for _ in range(5):
            in_file.readline()
        wifi_info += in_file.readline(27)  # show radio status
        for _ in range(7):
            in_file.readline()
        wifi_info += in_file.readline(33)  # show broadcast status
        in_file.readline()
        wifi_info += in_file.readline()  # show ssid name
        in_file.readline()
        wifi_info += in_file.readline()  # show password

        in_file.close()
        return wifi_info

    def change_wifi_status(self, choice):
        if choice == '1':
            print("exit with no changes.")
            return
        try:
            out_file = open(temp_wifi_out, 'w')
            with open(temp_wifi_input, 'r') as in_file:
                if choice == '2':
                    self.radio24(in_file, out_file, 'enabled')
                    self.radio50(in_file, out_file, 'unchanged')
                elif choice == '3':
                    self.radio24(in_file, out_file, 'unchanged')
                    self.radio50(in_file, out_file, 'enabled')
                elif choice == '4':
                    self.radio24(in_file, out_file, 'enabled')
                    self.radio50(in_file, out_file, 'enabled')
                elif choice == '5':
                    self.radio24(in_file, out_file, 'disabled')
                    self.radio50(in_file, out_file, 'disabled')
            out_file.close()
            self.write_wifi_info()
            self.wifi_info.setText(self.get_wifi_info_str())  # Update displayed info
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to change wifi status: {e}")

    def get_signal_strength(self):
        try:
            url = "http://192.168.12.1/TMI/v1/gateway?get=all"
            headers = {'Authorization': f'Bearer {self.token}'}
            
            self.signal_strength_info.setPlainText(f"Request Sent! \n(This can take 30 seconds...)")
            
            response = requests.get(url, headers=headers)
            response.raise_for_status() 
            
            signal_data = response.json()["signal"]  

            # Format signal strength information (customize as needed)
            signal_info = f"""
            4G:
              - Bands: {signal_data.get("4g", {}).get("bands", "N/A")}
              - eNBID: {signal_data.get("4g", {}).get("eNBID", "N/A")}
              - Bars: {signal_data.get("4g", {}).get("bars", "N/A")} 
              - RSSI: {signal_data.get("4g", {}).get("rssi", "N/A")} dBm
            5G:
              - Bands: {signal_data.get("5g", {}).get("bands", "N/A")}
              - gNBID: {signal_data.get("5g", {}).get("gNBID", "N/A")}
              - Bars: {signal_data.get("5g", {}).get("bars", "N/A")}
              - RSRP: {signal_data.get("5g", {}).get("rsrp", "N/A")} dBm
              - RSRQ: {signal_data.get("5g", {}).get("rsrq", "N/A")} dB
              - SINR: {signal_data.get("5g", {}).get("sinr", "N/A")} dB
              - RSSI: {signal_data.get("5g", {}).get("rssi", "N/A")} dBm
            Generic:
              - APN: {signal_data.get("generic", {}).get("apn", "N/A")}
              - Registration: {signal_data.get("generic", {}).get("registration", "N/A")}
              - Roaming: {signal_data.get("generic", {}).get("roaming", "N/A")}
              - IPv6: {signal_data.get("generic", {}).get("hasIPv6", "N/A")}
            """
            self.signal_strength_info.setPlainText(signal_info)

        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Error", f"Failed to get signal strength: {e}")

    def get_system_info(self):
        """Get comprehensive system information including SIM, cell, and version"""
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            
            self.system_info_display.setPlainText("Loading system information...")
            
            system_info = "=== SYSTEM INFORMATION ===\n\n"
            
            # Get version info
            try:
                version_url = "http://192.168.12.1/TMI/v1/version"
                version_response = requests.get(version_url, headers=headers, timeout=5)
                if version_response.status_code == 200:
                    version_data = version_response.json()
                    system_info += f"API Version: {version_data.get('version', 'N/A')}\n\n"
            except:
                system_info += "API Version: Unable to retrieve\n\n"
            
            # Get SIM info
            try:
                sim_url = "http://192.168.12.1/TMI/v1/network/telemetry?get=sim"
                sim_response = requests.get(sim_url, headers=headers, timeout=5)
                if sim_response.status_code == 200:
                    sim_data = sim_response.json().get('sim', {})
                    system_info += "=== SIM INFORMATION ===\n"
                    system_info += f"  ICCID: {sim_data.get('iccId', 'N/A')}\n"
                    system_info += f"  IMEI: {sim_data.get('imei', 'N/A')}\n"
                    system_info += f"  IMSI: {sim_data.get('imsi', 'N/A')}\n"
                    system_info += f"  MSISDN: {sim_data.get('msisdn', 'N/A')}\n"
                    system_info += f"  Status: {'Active' if sim_data.get('status') else 'Inactive'}\n\n"
            except:
                system_info += "=== SIM INFORMATION ===\nUnable to retrieve SIM info\n\n"
            
            # Get cell info
            try:
                cell_url = "http://192.168.12.1/TMI/v1/network/telemetry?get=cell"
                cell_response = requests.get(cell_url, headers=headers, timeout=5)
                if cell_response.status_code == 200:
                    cell_data = cell_response.json().get('cell', {})
                    
                    # 5G Info
                    if '5g' in cell_data:
                        fiveg = cell_data['5g']
                        system_info += "=== 5G CELL INFORMATION ===\n"
                        system_info += f"  Bandwidth: {fiveg.get('bandwidth', 'N/A')}\n"
                        system_info += f"  EARFCN: {fiveg.get('earfcn', 'N/A')}\n"
                        system_info += f"  ECGI: {fiveg.get('ecgi', 'N/A')}\n"
                        system_info += f"  MCC: {fiveg.get('mcc', 'N/A')}\n"
                        system_info += f"  MNC: {fiveg.get('mnc', 'N/A')}\n"
                        system_info += f"  PCI: {fiveg.get('pci', 'N/A')}\n"
                        system_info += f"  PLMN: {fiveg.get('plmn', 'N/A')}\n"
                        system_info += f"  TAC: {fiveg.get('tac', 'N/A')}\n"
                        system_info += f"  Supported Bands: {', '.join(fiveg.get('supportedBands', []))}\n"
                        
                        if 'sector' in fiveg:
                            sector = fiveg['sector']
                            system_info += f"\n  Sector Info:\n"
                            system_info += f"    Antenna: {sector.get('antennaUsed', 'N/A')}\n"
                            system_info += f"    Bands: {', '.join(sector.get('bands', []))}\n"
                            system_info += f"    Bars: {sector.get('bars', 'N/A')}\n"
                            system_info += f"    CID: {sector.get('cid', 'N/A')}\n"
                            system_info += f"    gNBID: {sector.get('gNBID', 'N/A')}\n"
                            system_info += f"    RSRP: {sector.get('rsrp', 'N/A')} dBm\n"
                            system_info += f"    RSRQ: {sector.get('rsrq', 'N/A')} dB\n"
                            system_info += f"    RSSI: {sector.get('rssi', 'N/A')} dBm\n"
                            system_info += f"    SINR: {sector.get('sinr', 'N/A')} dB\n"
                        system_info += "\n"
                    
                    # Generic Info
                    if 'generic' in cell_data:
                        generic = cell_data['generic']
                        system_info += "=== NETWORK STATUS ===\n"
                        system_info += f"  APN: {generic.get('apn', 'N/A')}\n"
                        system_info += f"  Registration: {generic.get('registration', 'N/A')}\n"
                        system_info += f"  Roaming: {'Yes' if generic.get('roaming') else 'No'}\n"
                        system_info += f"  IPv6: {'Enabled' if generic.get('hasIPv6') else 'Disabled'}\n\n"
                    
                    # GPS Info
                    if 'gps' in cell_data:
                        gps = cell_data['gps']
                        system_info += "=== GPS LOCATION ===\n"
                        system_info += f"  Latitude: {gps.get('latitude', 'N/A')}\n"
                        system_info += f"  Longitude: {gps.get('longitude', 'N/A')}\n\n"
                        
            except:
                system_info += "=== CELL INFORMATION ===\nUnable to retrieve cell info\n\n"
            
            self.system_info_display.setPlainText(system_info)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to get system information: {e}")
            self.system_info_display.setPlainText("Error retrieving system information")

    def get_devices(self):
        try:
            url = "http://192.168.12.1/TMI/v1/network/telemetry?get=clients"
            #url = "http://192.168.12.1/TMI/v1/gateway?get=all"
            headers = {'Authorization': f'Bearer {self.token}'}
            
            self.device_info.setPlainText(f"Request Sent! \n(This can take 30 seconds...)")
            
            response = requests.get(url, headers=headers)
            #print(str(response.json()))
            #response.raise_for_status() 

            device_data = response.json()
            device_list = ""

            
            # Format signal strength information (customize as needed)
            if "2.4ghz" in device_data["clients"] :
                for i in device_data["clients"]["2.4ghz"] :
                    device_list = device_list + f"""
                    2.4Ghz:
                      - Name: {i.get("name", "N/A")}
                      - Connected: {i.get("connected", "N/A")}
                      - MAC: {i.get("mac", "N/A")}
                      - IPV4: {i.get("ipv4", "N/A")} 
                      - IPV6: {i.get("ipv6", "N/A")}
                      - Signal: {i.get("signal", "N/A")} dBm
                    """
            if "5.0ghz" in device_data["clients"] :
                for i in device_data["clients"]["5.0ghz"] :
                    device_list = device_list + f"""
                    5Ghz:
                      - Name: {i.get("name", "N/A")}
                      - Connected: {i.get("connected", "N/A")}
                      - MAC: {i.get("mac", "N/A")}
                      - IPV4: {i.get("ipv4", "N/A")} 
                      - IPV6: {i.get("ipv6", "N/A")}
                      - Signal: {i.get("signal", "N/A")} dBm
                    """
            if "ethernet" in device_data["clients"] :
                for i in device_data["clients"]["ethernet"] :
                    device_list = device_list + f"""
                    Ethernet:
                      - Name: {i.get("name", "N/A")}
                      - Connected: {i.get("connected", "N/A")}
                      - MAC: {i.get("mac", "N/A")}
                      - IPV4: {i.get("ipv4", "N/A")} 
                      - IPV6: {i.get("ipv6", "N/A")}
                    """
            
            self.device_info.setPlainText(device_list)

        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Error", f"Failed to get signal strength: {e}")
            
    def closeEvent(self, event):
        # Clean up files before closing
        self.cleanup_files()
        event.accept()

    def cleanup_files(self):
        if Path(temp_wifi_input).exists():
            remove(temp_wifi_input)
        if Path(temp_wifi_out).exists():
            remove(temp_wifi_out) 

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
