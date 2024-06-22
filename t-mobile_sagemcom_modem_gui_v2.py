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
    QPlainTextEdit
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

        tab_widget = QTabWidget()
        tab_widget.addTab(self.connection_tab, "Connection")
        tab_widget.addTab(self.wifi_settings_tab, "WiFi Settings")
        tab_widget.addTab(self.device_tab, "DHCP Clients")
        tab_widget.addTab(self.signal_strength_tab, "Signal Strength")

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
        self.connection_tab.setLayout(layout)

    def create_wifi_settings_tab(self):
        self.wifi_settings_tab = QWidget()
        layout = QVBoxLayout()

        self.wifi_info_label = QLabel("Wifi Information:")
        self.wifi_info = QPlainTextEdit()  # Use QPlainTextEdit for multi-line text
        self.wifi_info.setReadOnly(True)  # Make it read-only

        self.enable_24ghz_button = QPushButton("Enable 2.4 GHz")
        self.enable_24ghz_button.clicked.connect(lambda: self.change_wifi_status('2'))
        self.enable_5ghz_button = QPushButton("Enable 5.0 GHz")
        self.enable_5ghz_button.clicked.connect(lambda: self.change_wifi_status('3'))
        self.enable_both_button = QPushButton("Enable Both")
        self.enable_both_button.clicked.connect(lambda: self.change_wifi_status('4'))
        self.disable_all_button = QPushButton("Disable Wifi")
        self.disable_all_button.clicked.connect(lambda: self.change_wifi_status('5'))

        layout.addWidget(self.wifi_info_label)
        layout.addWidget(self.wifi_info)
        layout.addWidget(self.enable_24ghz_button)
        layout.addWidget(self.enable_5ghz_button)
        layout.addWidget(self.enable_both_button)
        layout.addWidget(self.disable_all_button)
        self.wifi_settings_tab.setLayout(layout)
        self.disable_buttons()

    def create_signal_strength_tab(self):
        self.signal_strength_tab = QWidget()
        layout = QVBoxLayout()

        self.signal_strength_label = QLabel("Signal Strength:")
        self.signal_strength_info = QLabel("Not connected")

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
        self.device_info = QLabel("Not connected")

        self.device_button = QPushButton("Refresh")
        self.device_button.clicked.connect(self.get_devices)

        layout.addWidget(self.device_label)
        layout.addWidget(self.device_info)
        layout.addWidget(self.device_button)
        self.device_tab.setLayout(layout)

    def connect_to_router(self):
        try:
            self.admin_pass = self.password_input.text()
            if not self.admin_pass:
                QMessageBox.warning(self, "Error", "Please enter the router admin password.")
                return

            self.token = self.get_token()
            self.connection_status.setText("Connected")
            self.device_info.setText("Connected")
            #self.enable_buttons()
            #self.get_wifi_info_str()
            #self.get_signal_strength()
            #self.get_devices()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect to router: {e}")

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
            
            self.signal_strength_info.setText(f"Request Sent! \n(This can take 30 seconds...)")
            
            response = requests.get(url, headers=headers)
            response.raise_for_status() 
            #print(response.json())
            

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
              - RSSI: {signal_data.get("5g", {}).get("rssi", "N/A")} dBm
            """
            self.signal_strength_info.setText(signal_info)

        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Error", f"Failed to get signal strength: {e}")

    def get_devices(self):
        try:
            url = "http://192.168.12.1/TMI/v1/network/telemetry?get=clients"
            #url = "http://192.168.12.1/TMI/v1/gateway?get=all"
            headers = {'Authorization': f'Bearer {self.token}'}
            
            self.device_info.setText(f"Request Sent! \n(This can take 30 seconds...)")
            
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
            
            self.device_info.setText(device_list)

        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Error", f"Failed to get signal strength: {e}")
            
    def disable_buttons(self):
        self.enable_24ghz_button.setEnabled(False)
        self.enable_5ghz_button.setEnabled(False)
        self.enable_both_button.setEnabled(False)
        self.disable_all_button.setEnabled(False)
        self.refresh_signal_button.setEnabled(False)

    def enable_buttons(self):
        self.enable_24ghz_button.setEnabled(True)
        self.enable_5ghz_button.setEnabled(True)
        self.enable_both_button.setEnabled(True)
        self.disable_all_button.setEnabled(True)
        self.refresh_signal_button.setEnabled(True)

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
