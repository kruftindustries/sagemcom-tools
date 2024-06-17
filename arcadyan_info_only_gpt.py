import sys
import requests
from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLabel, QGroupBox, QGridLayout
from PySide6.QtCore import Qt

class ModemStatusApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Modem Status Viewer")
        self.setGeometry(300, 300, 600, 400)
        
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        
        self.layout = QVBoxLayout(self.main_widget)
        
        self.fetch_button = QPushButton("Fetch Modem Status")
        self.fetch_button.clicked.connect(self.fetch_modem_status)
        self.layout.addWidget(self.fetch_button)
        
        self.status_display = QWidget()
        self.status_layout = QVBoxLayout(self.status_display)
        self.layout.addWidget(self.status_display)
        
    def fetch_modem_status(self):
        url = "http://192.168.12.1/TMI/v1/gateway?get=all"
        try:
            response = requests.get(url)
            response.raise_for_status()
            status_data = response.json()
            self.display_status(status_data)
        except requests.RequestException as e:
            self.display_error(str(e))
    
    def display_status(self, data):
        self.clear_layout(self.status_layout)
        
        device_group = self.create_group_box("Device Information", data.get('device', {}))
        self.status_layout.addWidget(device_group)
        
        time_group = self.create_group_box("Time Information", data.get('time', {}))
        self.status_layout.addWidget(time_group)
        
        signal_group = self.create_group_box("Signal Information", data.get('signal', {}))
        self.status_layout.addWidget(signal_group)
    
    def create_group_box(self, title, info):
        group_box = QGroupBox(title)
        layout = QGridLayout()
        row = 0
        for key, value in info.items():
            if isinstance(value, dict):
                sub_group = self.create_group_box(key.capitalize(), value)
                layout.addWidget(sub_group, row, 0, 1, 2)
            else:
                key_label = QLabel(f"{key.capitalize()}:")
                value_label = QLabel(str(value))
                layout.addWidget(key_label, row, 0)
                layout.addWidget(value_label, row, 1)
            row += 1
        group_box.setLayout(layout)
        return group_box
    
    def display_error(self, message):
        self.clear_layout(self.status_layout)
        error_label = QLabel(f"Error: {message}")
        self.status_layout.addWidget(error_label)
    
    def clear_layout(self, layout):
        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ModemStatusApp()
    window.show()
    sys.exit(app.exec())
