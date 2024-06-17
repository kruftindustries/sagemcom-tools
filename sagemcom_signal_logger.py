import sys
import requests
from PySide6.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget, QGridLayout, QGroupBox, QComboBox, QHBoxLayout
from PySide6.QtCore import QTimer, QDateTime, Qt
from PySide6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis, QDateTimeAxis
from PySide6.QtGui import QPainter

class ModemStatusApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Modem Status")
        
        self.layout = QVBoxLayout()
        
        self.device_info_group = QGroupBox("Device Information")
        self.device_info_layout = QGridLayout()
        self.device_info_group.setLayout(self.device_info_layout)
        self.layout.addWidget(self.device_info_group)
        
        self.signal_info_group = QGroupBox("Signal Information")
        self.signal_info_layout = QGridLayout()
        self.signal_info_group.setLayout(self.signal_info_layout)
        self.layout.addWidget(self.signal_info_group)
        
        self.time_info_group = QGroupBox("Time Information")
        self.time_info_layout = QGridLayout()
        self.time_info_group.setLayout(self.time_info_layout)
        self.layout.addWidget(self.time_info_group)
        
        self.device_labels = {}
        self.signal_labels = {}
        self.time_labels = {}
        
        self.create_device_info_labels()
        self.create_signal_info_labels()
        self.create_time_info_labels()
        
        self.interval_layout = QHBoxLayout()
        self.interval_label = QLabel("Update Interval:")
        self.interval_combo = QComboBox()
        self.interval_combo.addItems(["5 seconds", "10 seconds", "30 seconds", "1 minute"])
        self.interval_combo.currentIndexChanged.connect(self.change_interval)
        self.interval_layout.addWidget(self.interval_label)
        self.interval_layout.addWidget(self.interval_combo)
        self.layout.addLayout(self.interval_layout)
        
        self.chart = QChart()
        self.chart_view = QChartView(self.chart)
        self.chart_view.setRenderHint(QPainter.Antialiasing)
        self.layout.addWidget(self.chart_view)
        
        self.series_4g_rssi = QLineSeries()
        self.series_4g_rssi.setName("4G RSSI")
        self.series_5g_rssi = QLineSeries()
        self.series_5g_rssi.setName("5G RSSI")
        
        self.chart.addSeries(self.series_4g_rssi)
        self.chart.addSeries(self.series_5g_rssi)
        
        self.axis_x = QDateTimeAxis()
        self.axis_x.setTickCount(10)
        self.axis_x.setFormat("hh:mm:ss")
        self.axis_x.setTitleText("Time")
        self.chart.addAxis(self.axis_x, Qt.AlignBottom)
        
        self.axis_y = QValueAxis()
        self.axis_y.setLabelFormat("%i")
        self.axis_y.setTitleText("RSSI")
        self.chart.addAxis(self.axis_y, Qt.AlignLeft)
        
        self.series_4g_rssi.attachAxis(self.axis_x)
        self.series_4g_rssi.attachAxis(self.axis_y)
        self.series_5g_rssi.attachAxis(self.axis_x)
        self.series_5g_rssi.attachAxis(self.axis_y)
        
        self.main_widget = QWidget()
        self.main_widget.setLayout(self.layout)
        self.setCentralWidget(self.main_widget)
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_status)
        self.timer.start(5000)
        
        self.update_status()
        
    def create_device_info_labels(self):
        labels = ["Type", "Manufacturer", "Model", "Serial", "Software Version", "Hardware Version", "MAC ID"]
        for i, label in enumerate(labels):
            self.device_info_layout.addWidget(QLabel(f"{label}:"), i, 0)
            self.device_labels[label] = QLabel("N/A")
            self.device_info_layout.addWidget(self.device_labels[label], i, 1)
    
    def create_signal_info_labels(self):
        labels = ["4G SINR", "4G RSRP", "4G RSRQ", "4G RSSI", "4G Bands", "4G Bars", 
                  "5G SINR", "5G RSRP", "5G RSRQ", "5G RSSI", "5G Bands", "5G Bars"]
        for i, label in enumerate(labels):
            self.signal_info_layout.addWidget(QLabel(f"{label}:"), i, 0)
            self.signal_labels[label] = QLabel("N/A")
            self.signal_info_layout.addWidget(self.signal_labels[label], i, 1)
    
    def create_time_info_labels(self):
        labels = ["Uptime", "Local Time", "Timezone", "Daylight Savings"]
        for i, label in enumerate(labels):
            self.time_info_layout.addWidget(QLabel(f"{label}:"), i, 0)
            self.time_labels[label] = QLabel("N/A")
            self.time_info_layout.addWidget(self.time_labels[label], i, 1)
    
    def update_status(self):
        try:
            response = requests.get("http://192.168.12.1/TMI/v1/gateway?get=all")
            data = response.json()
            
            device_info = data['device']
            self.device_labels["Type"].setText(device_info['type'])
            self.device_labels["Manufacturer"].setText(device_info['manufacturer'])
            self.device_labels["Model"].setText(device_info['model'])
            self.device_labels["Serial"].setText(device_info['serial'])
            self.device_labels["Software Version"].setText(device_info['softwareVersion'])
            self.device_labels["Hardware Version"].setText(device_info['hardwareVersion'])
            self.device_labels["MAC ID"].setText(device_info['macId'])
            
            signal_info_4g = data['signal']['4g']
            signal_info_5g = data['signal']['5g']
            self.signal_labels["4G SINR"].setText(str(signal_info_4g['sinr']))
            self.signal_labels["4G RSRP"].setText(str(signal_info_4g['rsrp']))
            self.signal_labels["4G RSRQ"].setText(str(signal_info_4g['rsrq']))
            self.signal_labels["4G RSSI"].setText(str(signal_info_4g['rssi']))
            self.signal_labels["4G Bands"].setText(", ".join(signal_info_4g['bands']))
            self.signal_labels["4G Bars"].setText(str(signal_info_4g['bars']))
            
            self.signal_labels["5G SINR"].setText(str(signal_info_5g['sinr']))
            self.signal_labels["5G RSRP"].setText(str(signal_info_5g['rsrp']))
            self.signal_labels["5G RSRQ"].setText(str(signal_info_5g['rsrq']))
            self.signal_labels["5G RSSI"].setText(str(signal_info_5g['rssi']))
            self.signal_labels["5G Bands"].setText(", ".join(signal_info_5g['bands']))
            self.signal_labels["5G Bars"].setText(str(signal_info_5g['bars']))
            
            time_info = data['time']
            self.time_labels["Uptime"].setText(str(time_info['upTime']))
            self.time_labels["Local Time"].setText(QDateTime.fromSecsSinceEpoch(time_info['localTime']).toString())
            self.time_labels["Timezone"].setText(time_info['localTimeZone'])
            self.time_labels["Daylight Savings"].setText("Yes" if time_info['daylightSavings']['isUsed'] else "No")
            
            current_time = QDateTime.currentDateTime().toMSecsSinceEpoch()
            self.series_4g_rssi.append(current_time, signal_info_4g['rssi'])
            self.series_5g_rssi.append(current_time, signal_info_5g['rssi'])
            #print(self.series_4g_rssi)
            
            if self.series_4g_rssi.count() > 20:
                self.series_4g_rssi.remove(0)
            if self.series_5g_rssi.count() > 20:
                self.series_5g_rssi.remove(0)
            
            self.axis_x.setMin(QDateTime.currentDateTime().addSecs(-100))
            self.axis_x.setMax(QDateTime.currentDateTime())

            
            self.chart.removeSeries(self.series_4g_rssi)
            self.chart.removeSeries(self.series_5g_rssi)
            self.chart.addSeries(self.series_4g_rssi)
            self.chart.addSeries(self.series_5g_rssi)
        
        except requests.RequestException as e:
            print(f"Error fetching data: {e}")
    
    def change_interval(self):
        interval_text = self.interval_combo.currentText()
        interval_mapping = {
            "5 seconds": 5000,
            "10 seconds": 10000,
            "30 seconds": 30000,
            "1 minute": 60000
        }
        interval = interval_mapping.get(interval_text, 5000)
        self.timer.setInterval(interval)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ModemStatusApp()
    window.show()
    sys.exit(app.exec())
