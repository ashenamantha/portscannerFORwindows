# portscannerFORwindows

# Advanced Port Scanner Tool


A sophisticated graphical port scanning utility built with Python and Tkinter that leverages the power of Nmap to provide detailed network reconnaissance information through an intuitive interface.

## Features

- **User-friendly Graphical Interface** - Clean, modern UI for easy interaction
- **Multiple Scan Types**:
  - Basic port scanning
  - Version detection scanning
  - Service information gathering
  - OS detection (requires admin/root privileges)
- **Real-time Results** - View scan results as they're discovered
- **Color-coded Results** - Quickly identify open, closed, or filtered ports
- **Custom Port Ranges** - Scan specific port ranges or use preset options
- **Progress Tracking** - Monitor scan progress with a visual progress bar
- **Result Saving** - Export scan results to text files for documentation
- **Network Utilities**:
  - Ping hosts
  - DNS lookups
  - Whois information
- **Configurable Options** - Adjust timeout settings and scan parameters

## Installation

### Prerequisites

- Python 3.x
- Tkinter (usually included with Python)
- Nmap
- python-nmap library

### Windows Installation

1. **Install Python**:
   - Download and install Python from [python.org](https://www.python.org/downloads/)
   - Make sure to check "Add Python to PATH" during installation

2. **Install Nmap**:
   - Download and install Nmap from [nmap.org](https://nmap.org/download.html)
   - Add Nmap to your system PATH

3. **Install Python Requirements**:
   ```bash
   pip install python-nmap
   ```

4. **Download the Port Scanner**:
   ```bash
   git clone https://github.com/ashenamantha/port-scanner-gui.git
   cd port-scanner-gui
   ```

5. **Run the Application**:
   ```bash
   python port_scanner_gui.py
   ```

### Linux Installation

1. **Install Python, Tkinter, and Nmap**:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-tk nmap
   ```

2. **Install Python Requirements**:
   ```bash
   pip3 install python-nmap
   ```

3. **Download the Port Scanner**:
   ```bash
   https://github.com/ashenamantha/portscannerFORwindows.git
   cd /portscannerFORwindows
   ```

4. **Run the Application**:
   ```bash
   python3 port_scanner_gui.py
   ```

## Usage Guide

### Basic Scanning

1. **Enter Target Information**:
   - Input the IP address of the target
   - Select a port range (e.g., 1-1024 for common ports)

2. **Configure Scan Options**:
   - Choose a scan type from the dropdown menu
   - Adjust timeout settings if needed

3. **Start Scanning**:
   - Click "Start Scan" to begin
   - Watch the progress bar for scan status

4. **View Results**:
   - Results appear in the table as they're discovered
   - Green rows indicate open ports
   - Red rows indicate closed ports
   - Yellow rows indicate filtered ports

5. **Save Results**:
   - Click "Save Results" to export scan data to a text file

### Using Network Utilities

Access additional network tools from the "Tools" menu:

- **Ping**: Test connectivity to a host
- **DNS Lookup**: Resolve domain names to IP addresses
- **Host Lookup**: Get host information
- **Whois**: Retrieve domain registration information

## Advanced Features

### Scan Types

- **Basic**: Fast scan that only checks if ports are open/closed/filtered
- **Version Detection**: Attempts to determine service versions running on open ports
- **Service Info**: Provides more detailed information about services
- **OS Detection**: Attempts to identify the operating system (requires admin/root privileges)

### Customization

- **Custom Port Ranges**: Scan specific port ranges beyond the presets
- **Timeout Settings**: Adjust the timeout period for scan operations
- **Results Filtering**: Focus on specific port states

## Legal and Ethical Considerations

Port scanning can be considered an intrusive activity and may be illegal in some jurisdictions if performed without explicit permission from the network owner.

### Legal Usage

This tool should ONLY be used:
- On your own networks
- On networks you have explicit permission to test
- For educational purposes in controlled environments

### Prohibited Usage

Do NOT use this tool to:
- Scan networks without permission
- Conduct unauthorized security assessments
- Attempt to gain unauthorized access
- Disrupt network services

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**:
   - For OS detection scans, run the application with admin/root privileges

2. **Nmap Not Found**:
   - Ensure Nmap is installed and added to your system PATH

3. **Slow Scanning**:
   - Large port ranges will take significant time to scan
   - Reduce the port range or use more specific targeting

4. **Connection Errors**:
   - Check network connectivity to the target
   - Verify firewall settings aren't blocking the scan

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Created by [Ashen Amantha](https://github.com/ashenamantha)

---

**Disclaimer:** This tool is for educational and legitimate network testing purposes only. The author assumes no liability for any misuse or for any damages resulting from the use of this software.
