# YARA Scanner GUI

A Python-based graphical interface for scanning files with YARA rules to detect malware signatures.  
This project demonstrates practical cybersecurity skills, including rule creation, malware detection, and GUI development.



## Features
- GUI-based scanning using Python.
- Custom YARA rules (`malware_rules.yara`) for malware detection.
- Scan logging (`scan_log.csv`) to track results.
- UML diagrams (`class.puml`, `activity.puml`, etc.) for system design documentation.
- Sample files in `/samples` for testing.



## Project Structure
├── yara_scanner_gui.py       # Main GUI application 
├── malware_rules.yara        # YARA rules for detection 
├── scan_log.csv              # Log of scan results 
├── samples/                  # Test files
├── *.puml                    # UML diagrams (class, activity, sequence, etc.) 
└── Project Information.pdf   # Project overview



## Installation and Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/ANJALI-V55/yara-scanner-gui.git
   cd yara-scanner-gui

2. Install dependencies 
   pip install yara-python

3. Run the GUI:
   python yara_scanner_gui.py

## Future Enhancements- 
  - Add support for real-time scanning of     directories.
  - Expand rule sets for broader malware coverage.
  - Integrate with threat intelligence feeds.
  - Package as a standalone executable for easy deployment.


## Author
Developed by Anjali V, B.Tech in Computer Science (Cyber Security specialization).
Focused on malware detection, vulnerability testing, and secure software design.