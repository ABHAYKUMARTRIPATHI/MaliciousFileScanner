# 🛡️ Malicious File Scanner

A modular Python-based tool to scan files for malicious behavior using:
- 🔍 Hash-based signature detection
- 🧬 YARA rules
- 🌐 VirusTotal API
- 🤖 Machine Learning (optional)

---

## 📁 Project Structure
MaliciousFileScanner/
├── main.py
├── scanner/
│   ├── hash_checker.py
│   ├── vt_checker.py
│   ├── yara_scanner.py
│   ├── ml_detector.py
│   └── init.py
├── data/
│   ├── known_hashes.txt
│   └── yara_rules.yar
├── reports/
│   └── scan_log.txt
├── models/
│   └── model.pkl (optional ML model)
├── requirements.txt
└── README.md

---

## 🚀 Features

| Feature              | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| ✅ Hash Checker       | Compares SHA256 of the file with known malicious hashes                    |
| ✅ YARA Scanner       | Applies custom YARA rules to detect suspicious content                     |
| ✅ VirusTotal API     | Integrates VirusTotal to check scan results using their public API         |
| ✅ ML Classifier      | Uses a trained ML model to detect anomalies in PE file features            |
| ✅ CLI Interface      | Easy-to-use command line scanner                                            |
| ✅ Logs               | All scan results are stored in `reports/scan_log.txt`                      |

---

## 🛠️ Setup Instructions

cd MaliciousFileScanner

python3 -m venv venv

source venv/bin/activate  # Windows: venv\Scripts\activate

VT_API_KEY=youractualapikey(https://www.virustotal.com/gui/join-us)go and get your API

pip install -r requirements.txt

python main.py path/to/file.exe

---

📊 Output

You’ll see a detailed scan report in the terminal and the same result saved to:

reports/scan_log.txt

---

🧠 ML Detection (Optional)
	•	Train your own classifier (e.g., RandomForest, SVM) on PE file features
	•	Save the model as model.pkl inside models/
	•	The tool will auto-load and predict the file’s behavior

---
📦 Dependencies
	•	Python 3.7+
	•	yara-python
	•	pefile
	•	scikit-learn
	•	requests

---
📌 Disclaimer

This tool is for educational and research purposes only. Use it responsibly and only on files you own or have permission to test.

---
👨‍💻 Author

Abhay Kumar Tripathi
Cyber Forensics & InfoSec Enthusiast
GitHub: ABHAYKUMARTRIPATHI
