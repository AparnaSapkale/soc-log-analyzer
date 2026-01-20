# 🚀 Log Analyzer Project

A simple **SOC (Security Operations Center) log analysis tool** written in Python.  
This project parses Apache access logs and detects **suspicious IPs, unusual user agents, and abnormal activity**.  

---

## 📂 Project Structure
log-analyzer-project/
│── logs/ # Input log files (ignored in git)
│ ├── apache_access.log
│ └── auth.log
│
│── output/ # Output reports
│ ├── soc_report.txt
│ └── .gitignore
│
│── src/ # Source code
│ └── main.py
│
│── requirements.txt # Python dependencies
│── LICENSE # Open-source license (MIT)
│── README.md # Project documentation
---

## ⚙️ Features
- Extracts **Top 5 IPs** by request count  
- Detects **suspicious IPs** (based on request threshold)  
- Highlights **suspicious User Agents** (bots, crawlers, scanners)  
- Generates a **SOC report** (`soc_report.txt`)  

---

## 🛠 Installation & Setup

1. Clone this repo:
   git clone https://github.com/AparnaSapkale/log-analyzer-project.git
   cd log-analyzer-project

2. Install dependencies:

    pip install -r requirements.txt

3. Run the analyzer:

    python src/main.py

4. Find the report in:

    output/soc_report.txt

## ℹ️ Note: Real logs are ignored for privacy; a sample log is provided for testing.

## 📑 Sample Logs & Reports
- `logs/apache_access.log` → Example input log file  
- `output/soc_report.txt` → Example SOC analysis report generated from the sample log.  
  *(When you run the tool on your own logs, you’ll get a similar report.)*

📊 Example Output

==== SOC ANALYST REPORT ====

🔎 Top 5 Suspicious IPs:
IP: 66.249.73.135 → 432 requests
Analysis: 🚨 Possible DoS / Crawling (High request volume)

🤖 Suspicious User Agents Detected:
- Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)
- Wget/1.12 (linux-gnu)
- Python-urllib/2.7