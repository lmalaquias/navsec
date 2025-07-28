# navsec
NavSec is the most comprehensive passive web vulnerability and privacy scanner. It performs real-time security analysis directly in your browser, running over 140 automated tests that quickly and accurately detect more than 80 types of vulnerabilities, including exposure of personal data.

## 🔍 Features

- ✅ **Real-time vulnerability detection** (140+ security checks)
- 🔒 **100% passive** – no data is altered or sent externally
- 🌐 **Regional privacy compliance** for **Brazil (LGPD)**, **EU (GDPR)**, **USA (CCPA/HIPAA)**, and more
- 📊 **Security Score**, summary dashboard, and exportable HTML report
- ⚠️ **Advanced detection** of XSS, SQLi, API key leaks, weak CSP, exposed credentials, JWT misuse, and more
- 🔔 **Critical alerts** and Chrome badge updates
- 📥 **Export feature** to download a full technical security report

---

## 🧠 How It Works

1. **Install** from the Chrome Web Store or load it manually
2. Navigate to any site
3. Click the NavSec icon to trigger a passive scan
4. Get instant insights on vulnerabilities, headers, data leaks, and privacy risks
5. Export full HTML security reports (with score and detailed findings)

---

## 📦 Installation

### ➤ Chrome, Brave and Edge Web Store
> [Coming Soon]

### ➤ Manual (Developer Mode)
```bash
git clone https://github.com/lmalaquias/navsec.git
cd navsec
Then:

Open:
chrome://extensions/
brave://extensions/

Enable Developer Mode

Click Load unpacked and select the project folder

📊 Security Score Breakdown
Score Range	Meaning
90–100	🟢 Excellent
70–89	🟡 Good (minor issues)
50–69	🟠 Fair (needs review)
0–49	🔴 Critical issues found

📁 Project Structure
bash
Copiar
Editar
navsec/
├── manifest.json           # Extension configuration
├── background.js           # Scan management & export engine
├── content.js              # DOM-based passive scanner
├── popup.html / popup.js   # UI dashboard with live scan results
├── icons/                  # Extension icons
└── README.md               # This file
📤 Exportable Reports
After a scan, click Export to download a full HTML security report, including:

Overall Security Score

Vulnerability list by severity and category

Evidence, recommendations, and compliance status

🧪 Technologies Used
JavaScript ES6+

Chrome Extension Manifest v3

Regex-based content analysis

Passive DOM inspection

HTML5 + inline CSS reporting

🔒 Privacy First
❌ No data collection

✅ Fully offline

✅ All scans run locally

✅ No cloud dependency

✅ Open source & auditable

📄 License
Licensed under the GNU General Public License v3.0

🔓 Free to use, modify, and share — but always open-source.

👨‍💻 Author
