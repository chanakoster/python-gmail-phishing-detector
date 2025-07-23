# 📧 Gmail Email Risk Scanner

This Python tool scans your Gmail inbox for potentially **risky emails** using multiple detection methods and VirusTotal's API. It flags emails with suspicious domains, attachments, QR codes, and other risk indicators.

## 🔍 Features

- ✅ VirusTotal scanning for:
  - Domains
  - URLs
  - File attachments
  - QR codes in images
- ✅ Detection Methods:
  - Email address similarity
  - Fake sender disguise using familiar names
  - Use of urgency language
  - Grammar mistakes
  - Generic greeting
  - Request for sensitive information
- ✅ Gmail integration:
  - Reads and labels emails
  - Sends summary reports
- ✅ Custom risk scoring system (Pass / Low / High)

## 🛠️ Setup

1. Clone this repo or download the ZIP.
2. Set up Gmail API access:
   1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
   2. Create a new project.
   3. Navigate to **APIs & Services > Credentials**.
   4. Click **Create Credentials > OAuth client ID**.
   5. Configure the consent screen if prompted.
   6. Select **Desktop app** or **Web application** as the application type.
   7. Download the generated `credentials.json` file.
   8. Rename the file to `credentials.json` and place it in the project's root folder.
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Create and configure a VirusTotal API key:
   1. **Sign up** for a free VirusTotal account at 👉 [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
   2. **Log in**, then click the **profile picture** in the top-right corner.
   3. From the dropdown menu, select **“API key”**.
   4. **Copy** the API key.
   5. In the project folder, open the `config.py` file and paste the API key like this:

      ```python
      VT_API_KEY = "your_virustotal_api_key_here"
      ```
      >⚠️ **Note:** The VirusTotal API is subject to [VirusTotal’s Terms of Service and Privacy Policy](https://support.virustotal.com/hc/en-us/articles/115002168385-Legal-terms). Submitting files or URLs may result in data being publicly shared. Use responsibly.

5. Install Java (required for grammar checking):
   - LanguageTool requires Java 8–17 to be installed and available in your system path.
   - You can download Java 17 from [https://adoptium.net/](https://adoptium.net/) or use your system's package manager.
6. Install Python 3.8 or higher if not yet installed
   - You can download python from this link [https://www.python.org/downloads/](https://www.python.org/downloads/)
## 🚀 Usage

After completing the setup:

```bash
python main.py
```
## 📄 Reports

- Reports are saved as JSON files in the `reports/` folder.
- Reports are organized by risk level (e.g., `reports/high_risk`, `reports/low_risk`).
- Email reports are also sent to your Gmail inbox as HTML-formatted messages.

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
