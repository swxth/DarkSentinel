<img width="1042" height="308" alt="image" src="https://github.com/user-attachments/assets/73af73fb-3df6-4d8e-88e8-f6486e5da5a3" />**DarkSentinel - AI-Powered Dark Web Surveillance Tool**

DarkSentinel is a Python-based tool for monitoring dark web content, detecting high-risk activities, and issuing real-time alerts. It combines Tor-based anonymity, Natural Language Processing (NLP), and AI-powered image/video analysis to identify threats such as drug trafficking, child exploitation, cybercrime, and weapon smuggling.

**Features**

**1. Dark Web Scraping** :

a. Collects content from predefined dark web URLs.

**2. Advanced Threat Detection**

a. NLP to detect dangerous phrases, slang, and encoded data.

b. Automatic translation of non-English text.

c. AI (CLIP model) to analyze images and videos for illicit content.

d. Sentiment analysis (DistilBERT) for threat classification.

**Real-Time Alerts**

a. Severity levels assigned to suspicious activity.

b. Alerts stored in an SQLite database and exportable to text files.

c. Email notifications for critical alerts (Mailjet SMTP integration).

**Privacy by Design**

a. All traffic routed through Tor (SOCKS5 proxy).

b. Periodic Tor identity change for improved anonymity.

**Resilient Monitoring**

a. Automatic retries on failed requests with identity rotation.

b. Continuous scanning loop with adjustable delay.

**Project Structure**

          DarkSentinel/
          ├── env/                     # Virtual environment folder (myenv)
          ├── myenv/                   # Alternate virtual environment folder (if used)
          ├── templates/               # Web templates
          │   └── ds.html              # Web dashboard for viewing alerts
          ├── .env                     # Environment variables (API keys, secrets)
          ├── dark_web_alerts.db       # SQLite database for storing alerts
          ├── dark_web_alerts.txt      # Exported alerts in text format
          ├── darksentinal.py          # Main Python application
          ├── logo.jpg                 # Project logo
          └── requirements.txt         # Python dependencies

**Installation**

**1. Clone the repository**

            git clone https://github.com/<your-username>/DarkSentinel.git
            cd DarkSentinel

**2. Create a virtual environment**

            python -m venv myenv
            source myenv/bin/activate    # For Linux/Mac
            myenv\Scripts\activate       # For Windows

**3. Install dependencies**
   
            pip install -r requirements.txt

**4. Install and configure Tor**

-> Install Tor.

-> Ensure Tor SOCKS5 proxy is running at 127.0.0.1:9050.

-> Optionally configure the control port (9051) for identity rotation.

**5. Configure environment variables**

-> Add your Mailjet API keys and Tor password to the .env file:

              MAILJET_USERNAME=your_username
              MAILJET_API_KEY=your_api_key
              TOR_PASSWORD=your_tor_password

**Usage**

Run the main script to start monitoring:

              python darksentinal.py

Gist of what happens:

1. Connects to Tor for anonymous requests.

2. Monitors predefined dark web URLs.

3. Scrapes content and analyzes it with NLP + AI vision.

4. Generates alerts for suspicious activities:

   a. Saves to SQLite database (dark_web_alerts.db).

   b. Exports to a .txt report (dark_web_alerts.txt).

   c. Sends email notifications for high-severity cases.

5. Rotates Tor identity after each check for privacy.

**Tech Stack**

**a. Language:** Python 3.13

**b. Libraries:** requests, stem, spacy, googletrans, regex, transformers (DistilBERT), torch, Pillow, flask, langdetect

**c. Network:** Tor SOCKS5 Proxy (127.0.0.1:9050)

**d. Alerts:** Mailjet SMTP API

**Sample Output**

**Database entries:** URL, detected activity, severity, timestamp

**Console alerts:**

            [ALERT] High-Risk Activity Detected: Drug trafficking
            URL: http://abcxyz.onion
            Severity: HIGH


**Email notifications:**

            Subject: [DarkSentinel] High-Severity Alert
            Body: Detected drug trafficking at http://abcxyz.onion

<img width="960" height="506" alt="image" src="https://github.com/user-attachments/assets/3b786bb8-12d2-4869-971f-09dd14a5058c" />
<img width="1042" height="308" alt="image" src="https://github.com/user-attachments/assets/58541c64-195f-4b2d-b0d1-fa4621f38b2e" />

**Author**
Swetha M- @swxth
