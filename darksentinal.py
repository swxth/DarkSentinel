from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from bs4 import BeautifulSoup
import requests
from stem import Signal
from stem.control import Controller
import time
import sqlite3
from datetime import datetime
import spacy
import nltk
import transformers
import tensorflow as tf
from nltk.tokenize import word_tokenize
from transformers import pipeline
from transformers import BertTokenizer
import string
from langdetect import detect
from googletrans import Translator
import getpass
import os
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
import re
import base64
from urllib.parse import urlparse, urlunparse
import cv2
import numpy as np
from PIL import Image
import requests
from io import BytesIO
import torch
from transformers import CLIPProcessor, CLIPModel
import torchvision
from torchvision import transforms
from urllib.parse import urlparse, parse_qs, urlunparse
import random


def set_tor_proxy():
    session = requests.Session()
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    return session

def get_user_input():
    print("\n")
    print("WELCOME TO DARK SENTINEL")
    tor_password = getpass.getpass("Enter your Tor password (The password you enter will not be displayed to ensure your security) : " ) 
    recipient_email = input("Enter the recipient's email for alerts: ")
    alert_preference = input("Select alert preferences (high, medium, low, all): ").lower()
    return tor_password, recipient_email, alert_preference

def change_tor_identity(password):
    with Controller.from_port(port=9051) as controller:
        controller.authenticate(password=password)  
        controller.signal(Signal.NEWNYM)  
        print("Tor identity changed")

def test_tor_connection():
    session = set_tor_proxy()
    response = session.get('http://httpbin.org/ip')  
    print("Your IP through Tor is:", response.text)

def send_alert_via_email(alert_message, recipient_email):
    sender_email = "darksentinaloff@gmail.com"  
    mailjet_username = "8847706341347bbebb2ffc5d19e6f013"  
    mailjet_api_key = "b421afdc4e232d301c1aa719d9e7cd63"  
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = "Dark Web Alert: Suspicious Activity Detected"
    
    body =  f"""
    Dear User,

    This is an automated alert from Dark Sentinal.

    A high-severity anomaly has been detected related to illegal activities on the dark web.

    Details:
    ------------------------
    URL: {alert_message['url']}
    Detected Activity: {alert_message['detected_activity']}
    Severity: {alert_message['severity']}

    A full analysis of the situation has been triggered and is currently under review.

    Please take necessary precautions as soon as possible.

    If you need further assistance, feel free to contact the security team.

    Regards,
    The DarkSentinal Team
    ------------------------

    This is an automated message. Please do not reply to this email.
    """
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP('in-v3.mailjet.com', 587) 
        server.starttls()  
        server.login(mailjet_username, mailjet_api_key)  
        text = msg.as_string()
        server.sendmail(sender_email, recipient_email, text)
        server.quit()
        print("Alert email sent successfully!")
    except smtplib.SMTPAuthenticationError as e:
        print("Authentication error:", e)
        print("Email not sent!")
    except smtplib.SMTPConnectError as e:
        print("Connection error:", e)
        print("Email not sent!")
    except smtplib.SMTPException as e:
        print("SMTP error:", e)
        print("Email not sent!")
    except Exception as e:
        print(f"General error: {e}")
        print("Email not sent!")

def connect_to_db():
    conn = sqlite3.connect('dark_web_alerts.db') 
    return conn

def create_table(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            detected_activity TEXT,
            videoimg_detection TEXT,
            severity TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()

def save_alert_to_db(conn, alert_message):
    cursor = conn.cursor()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute('''
        INSERT INTO alerts (url, detected_activity, severity, timestamp)
        VALUES (?, ?, ?, ?)
    ''' ,(alert_message['url'], alert_message['detected_activity'], alert_message['severity'], current_time))
    
    conn.commit()
    print(f"Alert saved to database: {alert_message['url']}, {alert_message['detected_activity']}, {alert_message['severity']} at {current_time}")

def export_db_to_txt(db_file, output_file):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts")
    with open(output_file, 'w', encoding='utf-8') as txtfile:
        column_names = [description[0] for description in cursor.description]
        txtfile.write(" | ".join(column_names) + "\n")
        txtfile.write("-" * 50 + "\n")
        for row in cursor.fetchall():
            txtfile.write(" | ".join(str(cell) for cell in row) + "\n")
    conn.close()

nlp = spacy.load("en_core_web_sm")
def analyze_dependencies(text):
    doc = nlp(text)
    relationships = []
    for token in doc:
        if token.dep_ in ['dobj', 'prep', 'pobj', 'agent']:
            relationships.append((token.head.text, token.dep_, token.text))
    
    return relationships

def detect_dangerous_phrases(text):
    relationships = analyze_dependencies(text)
    dangerous_phrases = [
    ("buy", "dobj", "heroin"),
    ("purchase", "dobj", "heroin"),
    ("sell", "dobj", "drugs"),
    ("distribute", "dobj", "fentanyl"),
    ("smuggle", "dobj", "cocaine"),
    ("traffic", "dobj", "methamphetamine"),
    ("sell", "dobj", "methamphetamine"),
    ("distribute", "dobj", "cocaine"),
    ("buy", "dobj", "crack"),
    ("deal", "dobj", "heroin"),
    ("purchase", "dobj", "methamphetamine"),
    ("sell", "dobj", "LSD"),
    ("distribute", "dobj", "LSD"),
    ("import", "dobj", "ecstasy"),
    ("export", "dobj", "marijuana"),
    ("produce", "dobj", "synthetic drugs"),
    ("create", "dobj", "designer drugs"),
    ("use", "dobj", "steroids"),
    ("manufacture", "dobj", "methamphetamine"),
    ("supply", "dobj", "opioids"),
    ("ship", "dobj", "drugs"),
    ("distribute", "dobj", "stimulants"),
    ("market", "dobj", "drug paraphernalia"),
    ("sell", "dobj", "drug-related equipment"),
    ("buy", "dobj", "counterfeit drugs"),
    ("trade", "dobj", "illicit substances"),
    ("obtain", "dobj", "illegal drugs"),
    ("procure", "dobj", "narcotics"),
    ("transport", "dobj", "drugs"),
    ("import", "dobj", "drug precursors"),
    ("sell", "dobj", "human trafficking"),
    ("recruit", "dobj", "human trafficking victims"),
    ("buy", "dobj", "child exploitation material"),
    ("sell", "dobj", "child exploitation material"),
    ("distribute", "dobj", "child pornography"),
    ("upload", "dobj", "illegal content"),
    ("stream", "dobj", "pirated content"),
    ("hack", "dobj", "systems"),
    ("phish", "dobj", "personal information"),
    ("steal", "dobj", "credit card details"),
    ("launder", "dobj", "money"),
    ("sell", "dobj", "stolen data"),
    ("exploit", "dobj", "vulnerabilities"),
    ("scam", "dobj", "victims"),
    ("buy", "dobj", "weapons"),
    ("sell", "dobj", "weapons"),
    ("distribute", "dobj", "explosives"),
    ("steal", "dobj", "credentials"),
    ("distribute", "dobj", "malware"),
    ("use", "dobj", "ransomware"),
    ("hack", "dobj", "system"),
    ("buy", "dobj", "malware"),
    ("advertise", "dobj", "fake websites"),
    ("withdraw", "dobj", "crypto"),
    ("sell", "dobj", "botnet"),
    ("mine", "dobj", "cryptocurrency"),
    ("launder", "dobj", "crypto")
    ]  
    detected_phrases = []
    for head, dep, token in relationships:
        for phrase in dangerous_phrases:
            if (head == phrase[0] and dep == phrase[1] and token.lower() == phrase[2]):
                detected_phrases.append(f"Dangerous phrase detected: {head} {dep} {token}")
    
    return detected_phrases

slang_dict = {
    "an0n": "Anonymous person",
    "cloak": "To hide one's identity or activities",
    "ghost": "Invisible or undetectable online",
    "vpn": "Virtual Private Network",
    "proxy": "Server to mask IP address",
    "wh1t3h4t": "Ethical hacker",
    "blackhat": "Malicious hacker",
    "r00t": "Root access to a system",
    "ghosting": "Disappearing or deleting traces",
    "darknet": "Hidden part of the internet",
    "se0": "Search engine optimization for illegal sites",
    "v1rgin": "Inexperienced user, often targeted",
    "scr0t": "Storing sensitive info illicitly",
    "f4ke": "Fake identities or items",
    "deepweb": "Non-indexed part of the internet",
    "r3kt": "Compromised or hacked",
    "shadow": "Stealthy online presence",
    "pwned": "Account or system compromised",
    "spoof": "Impersonating or falsifying info",
    "smurfing": "Using low-level accounts for hacking",
    "exploit": "Method to gain unauthorized access",
    "phreaking": "Hacking telephone systems",
    "rootkit": "Malicious software for system control",
    "dropbox": "Anonymous location for illegal exchange",
    "w4rez": "Pirated software",
    "rip": "Stolen or copied media/data",
    "doxing": "Releasing personal info without consent",
    "swatting": "Falsely reporting emergencies",
    "underground": "Hidden side of the internet",
    "fakeid": "Forged identification document",
    "coinmining": "Malicious cryptocurrency mining",
    "rat": "Remote Access Trojan (malware)",
    "keylogger": "Software to record keystrokes",
    "ddos": "Distributed Denial of Service attack",
    "zombie": "Infected, hacker-controlled computer",
    "leak": "Unauthorized release of sensitive info",
    "ccdump": "Selling stolen credit card data",
    "spoofer": "Falsifying information (e.g., IP address)",
    "ratware": "Malware for remote access.",
    "carding": "Fraudulent use of credit card info.",
    "b0t": "Automated malicious script.",
    "ransomware": "Malware that demands ransom.",
    "zero-day": "Exploiting unknown vulnerabilities.",
    "n00b": "Inexperienced user, often targeted.",
    "deepfake": "Synthetic media for deception.",
    "doxxing": "Releasing private info online.",
    "pharming": "Redirecting users to fake websites.",
    "skimming": "Stealing credit card info with devices.",
    "shady": "Suspicious or illegal activity.",
    "underground market": "Illegal goods/services marketplace.",
    "darknet marketplace": "Platform for illicit transactions.",
    "cyberattack": "Intentional disruption or damage to systems.",
    "whaling": "Phishing targeting high-profile individuals.",
    "fud": "Spreading misinformation to manipulate.",
    "hacking tool": "Software for system compromise.",
    "exploit kit": "Tools to exploit system vulnerabilities.",
    "r00ted": "Compromised system with admin access.",
    "smurfing": "Money laundering through small transactions.",
    "spyware": "Software that secretly monitors activities.",
    "trojan": "Malicious software disguised as legit.",
    "zero-click": "Exploits needing no user interaction.",
    "backdoor": "Hidden access for future exploitation.",
    "brute-force": "Cracking passwords by trial and error.",
    "p2p": "Peer-to-peer illegal file sharing.",
    "h0wto": "Guides for illegal activities.",
    "data breach": "Unauthorized access to sensitive data.",
    "leak site": "Sites hosting stolen data.",
    "dump": "Collection of stolen data.",
    "botnet": "Network of hacked devices controlled by attackers.",
    "hacked": "Compromised system or account.",
    "crypto-jacking": "Stealing system resources to mine crypto.",
    "4/20" : "marijuana",
    "H": "heroin"
}
def detect_slang(text, slang_dict):
    text = text.translate(str.maketrans('', '', string.punctuation))  
    detected_terms = {}
    for word in text.split():
        if word.lower() in slang_dict:
            detected_terms[word] = slang_dict[word.lower()]
    return detected_terms

def retry_on_failure(session, url, retries=3, tor_password=None):
    for attempt in range(retries):
        try:
            response = session.get(url, timeout=10)
            if response.status_code == 200:
                return response
            elif tor_password:
                change_tor_identity(tor_password)
                time.sleep(5)  
        except Exception as e:
            print(f"Attempt {attempt + 1} failed for {url}: {e}")
            time.sleep(5)
    print(f"Failed to access {url} after {retries} attempts.")
    return None

translator = Translator()
def detect_and_translate(text):
    try:
        detected_language = detect(text)
        if detected_language != 'en':
            translated_text = translator.translate(text, src=detected_language, dest='en').text
            print(f"Original text (no translation): {text}","\n")
            print(f"Translated text: {translated_text}","\n")
            return translated_text.lower()
        return text.lower()
    except Exception as e:
        print(f"Error in language detection or translation: {e}","\n")
        return text.lower()
    
def detect_encoded_strings(text):
    encoded_pattern = r'[A-Za-z0-9+/=]{20,}'
    matches = re.findall(encoded_pattern, text)
    return matches
    
def decode_base64(encoded_strings):
    decoded_results = {}
    for encoded in encoded_strings:
        try:
            decoded_bytes = base64.b64decode(encoded)
            try:
                decoded_text = decoded_bytes.decode('utf-8')
                decoded_results[encoded] = decoded_text
            except UnicodeDecodeError:
                decoded_results[encoded] = f"Failed to decode as UTF-8: Binary data"
        except base64.binascii.Error:
            decoded_results[encoded] = "Failed to decode: Incorrect padding or invalid base64"
        except Exception as e:
            decoded_results[encoded] = f"Failed to decode: {e}"
    return decoded_results

model = CLIPModel.from_pretrained("openai/clip-vit-base-patch32")
processor = CLIPProcessor.from_pretrained("openai/clip-vit-base-patch32")
def detect_image(image_tensor):
    queries = [
    "drug trafficking", "drug packaging", "illegal drugs", "drug cartels", "drug distribution networks",
    "fentanyl trafficking", "heroin production", "methamphetamine labs", "cocaine trafficking", 
    "drug smuggling routes", "drug manufacturing equipment", "drug storage", "drug overdose", 
    "drug money laundering", "synthetic drugs", "drug lab chemicals", "child abuse images", 
    "child pornography", "child sexual exploitation", "illegal child trafficking", "online child abuse", 
    "cyberbullying of children", "child exploitation rings", "child exploitation material", "pedophilia rings", 
    "sexual abuse of minors", "child trafficking networks", "online predators targeting children", 
    "child abuse documentation", "underage prostitution", "dark web child abuse forums", 
    "victims of child exploitation", "illegal weapons", "weapon storage", "arms trafficking", 
    "weapon smuggling", "military-grade weapons", "assault rifle trade", "unregistered firearms", 
    "gun parts trafficking", "homemade weapons", "explosives trading", "illegal gun manufacturing", 
    "weapon blueprints", "smuggled weapons", "illicit arms trade networks", "arms trade between cartels", 
    "weapon storage facilities", "cybercrime activities", "dark web hacking services", "data breaches", 
    "identity theft", "DDoS attack services", "malware distribution", "ransomware attacks", "phishing schemes", 
    "credential stuffing", "cyber fraud", "hacking tools", "zero-day exploits", "credit card fraud", 
    "illegal data sales", "cyber extortion", "cryptocurrency theft", "human trafficking", "illegal organ trade", 
    "smuggling networks", "forced labor exploitation", "illegal immigration smuggling", "sex trafficking", 
    "smuggling routes", "contraband trade", "smuggled goods", "counterfeit products", "illegal currency exchange", 
    "drug trafficking networks", "illegal migrant smuggling", "black market smuggling rings", "terrorist financing", 
    "terrorist propaganda", "bomb-making materials", "extremist organizations", "jihadist recruitment", 
    "radicalization content", "terrorist group communications", "explosives production", "nuclear weapons proliferation", 
    "terrorist training camps", "extremist ideology spread", "chemical warfare agents", "money laundering", 
    "illegal financial transactions", "cryptocurrency laundering", "black market economy", "counterfeit currency", 
    "tax evasion networks", "fraudulent financial schemes", "fraudulent investment opportunities", "illegal gambling operations", 
    "dark web stock market manipulation", "illegal bank transfers", "financial fraud", "Ponzi schemes", "fake credit card production", 
    "malware development", "hacking software", "rootkits", "botnet services", "spyware development", "keyloggers", 
    "exploit kits", "dark web ransomware", "data scraping tools", "illegal cyber surveillance tools", 
    "software piracy tools", "illegal software distribution", "illegal gambling", "counterfeit currencies", 
    "forged documents", "stolen intellectual property", "fake IDs", "black market wildlife trading", 
    "illegal counterfeit drugs", "illegal adult content", "black market electronics", "illegal academic exams", 
    "pirated software", "illegal stock trading practices", "counterfeit luxury goods", "organized crime syndicates", 
    "cartel communications", "money laundering operations", "illegal surveillance", "bribery and corruption", 
    "extortion schemes", "theft and burglary", "stolen property trade", "counterfeit passport rings", "illegal surveillance equipment"
    ]
    inputs = processor(
        text=queries,
        images=image_tensor,
        return_tensors="pt",
        padding=True
    )
    with torch.no_grad():
        logits_per_image = model(**inputs).logits_per_image
        probabilities = logits_per_image.softmax(dim=1)
    max_prob_idx = torch.argmax(probabilities)
    max_prob_value = probabilities[0][max_prob_idx].item()
    max_query = queries[max_prob_idx]
    print(f"Alert: {max_query} detected with probability {max_prob_value}")
    results = {max_query: max_prob_value}
    return results

def detect_images_in_video(video_path):
    cap = cv2.VideoCapture(video_path)
    suspicious_detections = {}
    frame_count = 0
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        frame_image = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
        frame_results = detect_image(frame_image)
        frame_count += 1
        for label, score in frame_results.items():
            if label in suspicious_detections:
                suspicious_detections[label] += 1
            else:
                suspicious_detections[label] = 1
    cap.release()
    return suspicious_detections

def scrape_dark_web(session, url, alert_preference, slang_dict, tor_password=None):
    
    high_risk_keywords = [
        "heroin", "methamphetamine", "cocaine", "ecstasy", "LSD", "fentanyl", "substances", "drug trade",
        "firearms", "guns for sale", "ammunition", "military-grade", "bomb making", "explosives",
        "child pornography", "CP", "child abuse", "underage", "illegal content", "child trafficking",
        "hacker for hire", "DDoS for hire", "malware", "ransomware", "exploit kit", "zero-day vulnerabilities",
        "credit card details", "identity theft", "phishing", "scams", "banking info", "carding",
        "hitman for hire", "contract killing", "assassination services",
        "drug trafficking", "money laundering", "black market", "smuggling", "cartel",
        "ISIS", "Al-Qaeda", "terrorist networks", "funding terrorism", "terrorist propaganda",
        "Darknet market", "Silk Road", "AlphaBay", "Dream Market", "ransomware-as-a-service", "DDoS-for-hire", "credential stuffing", "SIM swapping", 
        "data breach", "phishing kits", "stolen credit cards", "exploit broker", 
        "malware distribution", "human trafficking networks", "dark web hitman", 
        "child sexual exploitation", "illegal organ trade", "weapon smuggling", 
        "terrorist financing", "botnet services", "zero-day exploits", 
        "cryptojacking", "fake drug sales", "identity theft services"
    ]

    medium_risk_keywords = [
        "Tor network", "Tor browser", "VPN services", "I2P", "Freenet", "Tails OS", "Whonix", "proxy", 
        "anonymizer", "hidden services", "onion site",
        "Bitcoin", "Monero", "Zcash", "Litecoin", "Bitcoin mixer", "cryptocurrency tumbler", "CoinJoin", 
        "crypto wallet", "dark web coin", "stealth payments",
        "PGP encryption", "end-to-end encryption", "encrypted messages", "Signal app", "WhatsApp encryption", 
        "Jabber encryption", "encrypted email", "secure chat", "secure messaging", "cryptographic keys",
        "fake IDs", "ID forgery", "counterfeit documents", "passport forgery", "SSN generator", 
        "identity theft prevention", "stealth identity",
        "secure browsing", "privacy protection", "secure file storage", "privacy tools", "data encryption", 
        "encrypted storage", "data wiping", "file shredder", "deep web privacy",
        "dark web marketplace", "hidden marketplace", "hidden wiki", "DarkNet services", "onion services", 
        "untraceable transactions",
        "traffic obfuscation", "traffic masking", "IP cloaking", "data masking", "anonymized browsing",
        "privacy coins", "anonymity networks", "fake passports", "counterfeit currency", 
        "online gambling", "dark web forums", "hacking tutorials", "VPN services", 
        "cryptocurrency mixers", "social engineering", "fake reviews", 
        "online drug sales", "stolen databases", "deepfake technology", 
        "online fraud schemes", "phishing services", "fake IDs", 
        "data scraping services", "online auction fraud", "ad fraud"
    ]

    low_risk_keywords = [
    "secure browsing", "privacy protection", "VPN services", "encrypted messaging", "anonymous browsing",
    "privacy tools", "secure file storage", "data encryption", "private communication", "secure network",
    "web encryption", "data privacy", "file encryption", "encrypted cloud storage", "end-to-end security",
    "safe browsing", "secure online transactions", "strong passwords", "user anonymity", "data backup",
    "privacy-focused search engine", "Tor node", "encrypted voice call", "private VPN server", "anonymity tools",
    "encrypted backups", "digital security", "privacy solutions", "secure password management", "Tor network usage",
    "digital privacy", "data protection", "information security", "security features", "browser security",
    "digital identity protection", "internet privacy", "online anonymity", "personal data protection",
    "web security", "secure online services", "data confidentiality", "secure communication tools", "anonymity software","secure messaging apps", "data encryption tools", "privacy-focused browsers", 
    "digital privacy", "secure file sharing", "anonymizing proxies", 
    "cybersecurity awareness", "online privacy tools", "two-factor authentication", 
    "password managers", "secure cloud storage", "digital identity protection", 
    "data backup solutions", "internet safety tips", "secure online shopping", 
    "privacy policies", "data protection regulations", "cyber hygiene practices", 
    "secure coding practices", "incident response plans"
]

    try:
        response = retry_on_failure(session, url, retries=3, tor_password=tor_password)
        if not response:
            print(f"Access denied or site unreachable: {url}")
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            text_content = soup.get_text().lower()
            dangerous_phrases = detect_dangerous_phrases(text_content)
            if dangerous_phrases:
                print("Dangerous phrases detected:", dangerous_phrases,"\n","\n")
            else :
                print("No Dangerous phrases detected","\n","\n")
            encoded_strings = detect_encoded_strings(text_content)
            decoded_strings = []
            if encoded_strings:
                print(f"Encoded strings found: {encoded_strings}","\n")
                decoded_strings = decode_base64(encoded_strings)
                print(f"Decoded strings: {decoded_strings}","\n","\n")
            else:
                print("No Encoded strings found","\n","\n")
            
            if isinstance(decoded_strings, list):
                for decoded in decoded_strings:
                    text_content += f" {decoded}"
            else:
                print()
            text_content = detect_and_translate(text_content)
            detected_slang = detect_slang(text_content, slang_dict)
            if detected_slang:
                print("Detected slang terms:", detected_slang,"\n","\n")
            else:
                print("No Slang words Detected.","\n","\n")

            nlp_spacy = spacy.load("en_core_web_sm")
            doc = nlp_spacy(text_content)
            spacy_tokens = [token.text for token in doc]
            print("spaCy Tokens:", spacy_tokens, "\n","\n")

            nltk_tokens = word_tokenize(text_content)
            print("NLTK Tokens:", nltk_tokens, "\n","\n")

            unique_tokens = set(spacy_tokens)
            print("Unique spaCy Tokens:", unique_tokens, "\n","\n")

            nlp_model = pipeline('sentiment-analysis', model='distilbert-base-uncased-finetuned-sst-2-english')
            sentiment = nlp_model(text_content[:1024])  
            print(f"Sentiment Analysis Result: {sentiment}","\n","\n")

            alert_message = None
            for keyword in high_risk_keywords:
                if keyword in text_content:
                    alert_message = {
                        'url': url, 
                        'detected_activity': keyword , 
                        'severity': 'High'}
                   
            for keyword in medium_risk_keywords:
                if keyword in text_content:
                    alert_message = {
                        'url': url, 
                        'detected_activity': keyword , 
                        'severity': 'Medium'}

            for keyword in low_risk_keywords:
                if keyword in text_content:
                    alert_message = {
                        'url': url, 
                        'detected_activity': keyword , 
                        'severity': 'Low'}
                    
            images = soup.find_all('img')
            image_alerts = []
            for img in images:
                try:
                    img_url = img['src']
                    if not img_url.startswith('http'):
                        img_url = url + img_url
                    response = session.get(img_url)
                    content_type = response.headers.get('Content-Type')
                    if 'image' not in content_type:
                        print(f"Skipping non-image URL: {img_url} (Content-Type: {content_type})")
                        continue
                    image = Image.open(BytesIO(response.content))
                    print(f"Loaded image with format: {image.format}")
                    if image.mode in ['RGBA', 'LA', 'P']:  
                        image = image.convert("RGB")
                    image = image.resize((224, 224))  
                    transform = transforms.Compose([
                         transforms.Resize((224, 224)), 
                         transforms.ToTensor(),         
                         transforms.Normalize(mean=[0.5, 0.5, 0.5], std=[0.5, 0.5, 0.5])  
                         ])
                    image_tensor = transform(image).unsqueeze(0)  
                    print(f"Image tensor shape: {image_tensor.shape}")  
                except Exception as e:
                    print(f"Image detection error: {e}")
                    
            if alert_message:
                if alert_message['severity'].lower() in alert_preference or alert_preference == 'all':
                    return alert_message
            if image_alerts:
                alert_message['detected_activity'] += f" | Image results: {image_alerts}"
            else:
                alert_message['detected_activity'] += f"No suspicious activity detected in image."
            return alert_message
        else:
            return None
    except Exception as e:
        print(f"Error scraping {url}: {e}","\n")
        return None
    
def validate_links(links):
    pattern = re.compile(r'http[s]?://[a-zA-Z0-9]*\.onion')
    return {link for link in links if pattern.match(link)}

def search_tor_links(session, keyword):
    search_url = f"https://ahmia.fi/search/?q={keyword}"
    try:
        response = session.get(search_url, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        links = []
        for a_tag in soup.find_all("a", href=True):
            if "redirect_url" in a_tag["href"]:
                redirect_url = urlparse(a_tag["href"])
                query_params = parse_qs(redirect_url.query)
                if 'redirect_url' in query_params:
                    links.append(query_params['redirect_url'][0])  
            elif ".onion" in a_tag["href"]:
                links.append(a_tag["href"])
        return list(set(links))  

    except requests.exceptions.RequestException as e:
        print(f"Failed to search for links: {e}")
        return []

def scan_onion_link(link, keyword):
    try:
        response = requests.get(link, timeout=10)
        if keyword in response.text:
            print(f"Keyword '{keyword}' found on {link}")
        else:
            print(f"Keyword '{keyword}' not found on {link}")
    except Exception as e:
        print(f"Error scanning {link}: {e}")

def throttle_requests(delay=5):
    time.sleep(delay)

def get_user_consent():
    print("WARNING: Ensure you are authorized to conduct scans and adhere to ethical and legal standards.")
    consent = input("Do you agree to these terms? (yes/no): ").lower()
    if consent != 'yes':
        print("Exiting program.")
        exit()

def monitor_dark_web(session, recipient_email, tor_password, alert_preference, slang_dict, link):
    conn = connect_to_db()  
    create_table(conn)  
    try:
        print(f"Accessing {link}...")
        response = session.get(link, timeout=10)
        response.raise_for_status()  
        soup = BeautifulSoup(response.text, "html.parser")
        page_content = soup.get_text().lower()
        alert = scrape_dark_web(session, link, alert_preference, slang_dict, tor_password)
        
        if alert is None:
            print(f"No alert generated for {link}.")
            return  
        video_path = "/path/to/sample_video.mp4" 
        if os.path.exists(video_path):
            video_detections = detect_images_in_video(video_path)
            if video_detections:
                if not alert:
                    alert = {'url': link, 'detected_activity': '', 'severity': 'Medium'}
                alert['detected_activity'] += f" | Video results: {video_detections}"
            else:
                print("Image processing failed.")

        if alert:
            print(f"{alert['severity']} severity anomaly detected on {alert['url']} related to {alert['detected_activity']}")
            save_alert_to_db(conn, alert)
            send_alert_via_email(alert, recipient_email)
            export_db_to_txt('dark_web_alerts.db', 'dark_web_alerts.txt')
        else:
                print(f"No alert generated for {link}.")
    except requests.exceptions.RequestException as e:
            print(f"Failed to access {link}: {e}")
    except Exception as e:
            print(f"Error scraping {link}: {e}")
    finally:
            change_tor_identity(tor_password)
            time.sleep(5)
def main():
    get_user_consent()
    tor_password, recipient_email, alert_preference = get_user_input()
    valid_preferences = ['high', 'medium', 'low', 'all']
    if alert_preference not in valid_preferences:
        print(f"Invalid alert preference '{alert_preference}', defaulting to 'all'.")
        alert_preference = 'all'
    session = set_tor_proxy()
    try:
        test_tor_connection()
    except Exception as e:
        print(f"Failed to connect to Tor. Please check your Tor configuration. Error: {e}")
        return
    choice = input("Do you want to provide a link or a keyword to find links? (link/keyword): ").strip().lower()
    
    if choice == 'link':
        user_link = input("Please enter the .onion link you want to scrape: ").strip()
        monitor_dark_web(session, recipient_email, tor_password, alert_preference, slang_dict, user_link)
    
    elif choice == 'keyword':
        search_keyword = input("Enter the keyword to search on the dark web: ").strip()
        found_links = search_tor_links(session, search_keyword)

        if not found_links:
            print("No .onion links found for the given keyword.")
            return 
        print(f"Found {len(found_links)} links. Do you want to scan all links? (yes/no)")
        user_choice = input().strip().lower()

        if user_choice == 'yes':
            print("Scanning all links...")
            for link in found_links:
                monitor_dark_web(session, recipient_email, tor_password, alert_preference, slang_dict, link)
        elif user_choice == 'no':
            num_links_to_scan = int(input("How many popular links would you like to scan? "))
            if num_links_to_scan > len(found_links):
                print(f"You requested {num_links_to_scan} links, but only {len(found_links)} are available. Scanning all available links instead.")
                num_links_to_scan = len(found_links)

            selected_links = random.sample(found_links, num_links_to_scan)
            print(f"Scanning the following {num_links_to_scan} links:")
            for link in selected_links:
                monitor_dark_web(session, recipient_email, tor_password, alert_preference, slang_dict, link)
        else:
            print("Invalid choice. Exiting.")
            return

    else:
        print("Invalid choice. Please enter 'link' or 'keyword'.")



if __name__ == "__main__":
    main()
