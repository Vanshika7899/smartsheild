# smartsheild
real time threat detection and prevention over bluetooth
# SmartShield
Real-Time Threat Detection And Prevention Over Bluetooth
# 🔐 Bluetooth-Based Spam & Threat Detection System

This project simulates a *smartwatch or mobile device* sending messages via Bluetooth to a central system (like a laptop). The system receives these messages and detects potential *spam, phishing, or sensitive threats* in real time using predefined rule sets.

---

## 📌 Features

- Real-time Bluetooth message reception via COM port
- Detects threats using:
  - ❌ Untrusted sender ID
  - ⚠ Suspicious email domain
  - ⚠ Suspicious/phishing keywords
- Recognizes important messages (e.g., OTP, transaction alerts)
- Auto-blocks known spam sources (sender/domain)
- Prompts user to block new suspicious senders
- Visual bar chart summarizing threats detected
- Logs high-priority content for SMS-style alerts

---

## 🧠 Message Format

The system supports two formats:
- *JSON format*
  json
  {
    "sender": "abc@gmail.com",
    "subject": "Security Alert",
    "content": "Click here to reset your password"
  }
  
- *Comma-separated format*
  
  abc@gmail.com, Security Alert, Click here to reset your password
  

---

## 🛠 Technologies Used

- *Python 3*
- pyserial — for reading Bluetooth COM port
- re — regular expressions for domain/sender validation
- msvcrt — detects user keystrokes in Windows terminal
- matplotlib — visualizes threat summary in a bar chart
- json — parses message data

---

## 🚦 How to Run

1. *Install required packages:*
   bash
   pip install pyserial matplotlib
   

2. *Connect your device (or emulator) sending Bluetooth messages.*

3. *Update COM port in the script if needed:*
   python
   PORT = "COM4"  # Change to your actual COM port
   

4. *Run the Python script:*
   bash
   python detect_threats.py
   

5. *Send messages from another device or simulator.*

6. *Stop the script anytime using* Ctrl + C — the system will generate a bar graph summary of detected threats.

---

## 📊 Graph Output

- Displays how many times each of the following threats were detected:
  - Untrusted Senders
  - Suspicious Domains
  - Suspicious Keywords
- Bar chart is shown when the script ends via keyboard interrupt.

---

## 🧾 Sample Output


✅ Listening on COM4...

❌ Spam Alert ↓
From: hacker@unknown.com
Subject: Free Gift!
Content: Click here to win now.
  * ❌ Untrusted sender
  * ⚠ Suspicious domain
  * ⚠ Keyword detected: 'click here'

📩 [SMS] Important Message Received
   → , ,Your OTP for transaction is 349274


## 📦 Future Scope

- Add a web-based dashboard for message display
- Store messages and threats in a database (e.g., SQLite or Firebase)
- Add internet-based message ingestion (HTTP instead of Bluetooth)
- Build an Android app version for real deployment

---
