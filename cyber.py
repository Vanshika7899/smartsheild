import serial
import json
import re
import msvcrt
import matplotlib.pyplot as plt
from collections import Counter
import numpy as np

PORT = "COM4"
BAUDRATE = 9600

# ------------------ member-2 ---------------------
block_id = ["scam@fraud.com", "hacker@unknown.com", "fakebank@phishmail.org","offers@scamdeal.net", "admin@untrustedmail.io", "lottery@cheatmail.com"]
block_domain = ["spam.net", "phishmail.org", "scamdeal.net", "untrustedmail.io","malicious.info", "fakenews.online", "tricklink.biz"]

sender_id = ["abc@gmail.com", "support@yahoo.com", "alerts@bankofindia.com","info@securemail.com", "notifications@yourservice.in", "help@officialsite.org"]
domain = ["gmail.com", "yahoo.com", "bankofindia.com", "officialsite.org","yourservice.in", "securemail.com"]
suspecious = ["urgent", "click here", "free", "password", "reset", "login","verify", "confirm", "urgently", "offer", "win", "limited time", "claim now", "exclusive", "act fast", "access blocked", "security alert"]
impo = ["bank", "otp", "transaction", "account", "balance", "invoice","payment", "debit", "credit", "security code", "billing", "transfer"]


spam_list = []
sms_log = [] 

def extract_fields(message):
    try:
        data = json.loads(message)
        return data.get("sender", ""), data.get("subject", ""), data.get("content", "")
    except:
        pass

    if message.count(",") >= 2:
        parts = [p.strip() for p in message.split(",", 2)]
        if len(parts) == 3:
            return parts[0], parts[1], parts[2]
        
    return "", "", message.strip()


def get_domain(sender):
    match = re.search(r"@([\w.-]+)", sender)
    return match.group(1) if match else ""

# ........member-1.............
def detect(sender, subject, content):
    reasons = []

    if sender not in sender_id:
        reasons.append("❌ Untrusted sender")

    matches = re.findall(r"@([\w.-]+)", sender)
    if not matches or matches[0] not in domain:
        reasons.append("⚠ Suspicious domain")

    for word in suspecious:
        if word in subject or word in content:
            reasons.append(f"⚠ Keyword detected: '{word}'")
            break

    return reasons

def priority(content):
    for word in impo:
        if word in content.lower():
            return True
    return False

# --------------------- member-3 ----------------------
try:
    with serial.Serial(PORT, BAUDRATE, timeout=1) as bt:
        print(f"✅ Listening on {PORT}...")
        messagebox = None
        message_log = None 

        while True:
            if bt.in_waiting:
                raw = bt.readline().decode("utf-8").strip()
                if raw:
                    sender, subject, content = extract_fields(raw)
                    subject = subject.lower()
                    content = content.lower()

                    
                    domain_check = get_domain(sender)
                    if sender in block_id or domain_check in block_domain:
                        print(f"\n⛔ message blocked successfully)")
                        continue

                    
                    if not sender or not subject:
                        if content and priority(content):
                            messagebox = ("<unknown>", "<important>", content)
                            message_log = "<unknown>"
                            sms_log.append(content)  
                            print("\n📩 [SMS] Important Message Received")
                            continue
                        else:
                            print(f"\n⚠ Incomplete message received")
                            print(f"   → {raw}")
                        continue

                    reasons = detect(sender, subject, content)

                    if reasons:
                        spam_list.append(reasons)
                        print(f"\n❌ Spam Alert ↓")
                        print(f"From: {sender}")
                        print(f"Subject: {subject}")
                        print(f"Content: {content}")
                        for r in reasons:
                            print("  *", r)

                        
                        is_suspicious_only = (
                            sender in sender_id and
                            get_domain(sender) in domain and
                            any("Keyword detected" in r for r in reasons)
                        )

                        if is_suspicious_only:
                            block_decision = input("\n⚠ Suspicious content found want to Block this sender? ").strip().lower()
                            if block_decision == "yes":
                                domain_extracted = get_domain(sender)
                                if sender not in block_id:
                                    block_id.append(sender)
                                    print(f"✅ Sender '{sender}' blocked.")
                                if domain_extracted and domain_extracted not in block_domain:
                                    block_domain.append(domain_extracted)
                                    print(f"✅ Domain '{domain_extracted}' blocked.")

                        messagebox = (sender, subject, content)
                        message_log = sender

                    else:
                        messagebox = (sender, subject, content)
                        message_log = None
                        print("\n📥 Inbox: New message received")

            if messagebox and bt.in_waiting == 0:
                if msvcrt.kbhit():
                    user_input = input().strip().lower()
                    if user_input == "ok":
                        s, subj, cont = messagebox
                        print(f"\n🗂 Inbox Message")
                        print(f"From: {s}")
                        print(f"Subject: {subj}")
                        print(f"Content: {cont}")

                    
                        if message_log and message_log not in sender_id:
                            block_decision = input("\n⚠ Do you want to block this sender?").strip().lower()
                            if block_decision == "yes":
                                domain_extracted = get_domain(message_log)
                                if message_log not in block_id:
                                    block_id.append(message_log)
                                    print(f"✅ Sender '{message_log}' blocked.")
                                if domain_extracted and domain_extracted not in block_domain:
                                    block_domain.append(domain_extracted)
                                    print(f"✅ Domain '{domain_extracted}' blocked.")

                        messagebox = None
                        message_log = None

except serial.SerialException:
    print("❌ Connection failed!")
except KeyboardInterrupt:
    print("\n🛑 Stopped by user.")

    # ......................member-4.......................
    if spam_list:
        threat_counter = {
            "Untrusted Sender": 0,
            "Suspicious Domain": 0,
            "Keyword Detected": 0
        }

        for reasons in spam_list:
            for r in reasons:
                if "Untrusted sender" in r:
                    threat_counter["Untrusted Sender"] += 1
                if "Suspicious domain" in r:
                    threat_counter["Suspicious Domain"] += 1
                if "Keyword detected" in r.lower():
                    threat_counter["Keyword Detected"] += 1

        labels = list(threat_counter.keys())
        values = list(threat_counter.values())
        y = np.arange(len(labels))

        plt.figure(figsize=(8, 5))
        bars = plt.barh(y, values, color=["red", "blue", "orange"])

        plt.xlabel("Number of Times Detected")
        plt.ylabel("Threat Type")
        plt.title("Threat Detection Summary")
        plt.yticks(y, labels)
        plt.grid(axis='x')

        for bar in bars:
            width = bar.get_width()
            plt.text(width + 0.3, bar.get_y() + bar.get_height()/2, str(int(width)), va='center')

        plt.tight_layout()
        plt.show()
    else:
        print("📭 No spam threats to show.")

    # 🧾 Optional: Print SMS Log
    # if sms_log:
    #     print("\n📋 Summary of Important SMS Messages:")
    #     for i, msg in enumerate(sms_log, 1):
    #         print(f"  {i}. {msg}")