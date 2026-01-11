import os
import re
import time
import datetime
from groq import Groq

# --- UTILITY: LOGGING ---
def log_violation(event_type, user_input):
    # Get current timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create the log entry
    log_entry = f"[{timestamp}] ALERT: {event_type} | Input: '{user_input}'\n"
    
    # Append to file
    with open("security_events.log", "a") as f:
        f.write(log_entry)

# --- LAYER 3: RATE LIMITING ---
class SimpleRateLimiter:
    def __init__(self):
        self.last_request_time = 0
        self.min_interval = 2.0

    def is_allowed(self):
        current_time = time.time()
        if current_time - self.last_request_time < self.min_interval:
            return False
        self.last_request_time = current_time
        return True

limiter = SimpleRateLimiter()

# --- LAYER 1: THE BOUNCER ---
def scan_input(user_text):
    blocklist = ["ignore all instructions", "system prompt", "admin access", "delete logs"]
    for phrase in blocklist:
        if phrase in user_text.lower():
            print(f"🚨 SECURITY ALERT: Blocked phrase: '{phrase}'")
            # LOG IT!
            log_violation("Malicious Input Blocked", user_text)
            return False
    return True

# --- LAYER 2: THE CENSOR ---
def scan_output(text):
    cc_pattern = r"\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"
    if re.search(cc_pattern, text):
        print("\n🚨 ALERT: PII Detected! Redacting...")
        # LOG IT! (We log that it happened, but NOT the actual CC number)
        log_violation("PII Leak Prevented", "[REDACTED DATA]")
        return re.sub(cc_pattern, "[REDACTED]", text)
    return text

# --- MAIN APP ---
api_key = os.environ.get("GROQ_API_KEY")
client = Groq(api_key=api_key)

print("🤖 Secure Bot v1.0 is running. (Press Ctrl+C to quit)")

while True:
    try:
        user_prompt = input("\n💬 Enter prompt: ")
        
        # 1. Check Rate Limit
        if not limiter.is_allowed():
            print("⏳ Slow down!")
            continue

        # 2. Check Input
        if scan_input(user_prompt):
            completion = client.chat.completions.create(
                messages=[{"role": "user", "content": user_prompt}],
                model="llama-3.3-70b-versatile",
            )
            response = completion.choices[0].message.content
            
            # 3. Check Output
            print("\n🤖 Response:", scan_output(response))
    
    except KeyboardInterrupt:
        print("\n\n👋 Exiting Secure Bot...")
        break
    except Exception as e:
        print(f"❌ Error: {e}")
