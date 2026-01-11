import os
import re
import time
import datetime
from groq import Groq

# --- UTILITY: LOGGING ---
def log_violation(event_type, user_input):
    """
    Appends security violations to a log file with a timestamp.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] ALERT: {event_type} | Input: '{user_input}'\n"
    
    # Append to file
    with open("security_events.log", "a") as f:
        f.write(log_entry)

# --- LAYER 3: RATE LIMITING ---
class SimpleRateLimiter:
    def __init__(self):
        self.last_request_time = 0
        self.min_interval = 2.0  # Seconds required between requests

    def is_allowed(self):
        current_time = time.time()
        # Check if enough time has passed
        if current_time - self.last_request_time < self.min_interval:
            return False
        
        # Update the last request time
        self.last_request_time = current_time
        return True

# Initialize the limiter
limiter = SimpleRateLimiter()

# --- LAYER 1: THE BOUNCER (Input Sanitization) ---
def scan_input(user_text):
    """
    Checks for malicious keywords (Prompt Injection/Jailbreaking).
    Returns False if a threat is detected.
    """
    blocklist = [
        "ignore all instructions",
        "system prompt",
        "admin access",
        "delete logs",
        "brute force"
    ]
    
    normalized_text = user_text.lower()
    
    for phrase in blocklist:
        if phrase in normalized_text:
            print(f"🚨 SECURITY ALERT: Blocked phrase: '{phrase}'")
            log_violation("Malicious Input Blocked", user_text)
            return False
    return True

# --- LAYER 2: THE CENSOR (Output Filtering/DLP) ---
def scan_output(text):
    """
    Scans LLM output for sensitive PII (like Credit Card numbers).
    Redacts them if found.
    """
    # Regex pattern for Credit Card numbers (groups of 4 digits)
    cc_pattern = r"\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"
    
    if re.search(cc_pattern, text):
        print("\n🚨 ALERT: PII Detected! Redacting...")
        log_violation("PII Leak Prevented", "[REDACTED DATA]")
        return re.sub(cc_pattern, "[REDACTED]", text)
    
    return text

# --- MAIN APP ---
def main():
    # 1. Setup API Key
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("❌ Error: GROQ_API_KEY not found in environment variables.")
        return

    client = Groq(api_key=api_key)
    print("🤖 Secure Bot v1.0 is running. (Press Ctrl+C to quit)")

    # 2. Main Loop
    while True:
        try:
            user_prompt = input("\n💬 Enter prompt: ")
            
            # CHECK 1: Rate Limit
            if not limiter.is_allowed():
                print("⏳ Slow down! You are sending requests too fast.")
                continue

            # CHECK 2: Input Sanitization
            if scan_input(user_prompt):
                
                # 3. Call the API
                completion = client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": "You are a helpful assistant."},
                        {"role": "user", "content": user_prompt}
                    ],
                    model="llama-3.3-70b-versatile",
                )
                
                response = completion.choices[0].message.content
                
                # CHECK 3: Output Filtering
                safe_response = scan_output(response)
                print("\n🤖 Response:", safe_response)
        
        except KeyboardInterrupt:
            print("\n\n👋 Exiting Secure Bot...")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
