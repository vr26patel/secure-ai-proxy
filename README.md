📖 Overview
As AI adoption grows, so do the risks. This project demonstrates a "Security-First" architecture for LLM applications. Instead of connecting users directly to an AI model, this application acts as a secure proxy, enforcing Input Validation, Data Loss Prevention (DLP), and Traffic Throttling before requests are processed.

Tech Stack: Python, Groq API (Llama 3), Regex, Logging modules.

🔐 Key Security Features (The CIA Triad)
1. 🛡️ Input Sanitization (The Bouncer)
Defense Against: Prompt Injection, Jailbreaking.

Mechanism: Scans user input against a strict blocklist of known attack vectors (e.g., "Ignore instructions", "System prompt") before the API call is made.

2. 🕵️ Output Filtering (The Censor)
Defense Against: Sensitive Data Exposure (PII Leakage).

Mechanism: Uses Regex pattern matching to detect and redact sensitive information (like Credit Card numbers) from the AI's response before it reaches the user.

3. ⏱️ Rate Limiting (The Turnstile)
Defense Against: Denial of Service (DoS), Resource Exhaustion.

Mechanism: Implements a token-bucket style throttle that forces a cool-down period between requests to prevent API abuse.

4. 📝 Forensic Logging (The Black Box)
Defense Against: Non-Repudiation.

Mechanism: automatically records all security violations (blocked attacks, PII leaks) to a timestamped security_events.log file for incident response.

⚙️ How It Works
User Input → Rate Limiter Check (Pass/Fail)

Input Sanitization → Scans for malicious keywords.

API Call → Securely transmits sanitized prompt to Groq (Llama 3).

Output Analysis → Scans response for PII patterns.

Redaction → Masks sensitive data.

Final Output → Safe response delivered to user.
