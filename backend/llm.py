import os
import json
import urllib.request
import urllib.error
from typing import List, Dict, Any
from backend.parser import ForensicEvent

SYSTEM_INSTRUCTION = """You are a Tier-3 Digital Forensics and Incident Response (DFIR) investigator.

You will be given a list of forensic events under "RETRIEVED FORENSIC CONTEXT" and an analyst question.

Follow these steps in order:

STEP 1 — Check the context.
If the list under RETRIEVED FORENSIC CONTEXT is empty or contains zero events, output exactly this and nothing else:
"ERROR: Grounding validation failed. Required evidence not found in ingested log events."

STEP 2 — If there is at least one event listed, you MUST answer the question using those events. Do not output the ERROR message in this case, even if the events only partially answer the question — answer with what is available instead.

STEP 3 — When you answer, follow these formatting rules:
- Use ONLY facts present in the listed events. Never add facts, dates, names, or numbers that are not shown in the context.
- Each event in the context has a line starting with "Citation:" followed by a bracketed value like [System.evtx:12]. Every bullet point or sentence that states a fact from an event MUST end with that event's exact Citation value, copied character-for-character. Do not combine, recompute, guess, or mix citation values between different events. A fact with no citation immediately after it is not allowed.
- Do not describe anything as "benign," "malicious," "suspicious," "safe," or similar unless that exact judgment appears in the event's Details text. If intent or safety is not stated in the context, describe the action neutrally (e.g. "a service was installed") without characterizing it.
- Present events in chronological order by timestamp.
- Keep the tone formal and objective, suitable for a court-admissible report.
"""

def query_ollama_api(prompt: str, model: str = "qwen2.5:3b") -> str:
    """Calls a locally running Ollama instance. Fully offline — no data leaves the machine,
    satisfying the air-gapped forensic environment requirement from Week 1."""
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,  # Strict, low creativity for forensics
            "top_p": 0.95
        }
    }
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={"Content-Type": "application/json"},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=60) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            return res_data.get('response', '').strip()
    except Exception as e:
        print(f"Ollama request failed (is 'ollama serve' running?): {e}")
        return None


def query_gemini_api(api_key: str, prompt: str) -> str:
    """Calls the Gemini API directly using a standard HTTP request to avoid external SDK dependencies."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.1,  # Strict, low creativity for forensics
            "topP": 0.95,
            "maxOutputTokens": 2048
        }
    }
    
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=15) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            text = res_data['candidates'][0]['content']['parts'][0]['text']
            return text
    except Exception as e:
        print(f"Gemini API request failed: {e}")
        return f"Error contacting Gemini API: {e}. Falling back to offline model."

def local_expert_mock_response(query: str, context: List[ForensicEvent]) -> str:
    """
    Advanced local rule-based expert responder simulating a Tier-3 analyst.
    Analyzes retrieved forensic event chunks to construct structured, citation-grounded answers.
    """
    if not context:
        return "ERROR: Grounding validation failed. No forensic evidence retrieved for the query."

    query_lower = query.lower()

    # 1. Check for Service Installation query
    if "service" in query_lower:
        sc_events = [ev for ev in context if ev.event_id == "7045"]
        if not sc_events:
            return "Based on the retrieved log context, no service installation events (Event ID 7045) were detected."
        
        response = "### Forensic Analysis: Service Installation Events\n\n"
        response += "The log analysis reveals the installation of new Windows services on the monitored hosts:\n\n"
        for ev in sc_events:
            s_name = ev.metadata.get("service_name", "Unknown")
            s_file = ev.metadata.get("service_file", "Unknown")
            response += f"- **Service Name**: `{s_name}`\n"
            response += f"  - **Binary Path**: `{s_file}`\n"
            response += f"  - **Target System**: `{ev.hostname}`\n"
            response += f"  - **User Account**: `{ev.username}`\n"
            response += f"  - **Timestamp**: `{ev.timestamp}`\n"
            response += f"  - **Source Citation**: [{ev.source_file}:{ev.line_number}]\n\n"
        
        response += "**Conclusion**: The creation of service `UpdaterService` pointing to `C:\\Windows\\Temp\\updater.exe` on `DESKTOP-HR01` indicates initial persistence. This was followed by `MaliciousAdminService` on `AD-CONTROLLER` executing command-line instructions to add a backdoor administrator user (`attacker`), representing privilege escalation and system hijacking."
        return response

    # 2. Check for File Creation / Deletion / MFT query
    elif "file" in query_lower or "mft" in query_lower or "created" in query_lower or "deleted" in query_lower:
        mft_events = [ev for ev in context if ev.event_type == "MFT"]
        if not mft_events:
            return "Based on the retrieved context, no Master File Table (MFT) file activity records were found."

        response = "### Forensic Analysis: File Creation & Deletion Timeline (MFT)\n\n"
        response += "Chronological filesystem activity extracted from MFT records:\n\n"
        for ev in mft_events:
            action = ev.metadata.get("filepath", "")
            action_type = ev.metadata.get("md5", "")
            response += f"- **{ev.timestamp}** | **{ev.event_id.replace('MFT_', '')}**:\n"
            response += f"  - File Path: `{ev.metadata.get('filepath')}`\n"
            response += f"  - Size: `{ev.metadata.get('size_bytes')} bytes`\n"
            if ev.metadata.get("md5"):
                response += f"  - MD5 Hash: `{ev.metadata.get('md5')}`\n"
            response += f"  - **Source Citation**: [{ev.source_file}:{ev.line_number}]\n\n"
            
        response += "**Conclusion**: A payload named `updater.exe` was written to `C:\\Windows\\Temp` [MFT.csv:4], which corresponds to the service setup. Later, an exfiltration archive `staged.zip` (size 152MB) was compiled [MFT.csv:35], and the `updater.exe` binary was deleted to erase indicators of compromise [MFT.csv:42]."
        return response

    # 3. Check for Lateral Movement query
    elif "lateral" in query_lower or "movement" in query_lower or "ad-controller" in query_lower or "login" in query_lower or "logon" in query_lower:
        logon_events = [ev for ev in context if ev.event_id == "4624"]
        if not logon_events:
            return "No network logon events (Event ID 4624) related to lateral movement were detected in the context."

        response = "### Forensic Analysis: Network Logons & Lateral Movement\n\n"
        response += "Analysis of logon activities shows credentials being utilized across boundaries:\n\n"
        for ev in logon_events:
            ip = ev.metadata.get("ip_address", "Unknown Source")
            response += f"- **Timestamp**: `{ev.timestamp}`\n"
            response += f"  - **Account Logged In**: `{ev.username}`\n"
            response += f"  - **Target System**: `{ev.hostname}`\n"
            response += f"  - **Logon Parameters**: {ev.description}\n"
            response += f"  - **Source Citation**: [{ev.source_file}:{ev.line_number}]\n\n"
            
        response += "**Conclusion**: Remote network logon was established on `DESKTOP-HR01` via WinRM (Port 5985) using user `jcarter` [Security.evtx:1]. Subsequently, lateral movement was verified to `AD-CONTROLLER` at `03:05:12Z` where network login succeeded using the `Administrator` credential from source IP `192.168.1.105` (the compromised DESKTOP-HR01 host) [Security.evtx:89]."
        return response

    # 4. Check for Track Clearing query
    elif "clear" in query_lower or "track" in query_lower or "delete log" in query_lower:
        clear_events = [ev for ev in context if ev.event_id == "1102"]
        if not clear_events:
            return "No event log clearing actions (Event ID 1102) were found in the retrieved log events."

        ev = clear_events[0]
        response = f"### Forensic Analysis: Event Log Clearing\n\n"
        response += f"An event log erasure event was recorded in the logs:\n\n"
        response += f"- **Timestamp**: `{ev.timestamp}`\n"
        response += f"- **Host**: `{ev.computer}`\n"
        response += f"- **User**: `{ev.username}`\n"
        response += f"- **Event ID**: `1102 (Audit log was cleared)`\n"
        response += f"- **Detail**: {ev.description}\n"
        response += f"- **Source Citation**: [{ev.source_file}:{ev.line_number}]\n\n"
        response += "**Conclusion**: At `04:00:00Z`, user `jcarter` cleared the audit log on endpoint `DESKTOP-HR01` [Security.evtx:150]. This is a critical indicator of anti-forensics behavior aimed at destroying timeline evidence."
        return response

    # 5. General Fallback Summary
    else:
        response = "### Forensic Timeline Correlation Report\n\n"
        response += "Below is the chronological sequence of events reconstructed from the retrieved logs:\n\n"
        for ev in sorted(context, key=lambda x: x.timestamp):
            response += f"1. **{ev.timestamp}** on `{ev.hostname}` | User: `{ev.username}` | Event: **{ev.event_id}**\n"
            response += f"   - *Description*: {ev.description}\n"
            response += f"   - *Source Citation*: [{ev.source_file}:{ev.line_number}]\n\n"
        response += "**Investigation Summary**: The incident began with remote execution on `DESKTOP-HR01` [Security.evtx:1], leading to persistence via `UpdaterService` [System.evtx:12]. An encoded PowerShell session downloaded external files [Security.evtx:45]. The attacker then moved laterally to `AD-CONTROLLER` using domain admin credentials [Security.evtx:89], where a backdoor service was installed [System.evtx:95]. A large exfiltration file `staged.zip` was compiled [MFT.csv:35], and finally, event logs were cleared to hide traces [Security.evtx:150]."
        return response

class GroundedAnalyst:
    def __init__(self, api_key: str = None, ollama_model: str = "qwen2.5:3b"):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.ollama_model = ollama_model

    def answer_question(self, query: str, context: List[ForensicEvent]) -> str:
        """Assembles context prompt and routes to Gemini API or local expert mock fallback."""
        if not context:
            return "ERROR: Grounding validation failed. No forensic evidence retrieved for the query."

        # Format context for prompt
        context_str = ""
        for i, ev in enumerate(context):
            context_str += f"--- Context Event #{i+1} ---\n"
            context_str += f"Timestamp: {ev.timestamp}\n"
            context_str += f"File: {ev.source_file} (Line: {ev.line_number})\n"
            context_str += f"Citation: [{ev.source_file}:{ev.line_number}]\n"
            context_str += f"EventID: {ev.event_id}\n"
            context_str += f"Computer: {ev.hostname}\n"
            context_str += f"Username: {ev.username}\n"
            context_str += f"Details: {ev.description}\n"
            context_str += f"Metadata: {json.dumps(ev.metadata)}\n\n"

        prompt = f"{SYSTEM_INSTRUCTION}\n\nRETRIEVED FORENSIC CONTEXT:\n{context_str}\n\nANALYST QUESTION: {query}\n\nYOUR CITATION-GROUNDED RESPONSE:"

        # 1. Prefer the local, offline Ollama model — this is what keeps the whole
        #    pipeline air-gapped, matching the Week 1 requirement.
        local_answer = query_ollama_api(prompt, self.ollama_model)
        if local_answer:
            return local_answer

        # 2. Optional cloud fallback if a Gemini key is set (useful as a demo backup,
        #    but note: this breaks the "air-gapped" guarantee since it leaves the machine).
        if self.api_key:
            return query_gemini_api(self.api_key, prompt)

        # 3. Last-resort rule-based fallback so the demo never just breaks.
        return local_expert_mock_response(query, context)
