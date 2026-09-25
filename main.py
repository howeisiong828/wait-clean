import os
import json
import base64
import re
import time
import cv2
import numpy as np
from typing import Optional

import httpx
from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="STOP! CHECK! WAIT! Scam Checker")
rate_limit_store = {}
RATE_LIMIT = 20
RATE_WINDOW = 3600
def check_rate_limit(client_id: str):
    now = time.time() 
    requests = rate_limit_store.get(client_id, [])        
    requests = [t for t in requests if now - t < RATE_WINDOW]
    if len(requests) >= RATE_LIMIT:
        return False

    requests.append(now)
    rate_limit_store[client_id] = requests
    return True
def get_client_id(request: Request):
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.client.host if request.client else "unknown"      
def decode_qr_from_image(image_bytes: bytes):
    try:
        image_array = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)

        if image is None:
            return None

        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(image)

        if data and points is not None:
            return data.strip()

        return None

    except Exception:
        return None

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
WEB_RISK_API_KEY = os.getenv("WEB_RISK_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")


SYSTEM_PROMPT = """
You are the safety analysis engine for STOP! CHECK! WAIT!, an independent
Singapore-built scam checking service for people worldwide.

Your job is to assess scam RISK, not to make absolute accusations.

Analyse the meaning, context and social-engineering strategy of the content,
not merely keywords.

You must work with multilingual content. Analyse the original language and
meaning directly whenever possible.

Look for signals including:
- unexpected or unsolicited contact
- claimed family member, friend, colleague or changed phone number
- impersonation of banks, police, government, companies or authorities
- attempts to establish trust before asking for money
- urgency, threats, fear or pressure
- requests for secrecy
- OTP, PIN, password, banking or identity information
- suspicious links, domains or QR codes
- payment, PayNow, bank transfer, gift card or cryptocurrency requests
- investment or guaranteed-return claims
- job/task scams
- parcel/delivery scams
- romance or emotional manipulation
- marketplace scams
- tech-support or remote-access requests
- account suspension or verification threats
- advance-fee scams
- suspicious visual branding or inconsistencies when analysing screenshots
- conversation-stage context: scams may begin innocently before money is asked for

IMPORTANT:
A message can be suspicious even when it contains no link, payment request,
OTP request or explicit threat.

For example, an unknown number claiming to be a relative or friend may be the
opening stage of an impersonation scam. Explain that possibility while also
acknowledging that the contact could be genuine.

Never say something is "safe" simply because obvious scam indicators are absent.

Return ONLY valid JSON using this exact structure:

{
  "risk": "LOW" | "CAUTION" | "HIGH",
  "summary": "short plain-language assessment",
  "signals": [
    "specific reason based on the submitted content"
  ],
  "uncertainty": "what cannot be verified from the submitted content",
  "actions": [
    "practical next step appropriate to the actual risk; for LOW risk with no meaningful scam indicators, avoid unnecessary warnings or verification steps"
  ],
  "language": "detected language"
}

URL calibration:
For links, an unfamiliar domain, a domain without a recognisable brand name, a common TLD such as .com, or inability to verify the destination from the URL alone are NOT scam indicators by themselves. Do not assign CAUTION solely for these reasons. If the URL has no concrete suspicious indicators, classify it LOW while stating that authenticity has not been verified. Raise risk only for concrete signals such as deceptive lookalike domains, impersonation, misleading subdomains, punycode/homograph tricks, suspicious credential/payment paths, or other clear phishing patterns.

Risk guidance:

LOW:
No meaningful scam indicators found. Use LOW risk. Do not invent hypothetical scam scenarios or recommend identity verification unless the submitted content contains a concrete reason for concern. For ordinary benign messages, state plainly that no obvious warning signs were detected.

CAUTION:
There are suspicious or unverifiable signals that justify independent checking.

HIGH:
There are strong scam indicators such as credential theft, money requests,
malicious-looking links, impersonation plus pressure, guaranteed investment
returns, remote-access requests, or similar high-risk behaviour.

Use calm language. Do not shame or frighten the user.
Do not fabricate facts, identities, organisations, reporting numbers or websites.
"""


class TextRequest(BaseModel):
    text: str
    mode: str = "message"


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "ai_configured": bool(OPENAI_API_KEY)
    }


def extract_json(text: str):
    text = text.strip()

    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text).strip()
        text = re.sub(r"```$", "", text).strip()

    try:
        return json.loads(text)
    except Exception:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise ValueError("AI response was not valid JSON")


async def check_web_risk(url: str):
    endpoint = f"https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&uri={url}&key={WEB_RISK_API_KEY}"

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(endpoint)
       

        if response.status_code != 200:
             return None

        data = response.json()
        return data.get("threat")
async def call_openai(user_content):
    if not OPENAI_API_KEY:
        raise RuntimeError("AI analysis is not configured.")

    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT
            },
            {
                "role": "user",
                "content": user_content
            }
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"}
    }

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json"
            },
            json=payload
        )

    if response.status_code >= 400:
        raise RuntimeError(
            f"AI service returned error {response.status_code}"
        )

    data = response.json()
    content = data["choices"][0]["message"]["content"]

    return extract_json(content)


def normalise_result(result):
    risk = str(result.get("risk", "CAUTION")).upper()

    if risk not in {"LOW", "CAUTION", "HIGH"}:
        risk = "CAUTION"

    signals = result.get("signals", [])
    actions = result.get("actions", [])

    if not isinstance(signals, list):
        signals = [str(signals)]

    if not isinstance(actions, list):
        actions = [str(actions)]

    if not actions:
        actions = [
            "Do not send money, passwords, PINs or OTP codes.",
            "Verify the sender independently using contact details you already trust."
        ]

    return {
        "risk": risk,
        "summary": str(
            result.get(
                "summary",
                "We could not confidently classify this content."
            )
        ),
        "signals": [str(x) for x in signals][:8],
        "uncertainty": str(
            result.get(
                "uncertainty",
                "The sender's identity and intent cannot be independently verified."
            )
        ),
        "actions": [str(x) for x in actions][:8],
        "language": str(result.get("language", "Unknown"))
    }


@app.post("/analyze")
async def analyze(req: TextRequest, request: Request):
    client_id = get_client_id(request)       
    if not check_rate_limit(client_id):
        return {"error": "Too many checks. Please try again later."}
    text = req.text.strip()

    if not text:
        return {"error": "Please enter something to check."}
    if len(text) > 10000:
        return {"error": "Message is too long. Please keep it under 10,000 characters."}
    mode = req.mode if req.mode in {"message", "link"} else "message"

    web_risk_result = None
    if mode == "link" and WEB_RISK_API_KEY:
        web_risk_result = await check_web_risk(text)
  
    if mode == "link":
        instruction = f"""
Analyse this URL or link for scam/phishing risk.

Do not visit or claim to have verified the destination.
Assess the URL structure, wording, impersonation signals and context that can
reasonably be inferred from the submitted link.
Important: An unfamiliar or unrecognised domain is NOT suspicious by itself.
A domain not containing a recognisable brand or company name is NOT suspicious by itself.
A common top-level domain such as .com is NOT suspicious by itself.
Inability to verify a website from the URL alone is uncertainty, NOT evidence of a scam.
Do not raise the risk level solely because the domain is unfamiliar, generic, or unverifiable.
Look for concrete indicators such as deceptive lookalike domains, brand impersonation, misleading subdomains, punycode or homograph tricks, suspicious credential or payment paths, or other clear phishing patterns.
If no meaningful suspicious indicator is present in the URL itself, use LOW while clearly stating that authenticity has not been verified.

Submitted link:
{text}
"""
    else:
        instruction = f"""
Analyse this message for scam and social-engineering risk.

Pay attention to the stage of the conversation. An apparently friendly opening
from an unknown person can still be an impersonation setup. Do not raise the risk level merely because a message is unsolicited or its sender cannot be independently verified. If there is no suspicious link, payment request, request for credentials or OTP, impersonation inconsistency, threat, unusual urgency, or other concrete scam indicator, use LOW risk and clearly state that authenticity cannot be confirmed from the message alone.

Submitted message:
{text}
"""

    try:
        result = await call_openai(instruction)
        if web_risk_result:
          result["risk"] = "HIGH"
        return normalise_result(result)

    except Exception as exc:
        return {
            "error": "We could not complete the AI analysis."
          
        }


@app.post("/analyze-image")
async def analyze_image(
    file: UploadFile = File(...),
    context: Optional[str] = Form(None),
request: Request = None,
):
    client_id = get_client_id(request)
    if not check_rate_limit(client_id):
        return {"error": "Too many checks. Please try again later."}

    if not OPENAI_API_KEY:
        return {"error": "AI analysis is not configured."}
      
    allowed = {
        "image/jpeg",
        "image/png",
        "image/webp"
    }

    if file.content_type not in allowed:
        return {
            "error": "Please upload a JPG, PNG or WEBP screenshot."
        }

    image_bytes = await file.read()

    if len(image_bytes) > 8 * 1024 * 1024:
        return {
            "error": "Screenshot is too large. Please use an image under 8 MB."
        }

    qr_data = decode_qr_from_image(image_bytes)
    
    encoded = base64.b64encode(image_bytes).decode("utf-8")
    mime = file.content_type

    user_content = [
        {
            "type": "text",
            "text": """
Analyse this screenshot for scam and social-engineering risk.

Read the visible text and also examine visual context such as claimed branding,
sender identity, URLs, QR/payment requests, urgency, impersonation cues and
inconsistencies.

Do not assume a logo or professional-looking design proves authenticity.
Do not declare the content safe merely because no payment request has appeared yet.
"""
        },
        {
            "type": "image_url",
            "image_url": {
                "url": f"data:{mime};base64,{encoded}"
            }
        }
    ]
    if qr_data:
        user_content.insert(
            1,
            {
                "type": "text",
                "text": f"QR code decoded from the uploaded image: {qr_data}\nAnalyse this decoded content for scam risk. Do not open, visit, execute, or navigate to it."
            }
        )
    if context:
        user_content.insert(
            1,
            {
                "type": "text",
                "text": f"Optional user context: {context[:1000]}"
            }
        )

    try:
        result = await call_openai(user_content)
        return normalise_result(result)

    except Exception as exc:
        return {
            "error": "We could not analyse this screenshot."
        
        }


@app.get("/", response_class=HTMLResponse)
def home():
    return r"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">
<meta name="viewport"
content="width=device-width, initial-scale=1, viewport-fit=cover">

<meta name="theme-color" content="#123c7a">

<title>STOP! CHECK! WAIT! — Scam Checker</title>

<style>

:root {
    --blue: #123c7a;
    --blue2: #1855a0;
    --light: #eef5ff;
    --border: #d9e5f5;
    --text: #132238;
    --muted: #66758a;
    --white: #ffffff;
    --red: #c62828;
    --amber: #a96500;
    --green: #16734a;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #ffffff;
    color: var(--text);
    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Arial,
        sans-serif;
}

.shell {
    width: min(620px, 92%);
    margin: 0 auto;
    padding: 38px 0 45px;
}

.brand {
    text-align: center;
    margin-bottom: 34px;
}

.shield {
    width: 58px;
    height: 58px;
    margin: 0 auto 14px;
    border-radius: 18px;
    background: var(--blue);
    color: white;
    display: grid;
    place-items: center;
    font-size: 29px;
    font-weight: 900;
}

.brand h1 {
    margin: 0;
    color: var(--blue);
    font-size: clamp(30px, 8vw, 44px);
    line-height: 1;
    letter-spacing: -1.5px;
    font-weight: 900;
}

.scam-checker {
    margin-top: 10px;
    color: var(--blue2);
    font-weight: 800;
    letter-spacing: 1.8px;
    font-size: 13px;
    text-transform: uppercase;
}

.tagline {
    margin: 14px auto 0;
    color: var(--muted);
    font-size: 16px;
    line-height: 1.5;
}

.actions {
    display: grid;
    gap: 14px;
}

.action {
    width: 100%;
    border: 0;
    text-align: left;
    background: var(--blue);
    color: white;
    padding: 21px 20px;
    border-radius: 18px;
    cursor: pointer;
    display: flex;
    gap: 17px;
    align-items: center;
    box-shadow: 0 7px 18px rgba(18,60,122,.12);
}

.action:active {
    transform: scale(.99);
}

.icon {
    min-width: 48px;
    height: 48px;
    border-radius: 14px;
    background: rgba(255,255,255,.13);
    display: grid;
    place-items: center;
    font-size: 24px;
}

.action strong {
    display: block;
    font-size: 18px;
    margin-bottom: 4px;
}

.action span {
    display: block;
    color: rgba(255,255,255,.82);
    line-height: 1.35;
    font-size: 14px;
}

.panel {
    display: none;
    margin-top: 20px;
    padding: 21px;
    border: 1px solid var(--border);
    border-radius: 18px;
    background: #fff;
    box-shadow: 0 8px 24px rgba(18,60,122,.07);
}

.panel.active {
    display: block;
}

.panel h2 {
    margin: 0 0 8px;
    color: var(--blue);
    font-size: 21px;
}

.helper {
    margin: 0 0 15px;
    color: var(--muted);
    font-size: 14px;
    line-height: 1.45;
}

textarea,
input[type="url"],
input[type="text"], select {
    width: 100%;
    border: 1px solid #bdcde2;
    background: white;
    color: var(--text);
    padding: 15px;
    border-radius: 13px;
    font-size: 16px;
    outline: none;
}

textarea {
    min-height: 150px;
    resize: vertical;
}

textarea:focus,
input:focus {
    border-color: var(--blue2);
    box-shadow: 0 0 0 3px rgba(24,85,160,.10);
}

.primary {
    width: 100%;
    margin-top: 13px;
    border: 0;
    background: var(--blue2);
    color: white;
    padding: 15px;
    border-radius: 13px;
    font-weight: 800;
    font-size: 16px;
    cursor: pointer;
}

.primary:disabled {
    opacity: .55;
}

.upload {
    border: 2px dashed #aac0dc;
    background: var(--light);
    padding: 25px 15px;
    text-align: center;
    border-radius: 15px;
}

.upload input {
    margin-top: 13px;
    max-width: 100%;
}

.preview {
    display: none;
    width: 100%;
    max-height: 330px;
    object-fit: contain;
    margin-top: 15px;
    border-radius: 12px;
    border: 1px solid var(--border);
}

.result {
    display: block;
    margin-top: 20px;
    border-radius: 18px;
    padding: 22px;
    background: #f8fbff;
    border: 1px solid var(--border);
}

.risk {
    display: inline-block;
    font-size: 14px;
    font-weight: 900;
    letter-spacing: 1px;
    padding: 7px 11px;
    border-radius: 999px;
    margin-bottom: 13px;
}

.risk.HIGH {
    background: #ffebee;
    color: var(--red);
}

.risk.CAUTION {
    background: #fff4dc;
    color: var(--amber);
}

.risk.LOW {
    background: #e7f7ef;
    color: var(--green);
}

.summary {
    font-size: 18px;
    line-height: 1.45;
    font-weight: 700;
}

.result h3 {
    color: var(--blue);
    margin: 22px 0 8px;
    font-size: 16px;
}

.result ul {
    padding-left: 21px;
    margin: 7px 0;
}

.result li {
    margin: 8px 0;
    line-height: 1.45;
}

.uncertainty {
    color: var(--muted);
    line-height: 1.5;
}

.community-actions {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-top: 17px;
}

.history-btn,
.community-btn {
    width: 100%;
    padding: 14px;
    border-radius: 13px;
    border: 1px solid var(--border);
    background: white;
    color: var(--blue);
    font-weight: 800;
    cursor: pointer;
}

.history-btn {
    margin-top: 17px;
}

.history {
    display: none;
    margin-top: 15px;
    border: 1px solid var(--border);
    border-radius: 16px;
    overflow: hidden;
}

.history-item {
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
}

.history-item:last-child {
    border-bottom: 0;
}

.history-top {
    display: flex;
    justify-content: space-between;
    gap: 10px;
    font-weight: 800;
    color: var(--blue);
}

.history-text {
    margin-top: 5px;
    color: var(--muted);
    font-size: 13px;
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
}

.clear {
    width: 100%;
    padding: 12px;
    border: 0;
    background: #f5f8fc;
    color: var(--muted);
    font-weight: 700;
    cursor: pointer;
}

.safety {
    margin-top: 34px;
    padding-top: 23px;
    border-top: 1px solid var(--border);
    text-align: center;
}

.safety strong {
    color: var(--blue);
}

.safety p {
    margin: 8px auto;
    max-width: 500px;
    color: var(--muted);
    line-height: 1.5;
    font-size: 13px;
}

.singapore {
    margin-top: 19px !important;
    font-weight: 700;
    color: var(--blue) !important;
}

.loading {
    display: none;
    text-align: center;
    padding: 18px;
    color: var(--blue);
    font-weight: 700;
}

@media (max-width: 480px) {
    .shell {
        padding-top: 28px;
    }

    .action {
        padding: 18px;
    }

    .panel {
        padding: 18px;
    }
}

</style>

</head>

<body>

<main class="shell">

<section class="brand">

<div class="shield">✓</div>

<h1>STOP! CHECK! WAIT!</h1>

<div class="scam-checker">
Scam Checker
</div>

<div class="tagline">
Check before you click, pay or trust.
</div>
<div class="tagline">
Made in Singapore ·  Built for the world
</div>


</section>


<section class="actions">

<button class="action" onclick="openPanel('screenshot')">
<div class="icon">▣</div>
<div>
<strong>Check Screenshot or QR Code</strong>
<span>Upload a screenshot, photo or QR code.</span>
</div>
</button>

<button class="action" onclick="openPanel('link')">
<div class="icon">↗</div>
<div>
<strong>Check Link</strong>
<span>Paste a suspicious website or message link.</span>
</div>
</button>


<button class="action" onclick="openPanel('message')">
<div class="icon">✉</div>
<div>
<strong>Paste Message</strong>
<span>Check an SMS, WhatsApp, email or chat message.</span>
</div>
</button>
<button class="action" onclick="openPanel('scammed')">
<div class="icon">!</div>
<div>
<strong>I Think I've Been Scammed</strong>
<span>Get immediate steps to help limit the damage.</span>
</div>
</button>


</section>

<section id="scammed" class="panel">

<h2>I Think I've Been Scammed</h2>
<p class="hint">Tell us what happened so we can show you the most important next steps.</p>

<div class="field">
<label>What happened?</label>

<select id="scammedType">
<option value="">Choose one...</option>
<option value="money">I sent or transferred money</option>
<option value="banking">I shared banking, card or OTP details</option>
<option value="access">I installed an app or gave someone access to my device</option>
<option value="link">I clicked a link or entered personal information</option>
<option value="other">Something else happened</option>
</select>
</div>

<button class="primary" onclick="showScamHelp()">Show me what to do now</button>

<div id="scammedResult"></div>

</section>
<section id="screenshot" class="panel">

<h2>Check Screenshot or QR code</h2>

<p class="helper">
Upload a screenshot, photo or QR code. We will examine the visible content and
warning signs. QR codes can be checked without opening the website. JPG, PNG and WEBP up to 8 MB.
</p>

<div class="upload">

<strong>Choose a screenshot, photo or QR code</strong>

<br>

<input
id="imageFile"
type="file"
accept="image/jpeg,image/png,image/webp"
onchange="previewImage()">

<img id="preview" class="preview" alt="Screenshot preview">

</div>

<input
id="imageContext"
type="text"
maxlength="1000"
placeholder="Optional: Tell us what worries you for a more detailed check">

<button class="primary" onclick="checkImage()">
Analyse Image or QR code
</button>

</section>


<section id="link" class="panel">

<h2>Check Link</h2>

<p class="helper">
Paste the suspicious URL exactly as you received it.
We'll assess the link for warning signs without asking you to open or visit it.
</p>

<input
id="linkInput"
maxlength="10000"
type="url"
placeholder="https://example.com/...">

<button class="primary" onclick="checkText('link')">
Check Link
</button>

</section>


<section id="message" class="panel">

<h2>Paste Message</h2>

<p class="helper">
Paste the full message if possible. We can analyse multilingual
content and early-stage social engineering.
</p>

<textarea
id="messageInput"
maxlength="10000"
placeholder="Paste the suspicious message here..."></textarea>

<button class="primary" onclick="checkText('message')">
Check Message
</button>

</section>


<div id="loading" class="loading">
We are checking...
</div>


<section id="result" class="result"></section>


<button class="history-btn" onclick="toggleHistory()">
View last 10 checks
</button>

<div id="history" class="history"></div>
<div class="community-actions">
        <button class="community-btn" onclick="shareApp()">
    Share App
    <span style="display:block; font-size:13px; font-weight:400; margin-top:5px;">
        Share this with someone you care about. It might help them avoid a scam.
    </span>
</button>    

    <button class="community-btn" onclick="rateApp()">
        Rate App
    </button>
</div>



<section class="safety">

<strong>STOP. CHECK. WAIT.</strong>

<p>
Scammers often rely on urgency. Take time to verify unexpected
requests independently before clicking, paying or sharing sensitive information.
</p>

<p>
We provide risk guidance, not a guarantee that content is safe or fraudulent.
</p>

<p class="singapore">
Built in Singapore · Protecting people everywhere
</p>

</section>

</main>


<script>

function openPanel(id) {

    document
        .querySelectorAll(".panel")
        .forEach(x => x.classList.remove("active"));

    document
        .getElementById(id)
        .classList.add("active");

    document
        .getElementById("result")
        .style.display = "none";

    setTimeout(() => {
        document
            .getElementById(id)
            .scrollIntoView({
                behavior: "smooth",
                block: "center"
            });
    }, 80);
}


function setLoading(on) {

    document
        .getElementById("loading")
        .style.display = on ? "block" : "none";

    document
        .querySelectorAll(".primary")
        .forEach(btn => btn.disabled = on);
}


async function checkText(mode) {

    const input =
        mode === "link"
        ? document.getElementById("linkInput")
        : document.getElementById("messageInput");

    const text = input.value.trim();

    if (!text) {
        alert(
            mode === "link"
            ? "Please paste a link first."
            : "Please paste a message first."
        );
        return;
    }

    setLoading(true);

    try {

        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                text: text,
                mode: mode
            })
        });
        if (!response.ok) {
    throw new Error("Analysis service returned an error.");
}

        const data = await response.json();
        

        handleResult(data, mode, text);

    } catch (error) {

        showError(
            "We could not connect to the analysis service. Please try again."
        );

    } finally {

        setLoading(false);
    }
}


function previewImage() {

    const file =
        document.getElementById("imageFile").files[0];

    const preview =
        document.getElementById("preview");

    if (!file) {
        preview.style.display = "none";
        return;
    }

    preview.src = URL.createObjectURL(file);
    preview.style.display = "block";
}


async function checkImage() {

    const input =
        document.getElementById("imageFile");

    const file = input.files[0];

    if (!file) {
        alert("Please choose a screenshot first.");
        return;
    }

    const form = new FormData();

    form.append("file", file);

    form.append(
        "context",
        document.getElementById("imageContext").value.trim()
    );

    setLoading(true);

    try {

        const response = await fetch("/analyze-image", {
            method: "POST",
            body: form
        });

        if (!response.ok) {
            throw new Error("Image analysis service returned an error.");
        }

        const data = await response.json();

        handleResult(
            data,
            "screenshot",
            file.name
        );

    } catch (error) {

        showError(
            "We could not analyse this screenshot. Please try again."
        );

    } finally {

        setLoading(false);
    }
}


function handleResult(data, type, source) {

    if (data.error) {

        let message = escapeHtml(data.error);

        
        showError(message);

        return;
    }

    renderResult(data);

    saveHistory({
        type: type,
        source: source,
        risk: data.risk,
        summary: data.summary,
        time: new Date().toISOString()
    });
}


function renderResult(data) {

    const signals =
        (data.signals || [])
        .map(x => "<li>" + escapeHtml(x) + "</li>")
        .join("");

    const actions =
        (data.actions || [])
        .map(x => "<li>" + escapeHtml(x) + "</li>")
        .join("");

    const risk =
        ["LOW", "CAUTION", "HIGH"].includes(data.risk)
        ? data.risk
        : "CAUTION";

    const result =
        document.getElementById("result");

    result.innerHTML = `
        <div class="risk ${risk}">
            ${escapeHtml(risk)} RISK
        </div>

        <div class="summary">
            ${escapeHtml(data.summary || "")}
        </div>

        <h3>What we noticed</h3>
        <ul>
            ${signals || "<li>No specific warning signs were returned.</li>"}
        </ul>

        <h3>What we cannot verify</h3>
        <div class="uncertainty">
            ${escapeHtml(data.uncertainty || "Authenticity cannot be independently verified from this submission alone.")}
        </div>

        <h3>What to do next</h3>
        <ul>
            ${actions}
        </ul>

        <h3>Detected language</h3>
        <div class="uncertainty">
            ${escapeHtml(data.language || "Unknown")}
        </div>
    `;

    result.style.display = "block";

    result.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}


function showError(message) {

    const result =
        document.getElementById("result");

    result.innerHTML = `
        <div class="risk CAUTION">
            CHECK INCOMPLETE
        </div>

        <div class="uncertainty">
            ${message}
        </div>
    `;

    result.style.display = "block";
}


function getHistory() {

    try {

        return JSON.parse(
            localStorage.getItem("wait_history") || "[]"
        );

    } catch {

        return [];
    }
}


function saveHistory(item) {

    const history = getHistory();

    history.unshift(item);

    localStorage.setItem(
        "wait_history",
        JSON.stringify(history.slice(0, 10))
    );

    renderHistory();
}


function toggleHistory() {

    const el =
        document.getElementById("history");

    if (el.style.display === "block") {

        el.style.display = "none";

    } else {

        renderHistory();
        el.style.display = "block";
    }
}


function renderHistory() {

    const history = getHistory();

    const el =
        document.getElementById("history");

    if (!history.length) {

        el.innerHTML = `
            <div class="history-item">
                No checks saved on this device yet.
            </div>
        `;

        return;
    }

    el.innerHTML =
        history.map(item => `

            <div class="history-item">

                <div class="history-top">
                    <span>
                        ${escapeHtml(item.type)}
                    </span>

                    <span>
                        ${escapeHtml(item.risk)}
                    </span>
                </div>

                <div class="history-text">
                    ${escapeHtml(item.source || "")}
                </div>

            </div>

        `).join("") +

        `
        <button class="clear" onclick="clearHistory()">
            Clear history
        </button>
        `;
}


function clearHistory() {

    localStorage.removeItem("wait_history");

    renderHistory();
}


const APP_SHARE_URL = window.location.origin;
const APP_STORE_URL = "";

async function shareApp() {
    const shareData = {
        title: "STOP! CHECK! WAIT!",
        text: "Check suspicious messages, links, screenshots and QR codes for scam warning signs before you act.",
        url: APP_SHARE_URL
    };

    try {
        if (navigator.share) {
            await navigator.share(shareData);
            return;
        }

        await navigator.clipboard.writeText(APP_SHARE_URL);
        alert("App link copied. You can now share it with family and friends.");
    } catch (error) {
        if (error && error.name === "AbortError") {
            return;
        }

        try {
            await navigator.clipboard.writeText(APP_SHARE_URL);
            alert("App link copied. You can now share it with family and friends.");
        } catch {
            alert("We could not open sharing on this device.");
        }
    }
}

function rateApp() {
    if (!APP_STORE_URL) {
        alert("Rating will be available when the app is published in the app store.");
        return;
    }

    window.open(APP_STORE_URL, "_blank", "noopener,noreferrer");
}

function showScamHelp() {
    const type = document.getElementById("scammedType").value;
    const result = document.getElementById("scammedResult");

    if (!type) {
        result.innerHTML = `
            <div class="result">
                <strong>Please choose what happened first.</strong>
            </div>
        `;
        return;
    }

    const help = {
        money: {
            title: "You sent or transferred money",
            steps: [
                "Contact your bank or payment provider immediately using its official app, website or phone number. Tell them you may have been scammed and ask whether the transaction can be stopped, recalled or frozen.",
                "Do not send any more money, even if someone promises to recover what you lost.",
                "Save screenshots, receipts, transaction details, phone numbers, messages and other evidence.",
                "Report the incident to the police or official scam-reporting service in your country as soon as possible."
            ]
        },

        banking: {
            title: "You shared banking, card or OTP details",
            steps: [
                "Contact your bank or card provider immediately using an official channel and tell them what information was exposed.",
                "Ask them to secure affected accounts or cards and follow their instructions.",
                "Change affected passwords from a trusted device. Do not reuse the old password.",
                "Watch your accounts closely for transactions or changes you do not recognise."
            ]
        },

        access: {
            title: "You installed an app or gave someone access to your device",
            steps: [
                "Stop communicating with the person and do not approve any more requests.",
                "Disconnect the affected device from the internet if someone may still have remote access.",
                "Using another trusted device, contact your bank immediately if banking or payment information may have been exposed.",
                "Remove suspicious remote-access apps and secure important accounts. If you are unsure whether the device is clean, get help from a trusted technical professional."
            ]
        },

        link: {
            title: "You clicked a link or entered personal information",
            steps: [
                "Close the suspicious page and do not enter any more information.",
                "If you entered a password, change it immediately on the real service using its official app or website.",
                "If that password was reused elsewhere, change it on those accounts too.",
                "If you entered banking, card or payment details, contact the relevant bank or provider immediately."
            ]
        },

        other: {
            title: "Something else happened",
            steps: [
                "Stop communicating with the suspected scammer and do not send money or additional information.",
                "Save messages, screenshots, phone numbers, links and transaction details as evidence.",
                "Contact any bank, payment provider or account provider that may be affected using official channels.",
                "Report the incident to the appropriate police or official scam-reporting service in your country."
            ]
        }
    };

    const selected = help[type];
    result.style.display = "block";
    result.innerHTML = `
        <div class="result">
            <h3>${selected.title}</h3>
            <p><strong>Act as soon as you can:</strong></p>
            <ol>
                ${selected.steps.map(step => `<li>${step}</li>`).join("")}
            </ol>
            <p><strong>Important:</strong> Never trust a phone number, link or contact detail supplied by the suspected scammer. Find the organisation's official contact details independently.</p>
        </div>
    `;
}

function escapeHtml(value) {

    const div =
        document.createElement("div");

    div.textContent =
        String(value ?? "");

    return div.innerHTML;
}

</script>

</body>
</html>
"""
