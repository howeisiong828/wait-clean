import os
import json
import re

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="WAIT Scam Check")


class CheckRequest(BaseModel):
    text: str


@app.get("/health")
def health():
    return {"status": "healthy"}


def basic_scan(text: str):
    t = text.lower()
    flags = []

    rules = [
        (r"\burgent\b|\bimmediately\b|\bact now\b", "Creates urgency or pressure"),
        (r"\botp\b|\bverification code\b|\bpassword\b|\bpin\b", "Asks for sensitive account information"),
        (r"\btransfer\b|\bpayment\b|\bpaynow\b|\bcrypto\b|\bbitcoin\b", "Mentions transferring money or cryptocurrency"),
        (r"\bclick\b|\blink\b|https?://", "Contains or asks you to follow a link"),
        (r"\bprize\b|\bwinner\b|\breward\b|\bfree money\b", "Promises a prize or unexpected reward"),
        (r"\baccount.*(suspend|block|freeze)\b", "Threatens an account restriction"),
        (r"\bpolice\b|\bbank\b|\bgovernment\b|\bcourier\b", "May be impersonating a trusted organisation"),
    ]

    for pattern, reason in rules:
        if re.search(pattern, t):
            flags.append(reason)

    if len(flags) >= 4:
        risk = "HIGH"
    elif len(flags) >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return risk, flags


@app.post("/analyze")
def analyze(req: CheckRequest):
    text = req.text.strip()

    if not text:
        return {"error": "Please paste a message or URL first."}

    risk, flags = basic_scan(text)

    if not flags:
        flags = [
            "No obvious scam pattern was detected by the basic screening."
        ]

    return {
        "risk": risk,
        "reasons": flags,
        "next_steps": [
            "Do not send money or reveal passwords, PINs or OTP codes.",
            "Do not trust contact details contained in the suspicious message.",
            "Verify the sender independently using the organisation's official website or app.",
            "If money or account access may already be affected, contact your bank immediately."
        ],
        "ai_enabled": bool(os.getenv("OPENAI_API_KEY"))
    }


@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>WAIT Scam Check</title>

<style>
* { box-sizing: border-box; }

body {
    margin: 0;
    background: #07111f;
    color: white;
    font-family: Arial, Helvetica, sans-serif;
}

.container {
    width: min(720px, 92%);
    margin: 0 auto;
    padding: 55px 0;
}

.logo {
    font-size: 42px;
    font-weight: 900;
    letter-spacing: 4px;
    color: #48d597;
}

.tagline {
    color: #9eabc0;
    margin-top: 5px;
    margin-bottom: 45px;
}

h1 {
    font-size: 34px;
    margin-bottom: 10px;
}

.sub {
    color: #aeb8c8;
    line-height: 1.5;
    margin-bottom: 25px;
}

.card {
    background: #101c2d;
    padding: 25px;
    border-radius: 18px;
    border: 1px solid #22334a;
}

textarea {
    width: 100%;
    min-height: 180px;
    resize: vertical;
    padding: 17px;
    border-radius: 12px;
    border: 1px solid #34465e;
    background: #07111f;
    color: white;
    font-size: 16px;
    outline: none;
}

button {
    width: 100%;
    margin-top: 15px;
    padding: 16px;
    border: 0;
    border-radius: 12px;
    background: #48d597;
    color: #07111f;
    font-size: 17px;
    font-weight: bold;
    cursor: pointer;
}

button:disabled {
    opacity: .6;
}

#result {
    display: none;
    margin-top: 22px;
}

.risk {
    font-size: 27px;
    font-weight: bold;
    margin-bottom: 15px;
}

.HIGH { color: #ff6262; }
.MEDIUM { color: #ffc857; }
.LOW { color: #48d597; }

.section {
    margin-top: 20px;
}

.section h3 {
    margin-bottom: 8px;
}

li {
    margin: 8px 0;
    line-height: 1.4;
}

.footer {
    text-align: center;
    color: #65738a;
    font-size: 13px;
    margin-top: 35px;
}
</style>
</head>

<body>

<div class="container">

<div class="logo">WAIT</div>
<div class="tagline">Pause. Check. Protect.</div>

<h1>Could this be a scam?</h1>

<div class="sub">
Paste a suspicious message, email, SMS or website link below.
WAIT will look for common scam warning signs before you act.
</div>

<div class="card">

<textarea id="input"
placeholder="Paste the suspicious message or URL here..."></textarea>

<button id="button" onclick="checkScam()">
Check for scam signs
</button>

<div id="result"></div>

</div>

<div class="footer">
WAIT provides guidance only. Always verify important requests independently.
</div>

</div>

<script>

async function checkScam() {

    const text = document.getElementById("input").value.trim();
    const result = document.getElementById("result");
    const button = document.getElementById("button");

    if (!text) {
        alert("Please paste a message or URL first.");
        return;
    }

    button.disabled = true;
    button.innerText = "Checking...";

    try {

        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({text})
        });

        const data = await response.json();

        if (data.error) {
            throw new Error(data.error);
        }

        const reasons = data.reasons
            .map(x => `<li>${escapeHtml(x)}</li>`)
            .join("");

        const steps = data.next_steps
            .map(x => `<li>${escapeHtml(x)}</li>`)
            .join("");

        result.innerHTML = `
            <div class="risk ${data.risk}">
                ${data.risk} RISK
            </div>

            <div class="section">
                <h3>What WAIT noticed</h3>
                <ul>${reasons}</ul>
            </div>

            <div class="section">
                <h3>What you should do</h3>
                <ul>${steps}</ul>
            </div>
        `;

        result.style.display = "block";

    } catch (error) {

        result.innerHTML =
            "<p>Something went wrong. Please try again.</p>";

        result.style.display = "block";

    } finally {

        button.disabled = false;
        button.innerText = "Check for scam signs";
    }
}

function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value;
    return div.innerHTML;
}

</script>

</body>
</html>
"""
