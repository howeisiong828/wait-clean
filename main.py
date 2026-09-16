import json
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover
    OpenAI = None

app = FastAPI(title="WAIT Scam Check API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


class AnalyzeRequest(BaseModel):
    text: str


INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>WAIT Scam Checker</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex flex-col items-center justify-start px-4 py-8">
  <div class="w-full max-w-xl mx-auto">
    <div class="text-center mb-6">
      <h1 class="text-2xl sm:text-3xl font-bold text-gray-900">🛡️ WAIT Scam Checker</h1>
      <p class="text-gray-600 mt-2 text-sm sm:text-base">
        Paste a suspicious message, email, or URL below and we'll check it for common scam tactics.
      </p>
    </div>

    <div class="bg-white shadow rounded-xl p-4 sm:p-6">
      <label for="inputText" class="block text-sm font-medium text-gray-700 mb-2">
        Suspicious text or URL
      </label>
      <textarea
        id="inputText"
        rows="6"
        class="w-full border border-gray-300 rounded-lg p-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        placeholder="Paste the message, email, or link you want to check..."
      ></textarea>

      <button
        id="analyzeBtn"
        class="mt-4 w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 rounded-lg transition disabled:opacity-50 disabled:cursor-not-allowed"
      >
        Analyze
      </button>

      <div id="loading" class="hidden mt-4 flex items-center justify-center gap-2 text-gray-600 text-sm">
        <svg class="animate-spin h-5 w-5 text-blue-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
        </svg>
        Analyzing...
      </div>

      <div id="errorBox" class="hidden mt-4 bg-red-50 border border-red-200 text-red-700 rounded-lg p-3 text-sm"></div>

      <div id="results" class="hidden mt-6 space-y-4">
        <div>
          <h2 class="text-sm font-semibold text-gray-700 mb-1">Risk Level</h2>
          <span id="riskLevel" class="inline-block px-3 py-1 rounded-full text-sm font-bold"></span>
        </div>

        <div id="summaryBox">
          <h2 class="text-sm font-semibold text-gray-700 mb-1">Summary</h2>
          <p id="summaryText" class="text-sm text-gray-800"></p>
        </div>

        <div>
          <h2 class="text-sm font-semibold text-gray-700 mb-1">🚩 Red Flags</h2>
          <ul id="redFlags" class="list-disc list-inside text-sm text-gray-800 space-y-1"></ul>
        </div>

        <div>
          <h2 class="text-sm font-semibold text-gray-700 mb-1">✅ Safe Next Steps</h2>
          <ul id="nextSteps" class="list-disc list-inside text-sm text-gray-800 space-y-1"></ul>
        </div>
      </div>
    </div>

    <p class="text-center text-xs text-gray-400 mt-6">
      WAIT does not store your submissions. Always trust your instincts — if something feels off, stop and verify.
    </p>
  </div>

  <script>
    const analyzeBtn = document.getElementById('analyzeBtn');
    const inputText = document.getElementById('inputText');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const errorBox = document.getElementById('errorBox');
    const riskLevel = document.getElementById('riskLevel');
    const redFlags = document.getElementById('redFlags');
    const nextSteps = document.getElementById('nextSteps');
    const summaryText = document.getElementById('summaryText');

    const riskColors = {
      high: 'bg-red-100 text-red-800',
      medium: 'bg-yellow-100 text-yellow-800',
      low: 'bg-green-100 text-green-800',
    };

    function resetUI() {
      errorBox.classList.add('hidden');
      results.classList.add('hidden');
      errorBox.textContent = '';
    }

    function renderList(el, items) {
      el.innerHTML = '';
      if (!items || items.length === 0) {
        const li = document.createElement('li');
        li.textContent = 'None identified.';
        el.appendChild(li);
        return;
      }
      items.forEach((item) => {
        const li = document.createElement('li');
        li.textContent = item;
        el.appendChild(li);
      });
    }

    async function analyze() {
      const text = inputText.value.trim();
      resetUI();

      if (!text) {
        errorBox.textContent = 'Please paste some text or a URL to analyze.';
        errorBox.classList.remove('hidden');
        return;
      }

      analyzeBtn.disabled = true;
      loading.classList.remove('hidden');

      try {
        const res = await fetch('/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text }),
        });

        const data = await res.json();

        if (!res.ok) {
          errorBox.textContent = data.message || data.error || 'Something went wrong. Please try again later.';
          errorBox.classList.remove('hidden');
          return;
        }

        const level = (data.risk_level || 'unknown').toLowerCase();
        riskLevel.textContent = level.charAt(0).toUpperCase() + level.slice(1);
        riskLevel.className = 'inline-block px-3 py-1 rounded-full text-sm font-bold ' + (riskColors[level] || 'bg-gray-100 text-gray-800');

        summaryText.textContent = data.summary || '';
        renderList(redFlags, data.red_flags);
        renderList(nextSteps, data.next_steps);

        results.classList.remove('hidden');
      } catch (err) {
        errorBox.textContent = 'Network error. Please check your connection and try again.';
        errorBox.classList.remove('hidden');
      } finally {
        analyzeBtn.disabled = false;
        loading.classList.add('hidden');
      }
    }

    analyzeBtn.addEventListener('click', analyze);
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(content=INDEX_HTML)


@app.get("/health")
def health():
    return {"status": "healthy"}


SYSTEM_PROMPT = """You are WAIT, an assistant that helps everyday people identify scams in text \
messages, emails, and URLs. Analyze the user-provided content for common scam tactics such as \
phishing, fake offers, credential theft, urgency/pressure tactics, impersonation, too-good-to-be-true \
deals, requests for payment or personal/financial information, suspicious links or domains, and \
grammar/formatting red flags.

Respond ONLY with a valid JSON object with exactly these keys:
{
  "risk_level": "high" | "medium" | "low",
  "red_flags": ["short specific red flag", ...],
  "next_steps": ["short actionable safety recommendation", ...],
  "summary": "one or two sentence plain-language summary of the assessment"
}

Do not include any text outside the JSON object."""


@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    if not OPENAI_API_KEY or OpenAI is None:
        return JSONResponse(
            status_code=503,
            content={
                "error": "AI analysis is not configured",
                "message": "Please configure OPENAI_API_KEY",
            },
        )

    text = (request.text or "").strip()
    if not text:
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid input", "message": "Please provide text to analyze"},
        )

    try:
        client = OpenAI(api_key=OPENAI_API_KEY)

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze the following for scam risk:\n\n{text}"},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
        )

        content = response.choices[0].message.content
        result = json.loads(content)

        risk_level = str(result.get("risk_level", "medium")).lower()
        if risk_level not in ("high", "medium", "low"):
            risk_level = "medium"

        return {
            "risk_level": risk_level,
            "red_flags": result.get("red_flags", []) or [],
            "next_steps": result.get("next_steps", []) or [],
            "summary": result.get("summary", ""),
        }
    except Exception as exc:  # pragma: no cover - defensive catch-all
        return JSONResponse(
            status_code=502,
            content={
                "error": "AI analysis failed",
                "message": "We couldn't complete the analysis right now. Please try again shortly.",
                "detail": str(exc),
            },
        )
