import json
import os

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ValidationError

app = FastAPI(title="WAIT Scam Check API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

SYSTEM_PROMPT = (
    "You are a cybersecurity expert analyzing suspicious messages, URLs, and "
    "emails for scams. Respond with a structured JSON object containing "
    "risk_level (high/medium/low/safe), risk_score (0.0-1.0), reasons (list of "
    "3-5 concise red flags), flags (list of dicts with category, severity, "
    "description), safe_next_steps (2-3 actionable steps), and disclaimer. Be "
    "conservative: flag suspicious domain spellings, urgency tactics, requests "
    "for credentials, etc. Only respond with the JSON object, no other text."
)


class CheckRequest(BaseModel):
    text: str  # User input: suspicious message, URL, or email content


class RiskFlag(BaseModel):
    category: str  # e.g. "phishing", "urgent_language", "spoofed_sender", "suspicious_domain"
    severity: str  # "high", "medium", "low"
    description: str


class CheckResponse(BaseModel):
    risk_level: str  # "high", "medium", "low", "safe"
    risk_score: float  # 0.0 to 1.0
    reasons: list[str]  # Concise bullet-point red flags
    flags: list[RiskFlag]
    safe_next_steps: list[str]
    disclaimer: str


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/api/check-scam", response_model=CheckResponse)
async def check_scam(request: CheckRequest):
    text = request.text.strip() if request.text else ""

    if len(text) < 10:
        raise HTTPException(
            status_code=422,
            detail="Text must be at least 10 characters long.",
        )
    if len(text) > 5000:
        raise HTTPException(
            status_code=422,
            detail="Text must be at most 5000 characters long.",
        )

    if not OPENAI_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="Server is not configured with an OpenAI API key.",
        )

    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(OPENAI_API_URL, json=payload, headers=headers)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"OpenAI API returned an error: {exc.response.status_code}",
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail="Failed to reach OpenAI API.",
        ) from exc

    try:
        completion = response.json()
        content = completion["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        result = CheckResponse(**parsed)
    except (KeyError, IndexError, json.JSONDecodeError, ValidationError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Failed to parse a valid response from OpenAI.",
        ) from exc

    return result


@app.get("/")
def home():
    return FileResponse("public/index.html")


app.mount("/static", StaticFiles(directory="public"), name="static")
