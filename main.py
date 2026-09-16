import os
import json
from pydantic import BaseModel
import openai

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="WAIT Scam Check API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize OpenAI client
openai.api_key = os.getenv("OPENAI_API_KEY")


class AnalyzeRequest(BaseModel):
    input: str


@app.get("/")
def home():
    return {
        "status": "online",
        "message": "WAIT Scam Check API is running"
    }

@app.post("/api/analyze")
async def analyze_scam(request: AnalyzeRequest):
    """Analyze user input for scam indicators using OpenAI"""
    if not openai.api_key:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=500,
            detail="OpenAI API key not configured"
        )
    
    if not request.input or len(request.input.strip()) < 5:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail="Input must be at least 5 characters"
        )

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": """You are a scam detection expert. Analyze the user input for common scam patterns and red flags.
                    
ALWAYS respond with valid JSON in this exact format (no markdown, no extra text):
{
    "risk_level": "high" | "medium" | "low",
    "reasons": ["flag1", "flag2", ...],
    "next_steps": ["step1", "step2", ...]
}

Risk levels:
- high: Multiple scam indicators (urgency, money requests, unusual claims, phishing patterns, etc.)
- medium: Some warning signs (overly casual urgency, minor red flags)
- low: Appears legitimate based on content analysis

Reasons: List 2-4 specific red flags or observations (be concise, under 15 words each)
Next steps: Provide 2-3 actionable safety recommendations"""
                },
                {
                    "role": "user",
                    "content": request.input
                }
            ],
            temperature=0.3,
            max_tokens=300
        )
        
        # Parse the response
        content = response.choices[0].message.content.strip()
        result = json.loads(content)
        
        return {
            "risk_level": result.get("risk_level", "medium"),
            "reasons": result.get("reasons", []),
            "next_steps": result.get("next_steps", [])
        }
    
    except json.JSONDecodeError:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=500,
            detail="Invalid response from AI service"
        )
    except openai.error.AuthenticationError:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=500,
            detail="OpenAI API key is invalid"
        )
    except openai.error.RateLimitError:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=429,
            detail="API rate limit exceeded. Try again later."
        )
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )

@app.get("/health")
def health():
    return {"status": "healthy"}
