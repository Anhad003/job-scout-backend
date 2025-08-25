import os, re, json, time, base64
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from dotenv import load_dotenv

# Gmail
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
SERVER_API_KEY = os.getenv("JOBSCOUT_API_KEY", "change-me")

GMAIL_CLIENT_ID = os.getenv("GMAIL_CLIENT_ID", "")
GMAIL_CLIENT_SECRET = os.getenv("GMAIL_CLIENT_SECRET", "")
OAUTH_REDIRECT_URI = os.getenv(
    "OAUTH_REDIRECT_URI",
    "https://job-scout-backend.onrender.com/gmail/oauth2callback",  # default
)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.readonly",
]

TOKENS_PATH = "gmail_tokens.json"

app = FastAPI(title="Job Scout Backend", version="1.3.0")

# ---------- Security ----------
def require_auth(auth_header: Optional[str]):
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth_header.split(" ", 1)[1].strip()
    if token != SERVER_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")

# ---------- Models ----------
class RankPayload(BaseModel):
    candidate_profile: Dict[str, Any]
    jobs: List[Dict[str, Any]]

class PreparePayload(BaseModel):
    job: Dict[str, Any]
    candidate_profile: Dict[str, Any]
    cv_url: Optional[str] = None

class SubmitPayload(BaseModel):
    job: Dict[str, Any]
    form_answers: Dict[str, Any]
    attachments: List[str] = []

class EmailPayload(BaseModel):
    to: str
    subject: str
    body: str
    attachments: List[str] = []
    send_now: bool = False

# ---------- Helpers ----------
UAE_WORDS = {"uae","united arab emirates","dubai","abu dhabi","sharjah","ajman","ras al khaimah","umm al quwain","fujairah"}
INDIA_WORDS = {"india","mumbai","bombay","pune","bengaluru","bangalore","hyderabad","gurugram","gurgaon","noida","delhi","new delhi","ncr","chennai","ahmedabad","kolkata"}

def detect_country_from_location(text: str) -> Optional[str]:
    t = text.lower()
    if any(w in t for w in UAE_WORDS):
        return "uae"
    if any(w in t for w in INDIA_WORDS):
        return "india"
    return None

def choose_cv_for_job(job: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, str]:
    location_text = " ".join([job.get("location",""), job.get("title",""), job.get("company","")])
    country = detect_country_from_location(location_text)
    if country == "uae" and profile.get("cv_variants", {}).get("uae"):
        return {"tag": "uae", "url": profile["cv_variants"]["uae"]}
    if country == "india" and profile.get("cv_variants", {}).get("india"):
        return {"tag": "india", "url": profile["cv_variants"]["india"]}
    if profile.get("cv_variants", {}).get("india"):
        return {"tag": "india", "url": profile["cv_variants"]["india"]}
    if profile.get("cv_variants", {}).get("uae"):
        return {"tag": "uae", "url": profile["cv_variants"]["uae"]}
    return {"tag": "unknown", "url": ""}

# ---------- Gmail helpers ----------
def _flow() -> Flow:
    if not (GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET and OAUTH_REDIRECT_URI):
        raise HTTPException(status_code=500, detail="Gmail env vars missing")
    return Flow.from_client_config(
        {
            "web": {
                "client_id": GMAIL_CLIENT_ID,
                "client_secret": GMAIL_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
        redirect_uri=OAUTH_REDIRECT_URI,
    )

def _load_creds() -> Optional[Credentials]:
    if not os.path.exists(TOKENS_PATH):
        return None
    data = json.load(open(TOKENS_PATH, "r"))
    creds = Credentials.from_authorized_user_info(data, SCOPES)
    if creds and creds.expired and creds.refresh_token:
        from google.auth.transport.requests import Request
        creds.refresh(Request())
        with open(TOKENS_PATH, "w") as f:
            f.write(creds.to_json())
    return creds

def _gmail_service() -> Optional[Any]:
    creds = _load_creds()
    if not creds:
        return None
    return build("gmail", "v1", credentials=creds)

def _make_raw_email(to: str, subject: str, body: str) -> str:
    msg = f"To: {to}\r\nSubject: {subject}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{body}"
    return base64.urlsafe_b64encode(msg.encode("utf-8")).decode("utf-8")

# ---------- Endpoints ----------
@app.get("/health")
def health():
    return {"ok": True, "ts": time.time()}

@app.get("/gmail/auth_start")
def gmail_auth_start(authorization: Optional[str] = Header(None)):
    require_auth(authorization)
    flow = _flow()
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    return {"auth_url": auth_url}

@app.get("/gmail/oauth2callback")
def gmail_oauth2callback(request: Request):
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")
    flow = _flow()
    flow.fetch_token(code=code)
    creds = flow.credentials
    with open(TOKENS_PATH, "w") as f:
        f.write(creds.to_json())
    return {"ok": True, "msg": "Gmail authorized. You can close this tab."}

@app.post("/email_hiring_manager")
def email_hiring_manager(payload: EmailPayload, authorization: Optional[str] = Header(None)):
    require_auth(authorization)

    if payload.send_now:
        svc = _gmail_service()
        if not svc:
            return {"status": "needs_auth", "tip": "Run /gmail/auth_start and approve access, then retry."}
        raw = _make_raw_email(payload.to, payload.subject, payload.body + "\n\n-- \nAnhad Thakur")
        res = svc.users().messages().send(userId="me", body={"raw": raw}).execute()
        return {"status": "sent", "messageId": res.get("id"), "threadId": res.get("threadId")}

    draft = f"""Subject: {payload.subject}

{payload.body}

-- 
Anhad Thakur
"""
    return {"status": "draft_created", "draft_preview": draft}
