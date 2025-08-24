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
SERVER_API_KEY = os.getenv("JOBSCOUT_API_KEY", "change-me")  # set in Render

GMAIL_CLIENT_ID = os.getenv("GMAIL_CLIENT_ID", "")
GMAIL_CLIENT_SECRET = os.getenv("GMAIL_CLIENT_SECRET", "")
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "")

SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.readonly",
]

TOKENS_PATH = "gmail_tokens.json"  # stored on disk; re-authorize after a redeploy if needed

app = FastAPI(title="Job Scout Backend", version="1.2.0")

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
    cv_url: Optional[str] = None  # optional override

class SubmitPayload(BaseModel):
    job: Dict[str, Any]
    form_answers: Dict[str, Any]
    attachments: List[str] = []

class EmailPayload(BaseModel):
    to: str
    subject: str
    body: str
    attachments: List[str] = []
    send_now: bool = False  # safety: default false

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
    """
    Returns {'tag': 'uae'|'india'|'unknown', 'url': '...'}
    Uses filename convention ..._UAE.pdf / ..._INDIA.pdf via profile['cv_variants'].
    """
    location_text = " ".join([job.get("location",""), job.get("title",""), job.get("company","")])
    country = detect_country_from_location(location_text)
    if country == "uae" and profile.get("cv_variants", {}).get("uae"):
        return {"tag": "uae", "url": profile["cv_variants"]["uae"]}
    if country == "india" and profile.get("cv_variants", {}).get("india"):
        return {"tag": "india", "url": profile["cv_variants"]["india"]}
    # fallback (unknown): prefer India CV, else UAE CV, else none
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
        # save refreshed
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
    # protect this route: JASAAM will pass the Bearer header
    require_auth(authorization)
    flow = _flow()
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    # IMPORTANT: JASAAM looks for "auth_url"
    return {"auth_url": auth_url}

@app.get("/gmail/oauth2callback")
def gmail_oauth2callback(request: Request):
    # This is a public redirect target called by Google; no auth header
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")
    flow = _flow()
    flow.fetch_token(code=code)
    creds = flow.credentials
    with open(TOKENS_PATH, "w") as f:
        f.write(creds.to_json())
    return {"ok": True, "msg": "Gmail authorized. You can close this tab."}

@app.get("/search_jobs")
def search_jobs(
    q: str = "",
    locations: str = "Dubai,Abu Dhabi,Sharjah,Mumbai,Pune,Bengaluru,Hyderabad,Gurugram,Noida,Remote",
    sources: str = "greenhouse,lever,workable,ashby",
    limit: int = 20,
    authorization: Optional[str] = Header(None)
):
    require_auth(authorization)
    # Minimal sample data (you can wire real ATS APIs later)
    sample = [
        {
            "id": "sample-uae-1",
            "title": "IoT Architect – Smart Cities",
            "company": "UrbanTech GCC",
            "location": "Dubai, UAE",
            "source": "greenhouse",
            "url": "https://careers.example.com/iot-architect",
            "description": "Lead ICCC, IoT platforms, mobility; AWS/Azure; vendor mgmt; RFP/RFI."
        },
        {
            "id": "sample-india-1",
            "title": "Manager – Digital Transformation (Utilities)",
            "company": "Utilities India Group",
            "location": "Bengaluru, India",
            "source": "lever",
            "url": "https://jobs.example.com/dx-manager",
            "description": "Smart metering, data hubs, cloud (AWS/GCP), stakeholder mgmt."
        }
    ]
    # crude keyword & location filter
    words = [w.lower() for w in re.findall(r"[A-Za-z0-9\-]+", q)]
    loc_list = [l.strip().lower() for l in locations.split(",")] if locations else []
    filtered = []
    for job in sample:
        text = (job["title"] + " " + job["description"] + " " + job["location"]).lower()
        if all(w in text for w in words) if words else True:
            if (loc_list and any(loc in text for loc in loc_list)) or (not loc_list):
                filtered.append(job)
    return filtered[:limit]

@app.post("/rank_jobs")
def rank_jobs(payload: RankPayload, authorization: Optional[str] = Header(None)):
    require_auth(authorization)
    skills = set([s.lower() for s in payload.candidate_profile.get("skills", [])])
    locs = set([l.lower() for l in payload.candidate_profile.get("locations", [])])
    ranked = []
    for j in payload.jobs:
        text = (j.get("title","") + " " + j.get("description","")).lower()
        score = 0
        score += sum(1 for s in skills if s in text)
        score += 2 if any(l in j.get("location","").lower() for l in locs) else 0
        score += 1 if any(k in text for k in ["iccc","smart city","iot"]) else 0
        ranked.append({"job": j, "score": score})
    ranked.sort(key=lambda x: x["score"], reverse=True)
    return ranked

@app.post("/prepare_application")
def prepare_application(payload: PreparePayload, authorization: Optional[str] = Header(None)):
    require_auth(authorization)
    prof = payload.candidate_profile
    job = payload.job

    # Auto-select CV (UAE vs India) using filename convention
    cv_choice = choose_cv_for_job(job, prof)
    cv_url = payload.cv_url or cv_choice["url"] or ""

    answers = {
        "full_name": prof.get("name"),
        "email": "your.email@example.com",
        "phone": "+91-XXXXXXXXXX",
        "current_location": "India",
        "work_authorization": "Requires employer sponsorship if in UAE",
        "notice_period": prof.get("notice_period", "Immediate"),
        "years_experience": prof.get("experience_years", 12),
        "salary_expectation": prof.get("salary_expectation", "Negotiable"),
        "why_fit": f"12+ yrs in Smart Cities/IoT. Led ICCC, mobility, utilities; AWS/Azure/GCP; vendor & RFP/DPR. Role '{job.get('title')}' aligns with my ICCC/IoT delivery background."
    }
    cover_letter = f"""Dear Hiring Team,

I’m applying for {job.get('title')} at {job.get('company','your company')}. I bring 12+ years across Smart Cities, ICCC, IoT platforms, utilities and mobility, leading vendor delivery, RFP/DPR, and cloud (AWS/Azure/GCP). Recent work: PCSCL ICCC with AI/ML, IWAI Smart Port (cost/CO₂ reductions), and Cisco rail-yard PoC (+40% fault detection). I’m ready to drive outcomes in {job.get('location','your region')}.

Best regards,
{prof.get('name')}
"""

    red_flags = []
    if cv_choice["tag"] == "unknown":
        red_flags.append("cv_selection_unknown")
    if not cv_url:
        red_flags.append("cv_url_missing")

    return {
        "answers": answers,
        "cover_letter": cover_letter.strip(),
        "cv_variant_tag": cv_choice["tag"],
        "cv_url": cv_url,
        "red_flags": red_flags
    }

@app.post("/submit_application")
def submit_application(payload: SubmitPayload, authorization: Optional[str] = Header(None)):
    require_auth(authorization)
    # For compliance, default to manual review unless wired to official ATS APIs
    return {
        "nextAction": "manual_review",
        "applyUrl": payload.job.get("url"),
        "note": "Open the URL; use the answers and attach the selected CV. Submit after review."
    }

@app.post("/email_hiring_manager")
def email_hiring_manager(payload: EmailPayload, authorization: Optional[str] = Header(None)):
    require_auth(authorization)

    # If send_now, try to send via Gmail API. Otherwise return a draft preview.
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
