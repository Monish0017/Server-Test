import os
import secrets
from datetime import datetime, timezone
from threading import Lock
from typing import Dict, List, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

load_dotenv()

def get_required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


DEFAULT_USERNAME = get_required_env("BASIC_AUTH_USERNAME")
DEFAULT_PASSWORD = get_required_env("BASIC_AUTH_PASSWORD")
REQUIRED_HEADER_KEY = get_required_env("REQUIRED_HEADER_KEY")
REQUIRED_HEADER_VALUE = get_required_env("REQUIRED_HEADER_VALUE")

security = HTTPBasic()
app = FastAPI(title="Incident Auth API", version="1.0.0")

incident_lock = Lock()


class IncidentCreate(BaseModel):
    incident_created_date: str = Field(..., examples=["2026-06-28 10:15:00"])
    priority: str = Field(..., examples=["P1"])
    description: str
    assigned_to: str
    status: str = Field(..., examples=["Open"])
    category: str = Field(default="General")
    short_description: str = Field(default="")


class IncidentUpdate(BaseModel):
    incident_created_date: Optional[str] = None
    priority: Optional[str] = None
    description: Optional[str] = None
    assigned_to: Optional[str] = None
    status: Optional[str] = None
    category: Optional[str] = None
    short_description: Optional[str] = None


def build_default_incidents() -> List[Dict[str, object]]:
    return [
        {
            "id": 1,
            "inc_num": "INC0001001",
            "incident_created_date": "2026-06-01 08:15:00",
            "priority": "P1",
            "description": "Email service outage reported by finance users.",
            "assigned_to": "Alice Johnson",
            "status": "Open",
            "category": "Email",
            "short_description": "Finance email outage",
        },
        {
            "id": 2,
            "inc_num": "INC0001002",
            "incident_created_date": "2026-06-01 09:30:00",
            "priority": "P2",
            "description": "VPN login failures for remote staff.",
            "assigned_to": "Ravi Kumar",
            "status": "In Progress",
            "category": "Network",
            "short_description": "VPN login failure",
        },
        {
            "id": 3,
            "inc_num": "INC0001003",
            "incident_created_date": "2026-06-01 10:05:00",
            "priority": "P3",
            "description": "Password reset portal shows intermittent errors.",
            "assigned_to": "Maria Garcia",
            "status": "Resolved",
            "category": "Access",
            "short_description": "Password reset portal error",
        },
        {
            "id": 4,
            "inc_num": "INC0001004",
            "incident_created_date": "2026-06-01 11:12:00",
            "priority": "P4",
            "description": "Printer queue stuck on floor 4.",
            "assigned_to": "John Smith",
            "status": "Open",
            "category": "Hardware",
            "short_description": "Printer queue stuck",
        },
        {
            "id": 5,
            "inc_num": "INC0001005",
            "incident_created_date": "2026-06-01 12:22:00",
            "priority": "P2",
            "description": "SharePoint upload failures for project docs.",
            "assigned_to": "Nina Patel",
            "status": "In Progress",
            "category": "Collaboration",
            "short_description": "SharePoint upload failure",
        },
        {
            "id": 6,
            "inc_num": "INC0001006",
            "incident_created_date": "2026-06-01 13:45:00",
            "priority": "P3",
            "description": "Laptop battery replacement requested for user.",
            "assigned_to": "Ethan Brown",
            "status": "Closed",
            "category": "Hardware",
            "short_description": "Battery replacement",
        },
        {
            "id": 7,
            "inc_num": "INC0001007",
            "incident_created_date": "2026-06-01 14:10:00",
            "priority": "P1",
            "description": "Production application error after deploy.",
            "assigned_to": "Sophia Lee",
            "status": "Open",
            "category": "Application",
            "short_description": "Production app error",
        },
        {
            "id": 8,
            "inc_num": "INC0001008",
            "incident_created_date": "2026-06-01 15:00:00",
            "priority": "P4",
            "description": "User requests monitor replacement.",
            "assigned_to": "David Wilson",
            "status": "Closed",
            "category": "Hardware",
            "short_description": "Monitor replacement",
        },
        {
            "id": 9,
            "inc_num": "INC0001009",
            "incident_created_date": "2026-06-02 08:20:00",
            "priority": "P2",
            "description": "CRM dashboard loading slowly for sales team.",
            "assigned_to": "Priya Shah",
            "status": "In Progress",
            "category": "Application",
            "short_description": "CRM dashboard slow",
        },
        {
            "id": 10,
            "inc_num": "INC0001010",
            "incident_created_date": "2026-06-02 09:05:00",
            "priority": "P3",
            "description": "User cannot access shared drive folder.",
            "assigned_to": "Kevin Miller",
            "status": "Open",
            "category": "Access",
            "short_description": "Shared drive access issue",
        },
        {
            "id": 11,
            "inc_num": "INC0001011",
            "incident_created_date": "2026-06-02 10:40:00",
            "priority": "P1",
            "description": "Payroll batch job failed during processing.",
            "assigned_to": "Olivia Davis",
            "status": "In Progress",
            "category": "Batch Job",
            "short_description": "Payroll batch failure",
        },
        {
            "id": 12,
            "inc_num": "INC0001012",
            "incident_created_date": "2026-06-02 11:25:00",
            "priority": "P3",
            "description": "Teams calls drop every 15 minutes.",
            "assigned_to": "Liam Anderson",
            "status": "Open",
            "category": "Collaboration",
            "short_description": "Teams call drops",
        },
        {
            "id": 13,
            "inc_num": "INC0001013",
            "incident_created_date": "2026-06-02 13:10:00",
            "priority": "P4",
            "description": "Request for new mouse and keyboard.",
            "assigned_to": "Mia Thompson",
            "status": "Closed",
            "category": "Hardware",
            "short_description": "Peripheral request",
        },
        {
            "id": 14,
            "inc_num": "INC0001014",
            "incident_created_date": "2026-06-02 14:55:00",
            "priority": "P2",
            "description": "Internal portal certificate warning displayed.",
            "assigned_to": "Benjamin Clark",
            "status": "Open",
            "category": "Security",
            "short_description": "Portal certificate warning",
        },
        {
            "id": 15,
            "inc_num": "INC0001015",
            "incident_created_date": "2026-06-03 08:30:00",
            "priority": "P1",
            "description": "Database connection pool exhaustion on API.",
            "assigned_to": "Ava Martinez",
            "status": "In Progress",
            "category": "Database",
            "short_description": "DB pool exhaustion",
        },
        {
            "id": 16,
            "inc_num": "INC0001016",
            "incident_created_date": "2026-06-03 09:45:00",
            "priority": "P3",
            "description": "New hire account creation pending approval.",
            "assigned_to": "Daniel Taylor",
            "status": "Resolved",
            "category": "Access",
            "short_description": "New hire account approval",
        },
        {
            "id": 17,
            "inc_num": "INC0001017",
            "incident_created_date": "2026-06-03 11:00:00",
            "priority": "P2",
            "description": "Intranet homepage broken for mobile users.",
            "assigned_to": "Charlotte Harris",
            "status": "Open",
            "category": "Web",
            "short_description": "Intranet mobile issue",
        },
        {
            "id": 18,
            "inc_num": "INC0001018",
            "incident_created_date": "2026-06-03 12:18:00",
            "priority": "P4",
            "description": "Request to update office software license.",
            "assigned_to": "Henry Walker",
            "status": "Closed",
            "category": "License",
            "short_description": "Software license update",
        },
        {
            "id": 19,
            "inc_num": "INC0001019",
            "incident_created_date": "2026-06-03 14:22:00",
            "priority": "P2",
            "description": "SFTP transfer job failing on schedule.",
            "assigned_to": "Isabella Young",
            "status": "In Progress",
            "category": "Integration",
            "short_description": "SFTP transfer failure",
        },
        {
            "id": 20,
            "inc_num": "INC0001020",
            "incident_created_date": "2026-06-03 15:35:00",
            "priority": "P3",
            "description": "Need password reset for shared service account.",
            "assigned_to": "Michael King",
            "status": "Open",
            "category": "Access",
            "short_description": "Service account reset",
        },
    ]


INCIDENTS: List[Dict[str, object]] = build_default_incidents()


def require_basic_auth(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    username_ok = secrets.compare_digest(credentials.username, DEFAULT_USERNAME)
    password_ok = secrets.compare_digest(credentials.password, DEFAULT_PASSWORD)

    if not username_ok or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid basic auth credentials.",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username


def require_copilot_header(request: Request) -> None:
    header_value = request.headers.get(REQUIRED_HEADER_KEY)
    if header_value is None or not secrets.compare_digest(header_value, REQUIRED_HEADER_VALUE):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Missing or invalid header: {REQUIRED_HEADER_KEY}.",
            headers={"WWW-Authenticate": "Basic"},
        )


def require_request_auth(
    request: Request,
    username: str = Depends(require_basic_auth),
) -> str:
    require_copilot_header(request)
    return username


def next_incident_id() -> int:
    if not INCIDENTS:
        return 1
    return max(item["id"] for item in INCIDENTS) + 1


def next_incident_number() -> str:
    return f"INC{1000 + next_incident_id():07d}"


def find_incident_index(incident_id: int) -> int:
    for index, incident in enumerate(INCIDENTS):
        if incident["id"] == incident_id:
            return index
    return -1


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/auth-info")
def auth_info() -> Dict[str, str]:
    return {
        "header_key": "Authorization",
        "header_value_format": "Basic <base64(username:password)>",
        "default_username": DEFAULT_USERNAME,
        "default_password": DEFAULT_PASSWORD,
    }


@app.get("/incidents")
def list_incidents(username: str = Depends(require_request_auth)) -> Dict[str, object]:
    return {"requested_by": username, "count": len(INCIDENTS), "items": INCIDENTS}


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int, username: str = Depends(require_request_auth)) -> Dict[str, object]:
    index = find_incident_index(incident_id)
    if index == -1:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
    return {"requested_by": username, "item": INCIDENTS[index]}


@app.post("/incidents", status_code=status.HTTP_201_CREATED)
def create_incident(payload: IncidentCreate, username: str = Depends(require_request_auth)) -> Dict[str, object]:
    with incident_lock:
        incident = payload.model_dump()
        incident_record = {
            "id": next_incident_id(),
            "inc_num": next_incident_number(),
            **incident,
        }
        INCIDENTS.append(incident_record)

    return {"requested_by": username, "created": incident_record}


@app.put("/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    username: str = Depends(require_request_auth),
) -> Dict[str, object]:
    with incident_lock:
        index = find_incident_index(incident_id)
        if index == -1:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")

        current = INCIDENTS[index].copy()
        updates = payload.model_dump(exclude_unset=True)
        current.update(updates)
        current["updated_at"] = datetime.now(timezone.utc).isoformat()
        INCIDENTS[index] = current

    return {"requested_by": username, "updated": current}


@app.delete("/incidents/{incident_id}")
def delete_incident(incident_id: int, username: str = Depends(require_request_auth)) -> Dict[str, object]:
    with incident_lock:
        index = find_incident_index(incident_id)
        if index == -1:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")

        removed = INCIDENTS.pop(index)

    return {"requested_by": username, "deleted": removed}


@app.get("/")
def root() -> Dict[str, str]:
    return {
        "service": "Incident Auth API",
        "health": "/health",
        "incidents": "/incidents",
        "auth_header": "Authorization",
        "required_header": REQUIRED_HEADER_KEY,
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "10000"))
    uvicorn.run(app, host="0.0.0.0", port=port)