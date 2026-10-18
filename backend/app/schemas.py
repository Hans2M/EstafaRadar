from typing import Literal
from pydantic import BaseModel, Field

class ScanRequest(BaseModel):
    value: str = Field(min_length=1, max_length=6000)

class Finding(BaseModel):
    code: str
    severity: Literal["info", "warning", "critical"]
    description: str

class ScanResult(BaseModel):
    kind: Literal["url", "qr", "message"]
    verdict: Literal["bajo", "moderado", "alto", "no_concluyente"]
    score: int = Field(ge=0, le=100)
    findings: list[Finding]
    advice: str
    limitations: list[str]
    visited_destination: bool = False
    category: str | None = None
    page_title: str | None = None
    page_description: str | None = None
    final_url: str | None = None
    inspection_mode: Literal["playwright", "http_fallback", "none"] = "none"
