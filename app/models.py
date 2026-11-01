from pydantic import BaseModel, Field
from typing import List, Optional

class AppLog(BaseModel):
    app_id: str
    app_name: str
    category: str
    user_department: str
    active_users: int
    data_sensitivity: str  # High, Medium, Low
    sso_integrated: bool
    monthly_spend: float
    raw_log_snippet: str
    additional_notes: Optional[str] = ""

class SecurityAssessment(BaseModel):
    app_id: str
    app_name: str
    risk_score: int  # 0 to 100
    risk_level: str  # High, Medium, Low
    identified_threats: List[str]
    compliance_framework_gaps: List[str]
    remediation_steps: List[str]
    recommended_action: str
    department_notification_draft: str