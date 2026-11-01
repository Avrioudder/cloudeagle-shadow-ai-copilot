import os
import json
from groq import Groq
from app.models import AppLog, SecurityAssessment

GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

def fallback_security_evaluation(log: AppLog) -> SecurityAssessment:
    """Heuristic fallback rule engine when Groq API key is absent or rate-limited."""
    risk_score = 30
    threats = []
    gaps = []
    remediations = []

    if not log.sso_integrated:
        risk_score += 35
        threats.append("Unauthenticated Access: Bypasses SSO & Okta Multi-Factor Authentication.")
        gaps.append("SOC2 Type II - Trust Services Criteria (Access Control)")
        remediations.append("Enforce SSO integration or block app access at DNS/Gateway level.")

    if log.data_sensitivity == "High":
        risk_score += 30
        threats.append("Data Leakage Risk: High-sensitivity organizational data processed by unvetted LLM vendor.")
        gaps.append("GDPR Article 28 / HIPAA Data Processing Addendum (DPA) missing")
        remediations.append("Conduct Vendor Risk Assessment (VRA) and secure signed DPA before allowing usage.")

    if log.active_users > 10 and not log.sso_integrated:
        risk_score += 15
        threats.append(f"Unmanaged Shadow IT Expansion: {log.active_users} users active across {log.user_department}.")

    risk_score = min(100, risk_score)
    risk_level = "High" if risk_score >= 70 else ("Medium" if risk_score >= 40 else "Low")

    action = f"Immediate IT Intervention Required: Block endpoint and contact {log.user_department} lead." if risk_level == "High" else "Review license usage and schedule VRA."

    email_draft = (
        f"Subject: Security Advisory: Unvetted AI App Usage Detected ({log.app_name})\n\n"
        f"Hi {log.user_department} Team Lead,\n\n"
        f"Our CloudEagle Governance system detected active usage of '{log.app_name}' across {log.active_users} users in your department.\n"
        f"This tool is currently unapproved and lacks SSO authentication and verified Data Processing Addendums.\n\n"
        f"Next Steps:\n"
        f"1. Please pause uploading high-sensitivity data to this tool immediately.\n"
        f"2. Schedule a 15-minute review with IT Security to assess enterprise licensing options.\n\n"
        f"Best regards,\nIT Governance & Security Team"
    )

    return SecurityAssessment(
        app_id=log.app_id,
        app_name=log.app_name,
        risk_score=risk_score,
        risk_level=risk_level,
        identified_threats=threats or ["Low governance risk detected."],
        compliance_framework_gaps=gaps or ["Standard enterprise compliance maintained."],
        remediation_steps=remediations or ["Monitor monthly license spend and active seats."],
        recommended_action=action,
        department_notification_draft=email_draft
    )

def evaluate_app_security(log: AppLog) -> SecurityAssessment:
    """Evaluates Shadow AI application security risk via Groq/Llama-3 with heuristic fallback."""
    if not GROQ_API_KEY:
        return fallback_security_evaluation(log)

    try:
        client = Groq(api_key=GROQ_API_KEY)
        prompt = f"""
        You are an Enterprise IT Security & SaaS Governance AI Agent for CloudEagle.
        Analyze the following Shadow AI / SaaS tool usage log and generate a structured JSON security assessment.

        App Name: {log.app_name}
        Category: {log.category}
        Department: {log.user_department}
        Active Users: {log.active_users}
        Data Sensitivity: {log.data_sensitivity}
        SSO Integrated: {log.sso_integrated}
        Monthly Spend: ${log.monthly_spend}
        Log Snippet: {log.raw_log_snippet}
        Notes: {log.additional_notes}

        Return ONLY a JSON object with this exact structure:
        {{
            "risk_score": <int 0-100>,
            "risk_level": "<High|Medium|Low>",
            "identified_threats": ["<threat 1>", "<threat 2>"],
            "compliance_framework_gaps": ["<gap 1>", "<gap 2>"],
            "remediation_steps": ["<step 1>", "<step 2>"],
            "recommended_action": "<concise action recommendation>",
            "department_notification_draft": "<formal email draft from IT Admin to Department Head>"
        }}
        """

        response = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            response_format={"type": "json_object"}
        )

        res_json = json.loads(response.choices[0].message.content)
        return SecurityAssessment(
            app_id=log.app_id,
            app_name=log.app_name,
            risk_score=res_json.get("risk_score", 50),
            risk_level=res_json.get("risk_level", "Medium"),
            identified_threats=res_json.get("identified_threats", []),
            compliance_framework_gaps=res_json.get("compliance_framework_gaps", []),
            remediation_steps=res_json.get("remediation_steps", []),
            recommended_action=res_json.get("recommended_action", "Conduct Security Review"),
            department_notification_draft=res_json.get("department_notification_draft", "")
        )
    except Exception:
        return fallback_security_evaluation(log)