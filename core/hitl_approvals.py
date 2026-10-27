import time
import secrets
from .database import get_connection, log_audit

class HITLApprovalManager:
    """
    Human-in-the-Loop (HITL) Action Approval Orchestrator.
    Inspired by Vigil SOC confidence gates. High-consequence operations
    (scans, system locks, rule alterations) require explicit affirmative human confirmation.
    """
    def __init__(self):
        pass

    def create_request(self, action_type: str, target: str, risk_level: str, details: str, requested_by: str = "Analyst") -> dict:
        request_id = f"hitl_{secrets.token_hex(6)}"
        now = time.time()
        conn = get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO hitl_approvals (request_id, action_type, target, risk_level, details, status, requested_by, created_at)
            VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?)
        ''', (request_id, action_type, target, risk_level, details, requested_by, now))
        conn.commit()
        conn.close()

        log_audit(requested_by, "Analyst", "HITL_REQUEST_CREATED", f"{action_type}:{target}", "PENDING", "127.0.0.1", f"Requested {action_type} on {target} [{risk_level}]")
        return {
            "request_id": request_id,
            "action_type": action_type,
            "target": target,
            "risk_level": risk_level,
            "status": "PENDING",
            "message": "Action queued for Human-in-the-Loop authorization. Admin approval required."
        }

    def list_pending(self) -> list[dict]:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM hitl_approvals WHERE status = 'PENDING' ORDER BY id DESC")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    def list_all(self, limit: int = 50) -> list[dict]:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM hitl_approvals ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    def resolve(self, request_id: str, decision: str, resolved_by: str, client_ip: str = "127.0.0.1") -> dict:
        decision = decision.upper()
        if decision not in ("APPROVED", "REJECTED"):
            return {"success": False, "error": "Invalid decision state"}

        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM hitl_approvals WHERE request_id = ?", (request_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return {"success": False, "error": "Approval request not found"}

        if row["status"] != "PENDING":
            conn.close()
            return {"success": False, "error": f"Request already resolved as {row['status']}"}

        now = time.time()
        c.execute('''
            UPDATE hitl_approvals
            SET status = ?, resolved_by = ?, resolved_at = ?
            WHERE request_id = ?
        ''', (decision, resolved_by, now, request_id))
        conn.commit()
        conn.close()

        log_audit(resolved_by, "Admin", f"HITL_{decision}", f"{row['action_type']}:{row['target']}", decision, client_ip, f"Request {request_id} was {decision.lower()} by {resolved_by}")
        return {
            "success": True,
            "request_id": request_id,
            "decision": decision,
            "action_type": row["action_type"],
            "target": row["target"],
            "resolved_by": resolved_by
        }
