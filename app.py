import os
import re
import smtplib
import socket
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

import dns.resolver
from flask import Flask, request, jsonify

app = Flask(__name__)
DB = "emailapi.db"

# ── Domínios temporários conhecidos ────────────────────────────────────────────
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwam.com",
    "yopmail.com", "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "guerrillamail.info", "guerrillamail.biz", "guerrillamail.de",
    "guerrillamail.net", "guerrillamail.org", "spam4.me", "trashmail.com",
    "trashmail.me", "trashmail.net", "trashmail.at", "trashmail.io",
    "trashmail.xyz", "dispostable.com", "mailnesia.com", "maildrop.cc",
    "spamgourmet.com", "spamgourmet.net", "spamgourmet.org", "fakeinbox.com",
    "tempinbox.com", "tempinbox.co.uk", "getairmail.com", "filzmail.com",
    "throwam.com", "tempr.email", "discard.email", "mailnull.com",
    "spamspot.com", "spamthisplease.com", "mailexpire.com", "throwam.com",
    "getnada.com", "mohmal.com", "burnermail.io", "tempm.com",
}

# ── Base de dados ───────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            key TEXT PRIMARY KEY,
            plan TEXT DEFAULT 'free',
            requests_today INTEGER DEFAULT 0,
            last_reset TEXT,
            created_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS request_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key TEXT,
            email TEXT,
            score INTEGER,
            valid INTEGER,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

# Inicializa a base de dados ao arrancar a aplicação
with app.app_context():
    init_db()

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

# ── Limites por plano ───────────────────────────────────────────────────────────
PLAN_LIMITS = {
    "free":  100,   # requests/dia
    "basic": 1000,
    "pro":   10000,
}

# ── Decorador de autenticação ───────────────────────────────────────────────────
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if not key:
            return jsonify({"error": "API key em falta. Passa no header X-API-Key."}), 401

        db = get_db()
        row = db.execute("SELECT * FROM api_keys WHERE key = ?", (key,)).fetchone()
        if not row:
            db.close()
            return jsonify({"error": "API key inválida."}), 403

        # Reset diário
        today = datetime.utcnow().date().isoformat()
        if row["last_reset"] != today:
            db.execute(
                "UPDATE api_keys SET requests_today = 0, last_reset = ? WHERE key = ?",
                (today, key)
            )
            db.commit()
            requests_today = 0
        else:
            requests_today = row["requests_today"]

        limit = PLAN_LIMITS.get(row["plan"], 100)
        if requests_today >= limit:
            db.close()
            return jsonify({
                "error": "Limite diário atingido.",
                "plan": row["plan"],
                "limit": limit,
                "upgrade": "https://rapidapi.com/teu-username/api/emailvalidator"
            }), 429

        db.execute(
            "UPDATE api_keys SET requests_today = requests_today + 1 WHERE key = ?",
            (key,)
        )
        db.commit()
        db.close()

        request.api_key = key
        request.plan = row["plan"]
        return f(*args, **kwargs)
    return decorated

# ── Engine de validação ─────────────────────────────────────────────────────────
def check_syntax(email: str) -> dict:
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    valid = bool(re.match(pattern, email))
    return {"pass": valid, "reason": None if valid else "Sintaxe inválida"}

def check_domain_mx(domain: str) -> dict:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx = str(answers[0].exchange).rstrip(".")
        return {"pass": True, "mx": mx}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {"pass": False, "reason": "Domínio não existe ou sem MX record"}
    except dns.resolver.Timeout:
        return {"pass": None, "reason": "Timeout a verificar MX"}
    except Exception as e:
        return {"pass": None, "reason": f"Erro DNS: {str(e)}"}

def check_disposable(domain: str) -> dict:
    is_disposable = domain.lower() in DISPOSABLE_DOMAINS
    return {"disposable": is_disposable}

def check_smtp(email: str, mx_host: str) -> dict:
    """Verifica se a caixa de correio aceita email via SMTP.
    Nota: muitos servidores bloqueiam isto — resultado pode ser inconclusivo."""
    try:
        with smtplib.SMTP(timeout=8) as smtp:
            smtp.connect(mx_host, 25)
            smtp.ehlo_or_helo_if_needed()
            smtp.mail("check@yourdomain.com")
            code, _ = smtp.rcpt(email)
            return {"pass": code == 250, "code": code}
    except smtplib.SMTPConnectError:
        return {"pass": None, "reason": "Servidor recusou ligação SMTP"}
    except smtplib.SMTPServerDisconnected:
        return {"pass": None, "reason": "Servidor desligou (catch-all provável)"}
    except socket.timeout:
        return {"pass": None, "reason": "Timeout SMTP"}
    except Exception as e:
        return {"pass": None, "reason": f"Erro SMTP: {str(e)}"}

def calculate_score(syntax, mx, disposable, smtp) -> int:
    """Score de 0 a 100 baseado nos checks."""
    score = 0

    if not syntax["pass"]:
        return 0  # sintaxe errada = inválido de imediato

    score += 30  # sintaxe ok

    if mx.get("pass") is True:
        score += 30
    elif mx.get("pass") is None:
        score += 15  # inconclusivo, damos metade

    if not disposable["disposable"]:
        score += 20
    else:
        score -= 20  # penaliza emails temporários

    if smtp.get("pass") is True:
        score += 20
    elif smtp.get("pass") is None:
        score += 10  # inconclusivo

    return max(0, min(100, score))

# ── Endpoints ───────────────────────────────────────────────────────────────────
@app.route("/validate", methods=["POST", "GET"])
@require_api_key
def validate_email():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        email = data.get("email", "").strip().lower()
    else:
        email = request.args.get("email", "").strip().lower()

    if not email:
        return jsonify({"error": "Parâmetro 'email' em falta."}), 400

    domain = email.split("@")[-1] if "@" in email else ""

    # Executa os 4 checks
    syntax   = check_syntax(email)
    mx       = check_domain_mx(domain) if syntax["pass"] else {"pass": False, "reason": "Sintaxe inválida"}
    disposable = check_disposable(domain)
    smtp     = check_smtp(email, mx.get("mx", "")) if mx.get("pass") and mx.get("mx") else {"pass": None, "reason": "MX não disponível"}

    score = calculate_score(syntax, mx, disposable, smtp)
    is_valid = score >= 50

    # Log
    db = get_db()
    db.execute(
        "INSERT INTO request_log (api_key, email, score, valid, timestamp) VALUES (?,?,?,?,?)",
        (request.api_key, email, score, int(is_valid), datetime.utcnow().isoformat())
    )
    db.commit()
    db.close()

    response = {
        "email": email,
        "valid": is_valid,
        "score": score,
        "disposable": disposable["disposable"],
        "checks": {
            "syntax": syntax["pass"],
            "mx_record": mx.get("pass"),
            "smtp": smtp.get("pass"),
        },
        "details": {
            "domain": domain,
            "mx_host": mx.get("mx"),
            "syntax_reason": syntax.get("reason"),
            "mx_reason": mx.get("reason"),
            "smtp_reason": smtp.get("reason"),
        },
        "plan": request.plan,
    }

    return jsonify(response)

@app.route("/validate/batch", methods=["POST"])
@require_api_key
def validate_batch():
    """Validação em batch — só planos basic e pro."""
    if request.plan == "free":
        return jsonify({"error": "Batch disponível em planos basic e pro."}), 403

    data = request.get_json(silent=True) or {}
    emails = data.get("emails", [])

    if not emails or not isinstance(emails, list):
        return jsonify({"error": "Passa uma lista 'emails'."}), 400

    if len(emails) > 50:
        return jsonify({"error": "Máximo 50 emails por batch request."}), 400

    results = []
    for email in emails:
        email = email.strip().lower()
        domain = email.split("@")[-1] if "@" in email else ""
        syntax = check_syntax(email)
        mx     = check_domain_mx(domain) if syntax["pass"] else {"pass": False}
        disp   = check_disposable(domain)
        smtp   = check_smtp(email, mx.get("mx", "")) if mx.get("pass") and mx.get("mx") else {"pass": None}
        score  = calculate_score(syntax, mx, disp, smtp)
        results.append({
            "email": email,
            "valid": score >= 50,
            "score": score,
            "disposable": disp["disposable"],
        })

    return jsonify({"results": results, "count": len(results)})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})

# ── Admin: gerar API keys (protegido por secret local) ─────────────────────────
ADMIN_SECRET = "admin123"
# ev_PfxQSrpt61F3EbxKvp_A1KE2UTAyG7Qt  --> 1ª chave para testar
# curl "http://localhost:5000/validate?email=teste@gmail.com&api_key=ev_PfxQSrpt61F3EbxKvp_A1KE2UTAyG7Qt"

@app.route("/admin/keys", methods=["POST"])
def create_key():
    secret = request.headers.get("X-Admin-Secret")
    if secret != ADMIN_SECRET:
        return jsonify({"error": "Não autorizado."}), 403

    data = request.get_json(silent=True) or {}
    plan = data.get("plan", "free")
    new_key = "ev_" + secrets.token_urlsafe(24)

    db = get_db()
    db.execute(
        "INSERT INTO api_keys (key, plan, requests_today, last_reset, created_at) VALUES (?,?,0,?,?)",
        (new_key, plan, datetime.utcnow().date().isoformat(), datetime.utcnow().isoformat())
    )
    db.commit()
    db.close()

    return jsonify({"api_key": new_key, "plan": plan}), 201

#if __name__ == "__main__":
#    init_db()
#    app.run(debug=True, port=5000)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
