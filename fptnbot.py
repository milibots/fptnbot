#!/usr/bin/env python3
"""
fptnbot.py — Telegram bot for FPTN VPN management
With per-user usage tracking (bytes up/down, sessions, last seen)
"""

import os, re, json, logging, subprocess, urllib.request
from pathlib import Path
from datetime import datetime

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, ConversationHandler, ContextTypes, filters
)
from telegram.constants import ParseMode

# =============================================================================
# Config
# =============================================================================
BOT_TOKEN   = os.environ["BOT_TOKEN"]
ADMIN_IDS   = set(int(x.strip()) for x in os.environ.get("ADMIN_IDS", "").split(",") if x.strip())
SERVER_IP   = os.environ.get("SERVER_IP", "")
SERVER_PORT = os.environ.get("SERVER_PORT", "443")
INSTALL_DIR = os.environ.get("INSTALL_DIR", "/opt/fptn")
DEFAULT_BW  = os.environ.get("VPN_DEFAULT_BW", "100")
BOT_DIR     = Path(os.environ.get("BOT_DIR", "/opt/fptnbot"))
DB_FILE     = BOT_DIR / "users.json"
USAGE_FILE  = BOT_DIR / "usage.json"
PROM_SECRET = os.environ.get("PROMETHEUS_SECRET_ACCESS_KEY", "")
PROM_URL    = "http://localhost:9091/metrics"

# =============================================================================
# Logging
# =============================================================================
logging.basicConfig(format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", level=logging.INFO)
log = logging.getLogger("fptnbot")

# =============================================================================
# Conversation states
# =============================================================================
AWAIT_USERNAME, AWAIT_PASSWORD, AWAIT_BW, AWAIT_DEL_USER, AWAIT_TOKEN_USER, AWAIT_TOKEN_PASS = range(6)

# =============================================================================
# User DB
# =============================================================================
def load_db() -> dict:
    if DB_FILE.exists():
        try: return json.loads(DB_FILE.read_text())
        except Exception: pass
    return {"pending": {}, "approved": {}}

def save_db(db: dict):
    BOT_DIR.mkdir(parents=True, exist_ok=True)
    DB_FILE.write_text(json.dumps(db, indent=2))

def db_pending_add(tid: int, data: dict):
    db = load_db(); db["pending"][str(tid)] = {**data, "requested_at": datetime.utcnow().isoformat()}; save_db(db)

def db_approve(tid: int, vpn_user: str):
    db = load_db()
    entry = db["pending"].pop(str(tid), {})
    db["approved"][str(tid)] = {**entry, "vpn_username": vpn_user, "approved_at": datetime.utcnow().isoformat()}
    save_db(db)

def db_deny(tid: int):
    db = load_db(); db["pending"].pop(str(tid), None); save_db(db)

def db_remove_approved(vpn_user: str):
    db = load_db()
    db["approved"] = {k: v for k, v in db["approved"].items() if v.get("vpn_username") != vpn_user}
    save_db(db)

def get_vpn_username(tid: int) -> str | None:
    entry = load_db()["approved"].get(str(tid)); return entry.get("vpn_username") if entry else None

# =============================================================================
# Usage DB
# =============================================================================
def load_usage() -> dict:
    if USAGE_FILE.exists():
        try: return json.loads(USAGE_FILE.read_text())
        except Exception: pass
    return {}

def save_usage(u: dict):
    BOT_DIR.mkdir(parents=True, exist_ok=True); USAGE_FILE.write_text(json.dumps(u, indent=2))

def init_usage_record(vpn_user: str):
    usage = load_usage()
    usage.setdefault(vpn_user, {"bytes_in": 0, "bytes_out": 0, "sessions": 0,
                                "last_seen": None, "first_seen": datetime.utcnow().isoformat()})
    save_usage(usage)

# =============================================================================
# Prometheus scraper
# =============================================================================
def fetch_prometheus() -> dict[str, dict]:
    results: dict[str, dict] = {}
    try:
        headers = {"Authorization": f"Bearer {PROM_SECRET}"} if PROM_SECRET else {}
        req = urllib.request.Request(PROM_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            text = resp.read().decode()
        for line in text.splitlines():
            if line.startswith("#") or not line: continue
            m = re.match(r'(fptn_\w+)\{[^}]*username="([^"]+)"[^}]*\}\s+([\d.e+]+)', line)
            if not m: continue
            metric, user, val = m.group(1), m.group(2), float(m.group(3))
            u = results.setdefault(user, {"bytes_in": 0, "bytes_out": 0, "active_sessions": 0})
            if "received" in metric or "bytes_in"  in metric: u["bytes_in"]  = int(val)
            elif "sent"  in metric or "bytes_out" in metric: u["bytes_out"] = int(val)
            elif "session" in metric or "active"  in metric: u["active_sessions"] = int(val)
    except Exception as e:
        log.debug("Prometheus scrape failed: %s", e)
    return results

def get_all_usage() -> dict[str, dict]:
    local = load_usage()
    live  = fetch_prometheus()
    for user, pdata in live.items():
        u = local.setdefault(user, {"bytes_in": 0, "bytes_out": 0, "sessions": 0, "last_seen": None, "first_seen": None})
        if pdata.get("bytes_in",  0) > u.get("bytes_in",  0): u["bytes_in"]  = pdata["bytes_in"]
        if pdata.get("bytes_out", 0) > u.get("bytes_out", 0): u["bytes_out"] = pdata["bytes_out"]
        u["active_sessions"] = pdata.get("active_sessions", 0)
    save_usage(local)
    return local

# =============================================================================
# Formatting
# =============================================================================
def fmt_bytes(n: int) -> str:
    if n == 0: return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024: return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def fmt_date(iso: str | None) -> str:
    if not iso: return "never"
    try: return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M UTC")
    except Exception: return iso

def esc(text: str) -> str:
    for ch in r"\_*[]()~`>#+-=|{}.!": text = text.replace(ch, f"\\{ch}")
    return text

def usage_lines(data: dict) -> str:
    b_in  = data.get("bytes_in",  0)
    b_out = data.get("bytes_out", 0)
    total = b_in + b_out
    active = data.get("active_sessions", 0)
    return (
        f"📥 Downloaded:      `{esc(fmt_bytes(b_in))}`\n"
        f"📤 Uploaded:        `{esc(fmt_bytes(b_out))}`\n"
        f"📊 Total:           `{esc(fmt_bytes(total))}`\n"
        f"🔗 Active sessions: `{active}`\n"
        f"🕐 Last seen:       `{esc(fmt_date(data.get('last_seen')))}`\n"
        f"📅 Member since:    `{esc(fmt_date(data.get('first_seen')))}`"
    )

# =============================================================================
# Auth
# =============================================================================
def is_admin(uid: int) -> bool: return uid in ADMIN_IDS
def is_approved(uid: int) -> bool: return str(uid) in load_db()["approved"]

# =============================================================================
# Keyboards
# =============================================================================
def admin_kb():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("👥 All Users",        callback_data="admin_users"),
         InlineKeyboardButton("➕ Add User",         callback_data="admin_add")],
        [InlineKeyboardButton("🗑 Delete User",      callback_data="admin_del"),
         InlineKeyboardButton("🔑 Gen Token",        callback_data="admin_token")],
        [InlineKeyboardButton("📊 Server Status",    callback_data="admin_status"),
         InlineKeyboardButton("🔄 Restart Server",   callback_data="admin_restart")],
        [InlineKeyboardButton("📬 Pending Requests", callback_data="admin_pending"),
         InlineKeyboardButton("📈 All Usage",        callback_data="admin_usage")],
    ])

def user_kb(approved: bool = False):
    rows = [[InlineKeyboardButton("📊 Server Status", callback_data="user_status")]]
    if approved:
        rows.append([InlineKeyboardButton("📈 My Usage", callback_data="user_usage")])
    else:
        rows.append([InlineKeyboardButton("🙋 Request Access", callback_data="user_request")])
    return InlineKeyboardMarkup(rows)

def cancel_kb():
    return InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="cancel")]])

# =============================================================================
# Docker helpers
# =============================================================================
def run_cmd(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired: return 1, "", "Timed out"
    except Exception as e: return 1, "", str(e)

def dc(*args, timeout=30): return run_cmd(["docker","compose","--project-directory",INSTALL_DIR]+list(args), timeout)

def vpn_add_user(username, password, bw=DEFAULT_BW) -> bool:
    run_cmd(["bash","-c", f"printf 'y\\n' | docker compose --project-directory {INSTALL_DIR} exec -i -T fptn-server fptn-passwd --del-user '{username}' 2>/dev/null || true"])
    try:
        r = subprocess.run(["docker","compose","--project-directory",INSTALL_DIR,"exec","-i","-T","fptn-server","fptn-passwd","--add-user",username,"--bandwidth",bw],
                           input=f"{password}\n{password}\n", capture_output=True, text=True, timeout=30)
        return r.returncode == 0
    except Exception as e: log.error("vpn_add_user: %s", e); return False

def vpn_del_user(username) -> bool:
    try:
        r = subprocess.run(["bash","-c", f"printf 'y\\n' | docker compose --project-directory {INSTALL_DIR} exec -i -T fptn-server fptn-passwd --del-user '{username}'"],
                           capture_output=True, text=True, timeout=30)
        return r.returncode == 0
    except Exception as e: log.error("vpn_del_user: %s", e); return False

def vpn_token(username, password) -> str | None:
    rc, out, _ = dc("run","--rm","fptn-server","token-generator","--user",username,"--password",password,"--server-ip",SERVER_IP,"--port",SERVER_PORT, timeout=60)
    for line in out.splitlines():
        if line.startswith("fptn:"): return line.strip()
    return None

def container_running() -> bool:
    rc, out, _ = dc("ps","-q","fptn-server"); return rc == 0 and bool(out.strip())
def server_uptime() -> str: _, o, _ = run_cmd(["uptime","-p"]); return o or "unknown"
def server_load() -> str:
    try: return " / ".join(Path("/proc/loadavg").read_text().split()[:3])
    except: return "unknown"
def sanitize(name: str) -> str: return re.sub(r"[^a-zA-Z0-9_\-]","",name)[:32]

# =============================================================================
# /start
# =============================================================================
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid  = update.effective_user.id
    name = update.effective_user.first_name or "there"
    if is_admin(uid):
        await update.message.reply_text(f"👋 Welcome back, *{esc(name)}*\\! You're an admin\\.", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_kb())
    elif is_approved(uid):
        vpn = get_vpn_username(uid) or "?"
        await update.message.reply_text(f"👋 Welcome, *{esc(name)}*\\!\nVPN account: `{esc(vpn)}`\n\nUse /usage to see your data usage\\.", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=user_kb(approved=True))
    else:
        await update.message.reply_text(f"👋 Hello, *{esc(name)}*\\!\nYou don't have VPN access yet\\.", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=user_kb(approved=False))

# =============================================================================
# Status
# =============================================================================
async def show_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    send  = query.edit_message_text if query else update.message.reply_text
    if query: await query.answer()
    uid = update.effective_user.id
    db  = load_db()
    text = (f"*📊 FPTN Server Status*\n\n"
            f"{'🟢 Running' if container_running() else '🔴 Stopped'}\n"
            f"IP: `{esc(SERVER_IP)}`  Port: `{esc(SERVER_PORT)}`\n"
            f"Approved users: `{len(db['approved'])}`\n"
            f"Uptime: `{esc(server_uptime())}`\n"
            f"Load: `{esc(server_load())}`")
    back = "back_admin" if is_admin(uid) else "back_user"
    await send(text, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data=back)]]))

# =============================================================================
# Usage — user
# =============================================================================
async def cb_user_usage(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    uid = query.from_user.id
    if not (is_approved(uid) or is_admin(uid)):
        await query.edit_message_text("❌ You don't have VPN access yet\\.", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=user_kb()); return
    vpn = get_vpn_username(uid)
    if not vpn:
        await query.edit_message_text("⚠️ Could not find your VPN username\\.", parse_mode=ParseMode.MARKDOWN_V2); return
    data = get_all_usage().get(vpn, {})
    text = f"*📈 Your VPN Usage*\nAccount: `{esc(vpn)}`\n\n" + usage_lines(data)
    await query.edit_message_text(text, parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔄 Refresh", callback_data="user_usage"),
                                           InlineKeyboardButton("🔙 Back",    callback_data="back_user")]]))

# =============================================================================
# Usage — admin (all users)
# =============================================================================
async def cb_admin_usage(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    if not is_admin(query.from_user.id): return
    db = load_db(); approved = db["approved"]
    if not approved:
        await query.edit_message_text("📈 No approved users yet\\.", parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="back_admin")]])); return

    all_usage = get_all_usage()
    lines = ["*📈 Usage — All Users*\n"]
    for tid, info in approved.items():
        vpn  = info.get("vpn_username", "?")
        name = info.get("first_name", "?")
        data = all_usage.get(vpn, {})
        b_in  = data.get("bytes_in",  0)
        b_out = data.get("bytes_out", 0)
        total = b_in + b_out
        active = data.get("active_sessions", 0)
        last   = fmt_date(data.get("last_seen"))
        icon   = "🔗" if active else "💤"
        lines.append(
            f"{icon} *{esc(vpn)}* \\({esc(name)}\\)\n"
            f"  ↓ `{esc(fmt_bytes(b_in))}`  ↑ `{esc(fmt_bytes(b_out))}`  Total: `{esc(fmt_bytes(total))}`\n"
            f"  Last seen: `{esc(last)}`"
        )

    full = "\n\n".join(lines)
    if len(full) > 4000: full = full[:3900] + "\n\n_\\.\\.\\. truncated_"
    await query.edit_message_text(full, parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔄 Refresh", callback_data="admin_usage"),
                                           InlineKeyboardButton("🔙 Back",    callback_data="back_admin")]]))

# =============================================================================
# /usage command
# =============================================================================
async def cmd_usage(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if is_admin(uid):
        db = load_db(); all_usage = get_all_usage()
        lines = ["*📈 Usage — All Users*\n"]
        for tid, info in db["approved"].items():
            vpn  = info.get("vpn_username", "?")
            name = info.get("first_name", "?")
            data = all_usage.get(vpn, {})
            total = data.get("bytes_in", 0) + data.get("bytes_out", 0)
            last  = fmt_date(data.get("last_seen"))
            active = data.get("active_sessions", 0)
            icon = "🔗" if active else "💤"
            lines.append(f"{icon} *{esc(vpn)}* \\({esc(name)}\\) — `{esc(fmt_bytes(total))}` — Last: `{esc(last)}`")
        await update.message.reply_text("\n\n".join(lines) if db["approved"] else "No users yet\\.", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_kb())
    elif is_approved(uid):
        vpn  = get_vpn_username(uid); data = get_all_usage().get(vpn or "", {})
        text = f"*📈 Your VPN Usage*\nAccount: `{esc(vpn or '?')}`\n\n" + usage_lines(data)
        await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=user_kb(approved=True))
    else:
        await update.message.reply_text("❌ You don't have VPN access yet\\.", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=user_kb())

# =============================================================================
# Access request
# =============================================================================
async def cb_user_request(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    uid = query.from_user.id
    if is_approved(uid) or is_admin(uid):
        await query.edit_message_text("✅ You already have access\\.", parse_mode=ParseMode.MARKDOWN_V2); return
    db = load_db()
    if str(uid) in db["pending"]:
        await query.edit_message_text("⏳ Your request is already pending\\.", parse_mode=ParseMode.MARKDOWN_V2); return
    user = query.from_user
    db_pending_add(uid, {"first_name": user.first_name or "", "username": user.username or ""})
    for aid in ADMIN_IDS:
        try:
            await ctx.bot.send_message(aid,
                f"🔔 *New VPN access request*\n\nName: {esc(user.first_name or 'N/A')}\n"
                f"@{esc(user.username or 'N/A')}\nID: `{uid}`",
                parse_mode=ParseMode.MARKDOWN_V2,
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("✅ Approve", callback_data=f"approve_{uid}"),
                                                    InlineKeyboardButton("❌ Deny",    callback_data=f"deny_{uid}")]]))
        except Exception as e: log.warning("Notify admin %s: %s", aid, e)
    await query.edit_message_text("✅ Request sent\\. You'll be notified once approved\\.", parse_mode=ParseMode.MARKDOWN_V2)

# =============================================================================
# Approve / deny
# =============================================================================
async def cb_approve(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    if not is_admin(query.from_user.id): return
    target = int(query.data.split("_")[1])
    entry  = load_db()["pending"].get(str(target))
    if not entry:
        await query.edit_message_text("⚠️ Request no longer exists\\.", parse_mode=ParseMode.MARKDOWN_V2); return
    raw      = entry.get("username") or entry.get("first_name") or str(target)
    vpn_user = sanitize(raw) or f"user{target}"
    vpn_pass = f"fptn{target}"
    await query.edit_message_text(f"⏳ Creating `{esc(vpn_user)}`…", parse_mode=ParseMode.MARKDOWN_V2)
    if not vpn_add_user(vpn_user, vpn_pass):
        await query.edit_message_text("❌ Failed to create VPN account\\. Check server logs\\.", parse_mode=ParseMode.MARKDOWN_V2); return
    db_approve(target, vpn_user); init_usage_record(vpn_user)
    token = vpn_token(vpn_user, vpn_pass)
    try:
        msg = f"✅ *VPN access approved\\!*\n\nUsername: `{esc(vpn_user)}`\n"
        if token: msg += f"\n*Token:*\n`{esc(token)}`\n\n_Import into your FPTN client\\._"
        else: msg += "\n_Token generation failed — contact admin\\._"
        await ctx.bot.send_message(target, msg, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=user_kb(approved=True))
    except Exception as e: log.warning("Notify user: %s", e)
    await query.edit_message_text(f"✅ Approved `{esc(vpn_user)}`\\. Token sent\\.", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_kb())

async def cb_deny(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    if not is_admin(query.from_user.id): return
    target = int(query.data.split("_")[1]); db_deny(target)
    try: await ctx.bot.send_message(target, "❌ Your VPN access request was denied\\.", parse_mode=ParseMode.MARKDOWN_V2)
    except Exception: pass
    await query.edit_message_text(f"🗑 Denied ID `{target}`\\.", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_kb())

# =============================================================================
# Admin: all users list
# =============================================================================
async def cb_admin_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    if not is_admin(query.from_user.id): return
    db = load_db(); all_usage = get_all_usage()
    lines = ["*👥 VPN Users*\n"]
    if db["approved"]:
        lines.append("*Approved:*")
        for tid, info in db["approved"].items():
            vpn  = info.get("vpn_username", "?"); name = info.get("first_name", "?")
            data = all_usage.get(vpn, {}); active = data.get("active_sessions", 0)
            total = data.get("bytes_in", 0) + data.get("bytes_out", 0)
            icon = "🔗" if active else "💤"
            lines.append(f"  {icon} `{esc(vpn)}` — {esc(name)} — `{esc(fmt_bytes(total))}`")
    else: lines.append("No approved users yet\\.")
    if db["pending"]:
        lines.append("\n*Pending:*")
        for tid, info in db["pending"].items(): lines.append(f"  ⏳ {esc(info.get('first_name','?'))} \\(ID: `{tid}`\\)")
    await query.edit_message_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("📈 Usage", callback_data="admin_usage"),
                                           InlineKeyboardButton("🔙 Back",  callback_data="back_admin")]]))

# =============================================================================
# Admin: pending
# =============================================================================
async def cb_admin_pending(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    if not is_admin(query.from_user.id): return
    pending = load_db()["pending"]
    if not pending:
        await query.edit_message_text("📬 No pending requests\\.", parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="back_admin")]])); return
    buttons = []
    for tid, info in pending.items():
        name = info.get("first_name","?"); uname = info.get("username","")
        label = f"{name} (@{uname})" if uname else name
        buttons.append([InlineKeyboardButton(f"✅ {label}", callback_data=f"approve_{tid}"),
                        InlineKeyboardButton("❌", callback_data=f"deny_{tid}")])
    buttons.append([InlineKeyboardButton("🔙 Back", callback_data="back_admin")])
    await query.edit_message_text(f"*📬 Pending Requests* \\({len(pending)}\\)", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=InlineKeyboardMarkup(buttons))

# =============================================================================
# Admin: restart
# =============================================================================
async def cb_admin_restart(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    if not is_admin(query.from_user.id): return
    await query.edit_message_text("🔄 Restarting FPTN server…")
    rc, _, err = dc("restart","fptn-server", timeout=60)
    msg = "✅ Server restarted\\." if rc == 0 else f"❌ Failed:\n```\n{esc(err[:300])}\n```"
    await query.edit_message_text(msg, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_kb())

# =============================================================================
# Add user conversation
# =============================================================================
async def cb_admin_add(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    if not is_admin(query.from_user.id): return
    await query.edit_message_text("👤 Enter VPN *username* to create:", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_kb())
    return AWAIT_USERNAME

async def recv_username(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["new_username"] = sanitize(update.message.text.strip())
    if not ctx.user_data["new_username"]:
        await update.message.reply_text("⚠️ Invalid\\. Letters/numbers/\\-/\\_ only:", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_kb()); return AWAIT_USERNAME
    await update.message.reply_text(f"🔒 Enter *password* for `{esc(ctx.user_data['new_username'])}`:", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_kb())
    return AWAIT_PASSWORD

async def recv_password(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pw = update.message.text.strip()
    if len(pw) < 6:
        await update.message.reply_text("⚠️ Min 6 characters:", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_kb()); return AWAIT_PASSWORD
    ctx.user_data["new_password"] = pw
    await update.message.reply_text(f"📶 Bandwidth in Mbps? \\(default: {DEFAULT_BW}\\):", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_kb())
    return AWAIT_BW

async def recv_bw(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    bw = update.message.text.strip() or DEFAULT_BW
    if not bw.isdigit():
        await update.message.reply_text("⚠️ Enter a number:", reply_markup=cancel_kb()); return AWAIT_BW
    username = ctx.user_data["new_username"]; password = ctx.user_data["new_password"]
    await update.message.reply_text(f"⏳ Creating `{esc(username)}`…", parse_mode=ParseMode.MARKDOWN_V2)
    if not vpn_add_user(username, password, bw):
        await update.message.reply_text("❌ Failed\\.", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_kb()); return ConversationHandler.END
    init_usage_record(username)
    token = vpn_token(username, password)
    msg = f"✅ User `{esc(username)}` created\\!\n\n"
    if token: msg += f"*Token:*\n`{esc(token)}`"
    else: msg += "_Token generation failed — retry with Gen Token\\._"
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_kb())
    return ConversationHandler.END

# =============================================================================
# Delete user conversation
# =============================================================================
async def cb_admin_del(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    if not is_admin(query.from_user.id): return
    await query.edit_message_text("🗑 Enter VPN *username* to delete:", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_kb())
    return AWAIT_DEL_USER

async def recv_del_user(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    username = sanitize(update.message.text.strip())
    ok = vpn_del_user(username); db_remove_approved(username)
    status = "✅ Deleted" if ok else "⚠️ Could not delete \\(may not exist\\)"
    await update.message.reply_text(f"{status}: `{esc(username)}`", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_kb())
    return ConversationHandler.END

# =============================================================================
# Generate token conversation
# =============================================================================
async def cb_admin_token(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    if not is_admin(query.from_user.id): return
    await query.edit_message_text("🔑 Enter VPN *username*:", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_kb())
    return AWAIT_TOKEN_USER

async def recv_token_user(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["token_username"] = sanitize(update.message.text.strip())
    await update.message.reply_text("🔒 Enter VPN *password*:", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_kb())
    return AWAIT_TOKEN_PASS

async def recv_token_pass(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    username = ctx.user_data["token_username"]; password = update.message.text.strip()
    token = vpn_token(username, password)
    if token: msg = f"✅ Token for `{esc(username)}`:\n\n`{esc(token)}`"
    else: msg = "❌ Token generation failed\\. Check username/password\\."
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_kb())
    return ConversationHandler.END

# =============================================================================
# Navigation
# =============================================================================
async def cb_back_admin(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    await query.edit_message_text("What would you like to do?", reply_markup=admin_kb())

async def cb_back_user(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    uid = query.from_user.id
    await query.edit_message_text("What would you like to do?", reply_markup=user_kb(approved=is_approved(uid)))

async def cb_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    uid = query.from_user.id
    kb = admin_kb() if is_admin(uid) else user_kb(approved=is_approved(uid))
    await query.edit_message_text("❌ Cancelled\\.", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=kb)
    return ConversationHandler.END

# =============================================================================
# Callback router
# =============================================================================
async def cb_router(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    data = update.callback_query.data
    routes = {
        "user_status": show_status, "admin_status": show_status,
        "user_usage":  cb_user_usage, "admin_usage": cb_admin_usage,
        "user_request": cb_user_request,
        "admin_users":  cb_admin_users, "admin_pending": cb_admin_pending,
        "admin_restart": cb_admin_restart,
        "back_admin": cb_back_admin, "back_user": cb_back_user, "cancel": cb_cancel,
    }
    if data in routes: await routes[data](update, ctx)
    elif data.startswith("approve_"): await cb_approve(update, ctx)
    elif data.startswith("deny_"):    await cb_deny(update, ctx)

# =============================================================================
# Periodic usage sync
# =============================================================================
async def periodic_usage_sync(ctx: ContextTypes.DEFAULT_TYPE):
    try: get_all_usage(); log.debug("Usage sync OK.")
    except Exception as e: log.warning("Usage sync error: %s", e)

# =============================================================================
# Main
# =============================================================================
def main():
    log.info("Starting fptnbot — admins: %s", ADMIN_IDS)
    app = Application.builder().token(BOT_TOKEN).build()

    add_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(cb_admin_add,   pattern="^admin_add$")],
        states={AWAIT_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_username)],
                AWAIT_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_password)],
                AWAIT_BW:       [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_bw)]},
        fallbacks=[CallbackQueryHandler(cb_cancel, pattern="^cancel$")], allow_reentry=True)

    del_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(cb_admin_del,   pattern="^admin_del$")],
        states={AWAIT_DEL_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_del_user)]},
        fallbacks=[CallbackQueryHandler(cb_cancel, pattern="^cancel$")], allow_reentry=True)

    token_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(cb_admin_token, pattern="^admin_token$")],
        states={AWAIT_TOKEN_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_token_user)],
                AWAIT_TOKEN_PASS: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_token_pass)]},
        fallbacks=[CallbackQueryHandler(cb_cancel, pattern="^cancel$")], allow_reentry=True)

    app.add_handler(CommandHandler("start",  cmd_start))
    app.add_handler(CommandHandler("status", show_status))
    app.add_handler(CommandHandler("usage",  cmd_usage))
    app.add_handler(add_conv)
    app.add_handler(del_conv)
    app.add_handler(token_conv)
    app.add_handler(CallbackQueryHandler(cb_router))
    app.job_queue.run_repeating(periodic_usage_sync, interval=300, first=30)

    log.info("Bot polling started.")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
