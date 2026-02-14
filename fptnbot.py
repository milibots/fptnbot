#!/usr/bin/env python3
"""
fptnbot.py — Telegram bot for FPTN VPN management
Reads config from environment (loaded via systemd EnvironmentFile)
"""

import os
import re
import asyncio
import logging
import subprocess
import json
from pathlib import Path
from datetime import datetime

from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, BotCommand
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, ConversationHandler, ContextTypes, filters
)
from telegram.constants import ParseMode

# =============================================================================
# Config (from environment / EnvironmentFile)
# =============================================================================
BOT_TOKEN    = os.environ["BOT_TOKEN"]
ADMIN_IDS    = set(int(x.strip()) for x in os.environ.get("ADMIN_IDS", "").split(",") if x.strip())
SERVER_IP    = os.environ.get("SERVER_IP", "")
SERVER_PORT  = os.environ.get("SERVER_PORT", "443")
INSTALL_DIR  = os.environ.get("INSTALL_DIR", "/opt/fptn")
DEFAULT_BW   = os.environ.get("VPN_DEFAULT_BW", "100")
DB_FILE      = Path(os.environ.get("BOT_DIR", "/opt/fptnbot")) / "users.json"

# =============================================================================
# Logging
# =============================================================================
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO
)
log = logging.getLogger("fptnbot")

# =============================================================================
# Conversation states
# =============================================================================
(
    AWAIT_USERNAME,
    AWAIT_PASSWORD,
    AWAIT_BW,
    AWAIT_DEL_USER,
    AWAIT_TOKEN_USER,
    AWAIT_TOKEN_PASS,
    AWAIT_APPROVE_ID,
) = range(7)

# =============================================================================
# Persistent user DB (simple JSON file)
# =============================================================================
def load_db() -> dict:
    if DB_FILE.exists():
        try:
            return json.loads(DB_FILE.read_text())
        except Exception:
            pass
    return {"pending": {}, "approved": {}}

def save_db(db: dict):
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    DB_FILE.write_text(json.dumps(db, indent=2))

def db_pending_add(telegram_id: int, data: dict):
    db = load_db()
    db["pending"][str(telegram_id)] = {**data, "requested_at": datetime.utcnow().isoformat()}
    save_db(db)

def db_approve(telegram_id: int, vpn_username: str):
    db = load_db()
    entry = db["pending"].pop(str(telegram_id), {})
    db["approved"][str(telegram_id)] = {
        **entry,
        "vpn_username": vpn_username,
        "approved_at": datetime.utcnow().isoformat()
    }
    save_db(db)

def db_deny(telegram_id: int):
    db = load_db()
    db["pending"].pop(str(telegram_id), None)
    save_db(db)

def db_remove_approved(vpn_username: str):
    db = load_db()
    db["approved"] = {k: v for k, v in db["approved"].items()
                      if v.get("vpn_username") != vpn_username}
    save_db(db)

# =============================================================================
# Docker / FPTN helpers
# =============================================================================
def run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a shell command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)

def dc(*args, timeout: int = 30) -> tuple[int, str, str]:
    return run(["docker", "compose", "--project-directory", INSTALL_DIR] + list(args), timeout=timeout)

def vpn_add_user(username: str, password: str, bw: str = DEFAULT_BW) -> bool:
    """Add a VPN user non-interactively."""
    # Remove if exists
    run(["bash", "-c",
         f"printf 'y\\n' | docker compose --project-directory {INSTALL_DIR} "
         f"exec -i -T fptn-server fptn-passwd --del-user '{username}' 2>/dev/null || true"])
    # Add
    inp = f"{password}\n{password}\n"
    try:
        r = subprocess.run(
            ["docker", "compose", "--project-directory", INSTALL_DIR,
             "exec", "-i", "-T", "fptn-server",
             "fptn-passwd", "--add-user", username, "--bandwidth", bw],
            input=inp, capture_output=True, text=True, timeout=30
        )
        return r.returncode == 0
    except Exception as e:
        log.error("vpn_add_user error: %s", e)
        return False

def vpn_del_user(username: str) -> bool:
    try:
        r = subprocess.run(
            ["bash", "-c",
             f"printf 'y\\n' | docker compose --project-directory {INSTALL_DIR} "
             f"exec -i -T fptn-server fptn-passwd --del-user '{username}'"],
            capture_output=True, text=True, timeout=30
        )
        return r.returncode == 0
    except Exception as e:
        log.error("vpn_del_user error: %s", e)
        return False

def vpn_generate_token(username: str, password: str) -> str | None:
    rc, out, err = dc(
        "run", "--rm", "fptn-server", "token-generator",
        "--user", username, "--password", password,
        "--server-ip", SERVER_IP, "--port", SERVER_PORT,
        timeout=60
    )
    for line in out.splitlines():
        if line.startswith("fptn:"):
            return line.strip()
    return None

def vpn_server_status() -> str:
    rc, out, _ = dc("ps", "--format", "json")
    if rc != 0 or not out:
        rc2, out2, _ = dc("ps")
        return out2 or "Could not retrieve status."
    return out

def server_uptime() -> str:
    _, out, _ = run(["uptime", "-p"])
    return out or "unknown"

def server_load() -> str:
    try:
        load = Path("/proc/loadavg").read_text().split()[:3]
        return " / ".join(load)
    except Exception:
        return "unknown"

def container_running() -> bool:
    rc, out, _ = dc("ps", "-q", "fptn-server")
    return rc == 0 and bool(out.strip())

def import_password(password: str) -> bool:
    # Basic validation only — actual auth is done by the container
    return bool(password) and len(password) >= 6

def sanitize_username(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_\-]", "", name)[:32]

# =============================================================================
# Auth helpers
# =============================================================================
def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

def is_approved(user_id: int) -> bool:
    db = load_db()
    return str(user_id) in db["approved"]

# =============================================================================
# Keyboards
# =============================================================================
def admin_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("👥 All Users",      callback_data="admin_users"),
         InlineKeyboardButton("➕ Add User",       callback_data="admin_add")],
        [InlineKeyboardButton("🗑 Delete User",    callback_data="admin_del"),
         InlineKeyboardButton("🔑 Gen Token",      callback_data="admin_token")],
        [InlineKeyboardButton("📊 Server Status",  callback_data="admin_status"),
         InlineKeyboardButton("🔄 Restart Server", callback_data="admin_restart")],
        [InlineKeyboardButton("📬 Pending Requests", callback_data="admin_pending")],
    ])

def user_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📊 Server Status",   callback_data="user_status")],
        [InlineKeyboardButton("🙋 Request Access",  callback_data="user_request")],
    ])

def cancel_keyboard():
    return InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="cancel")]])

# =============================================================================
# /start
# =============================================================================
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    name = update.effective_user.first_name or "there"

    if is_admin(uid):
        await update.message.reply_text(
            f"👋 Welcome back, *{name}*\\! You're an admin\\.\n\nWhat would you like to do?",
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=admin_keyboard()
        )
    elif is_approved(uid):
        db = load_db()
        vpn_user = db["approved"][str(uid)].get("vpn_username", "")
        await update.message.reply_text(
            f"👋 Welcome, *{name}*\\!\n\n"
            f"Your VPN account: `{vpn_user}`\n\n"
            "Use /token to get your access token\\.",
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=user_keyboard()
        )
    else:
        await update.message.reply_text(
            f"👋 Hello, *{name}*\\!\n\n"
            "You don't have VPN access yet\\. "
            "Press the button below to request access from the admin\\.",
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🙋 Request Access", callback_data="user_request")
            ]])
        )

# =============================================================================
# Server status
# =============================================================================
async def show_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if query:
        await query.answer()
        send = query.edit_message_text
    else:
        send = update.message.reply_text

    running = container_running()
    status_icon = "🟢 Running" if running else "🔴 Stopped"
    db = load_db()
    user_count = len(db["approved"])

    text = (
        f"*📊 FPTN Server Status*\n\n"
        f"Container: {status_icon}\n"
        f"Server IP: `{SERVER_IP}`\n"
        f"Port: `{SERVER_PORT}`\n"
        f"Approved users: `{user_count}`\n"
        f"Server uptime: `{server_uptime()}`\n"
        f"Load avg: `{server_load()}`"
    )
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="back_admin" if is_admin(update.effective_user.id) else "back_user")]])
    await send(text, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=kb)

# =============================================================================
# Access request flow
# =============================================================================
async def cb_user_request(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    uid = query.from_user.id

    if is_approved(uid) or is_admin(uid):
        await query.edit_message_text("✅ You already have access.")
        return

    db = load_db()
    if str(uid) in db["pending"]:
        await query.edit_message_text("⏳ Your request is already pending admin approval.")
        return

    user = query.from_user
    db_pending_add(uid, {
        "first_name": user.first_name or "",
        "username": user.username or "",
    })

    # Notify all admins
    for admin_id in ADMIN_IDS:
        try:
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton(f"✅ Approve", callback_data=f"approve_{uid}"),
                 InlineKeyboardButton(f"❌ Deny",    callback_data=f"deny_{uid}")]
            ])
            await ctx.bot.send_message(
                admin_id,
                f"🔔 *New VPN access request*\n\n"
                f"Name: {user.first_name or 'N/A'}\n"
                f"Username: @{user.username or 'N/A'}\n"
                f"Telegram ID: `{uid}`",
                parse_mode=ParseMode.MARKDOWN_V2,
                reply_markup=kb
            )
        except Exception as e:
            log.warning("Could not notify admin %s: %s", admin_id, e)

    await query.edit_message_text(
        "✅ Your request has been sent to the admin\\.\n\n"
        "You'll be notified once it's approved\\.",
        parse_mode=ParseMode.MARKDOWN_V2
    )

# =============================================================================
# Admin: approve / deny
# =============================================================================
async def cb_approve(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if not is_admin(query.from_user.id):
        await query.answer("Not authorized.", show_alert=True); return

    target_id = int(query.data.split("_")[1])
    db = load_db()
    entry = db["pending"].get(str(target_id))
    if not entry:
        await query.edit_message_text("⚠️ Request no longer exists."); return

    # Generate VPN username from their Telegram info
    raw = entry.get("username") or entry.get("first_name") or str(target_id)
    vpn_user = sanitize_username(raw) or f"user{target_id}"
    vpn_pass = f"fptn{target_id}"  # Deterministic — admin can reset via /adduser

    ctx.user_data["approve_target_id"] = target_id
    ctx.user_data["approve_vpn_user"]  = vpn_user
    ctx.user_data["approve_vpn_pass"]  = vpn_pass

    # Create VPN account
    await query.edit_message_text(f"⏳ Creating VPN account for `{vpn_user}`…", parse_mode=ParseMode.MARKDOWN_V2)
    ok = vpn_add_user(vpn_user, vpn_pass)
    if not ok:
        await query.edit_message_text(f"❌ Failed to create VPN account for `{vpn_user}`\\. Check server logs\\.", parse_mode=ParseMode.MARKDOWN_V2)
        return

    db_approve(target_id, vpn_user)

    # Generate token
    token = vpn_generate_token(vpn_user, vpn_pass)

    # Notify user
    try:
        msg = (
            "✅ *Your VPN access has been approved\\!*\n\n"
            f"VPN Username: `{vpn_user}`\n"
        )
        if token:
            msg += f"\n*Your access token:*\n`{token}`\n\n_Copy this token into your FPTN client\\._"
        else:
            msg += "\n_Token generation failed — contact admin\\._"
        await ctx.bot.send_message(target_id, msg, parse_mode=ParseMode.MARKDOWN_V2)
    except Exception as e:
        log.warning("Could not notify approved user %s: %s", target_id, e)

    await query.edit_message_text(
        f"✅ Approved `{vpn_user}` \\(ID: `{target_id}`\\)\\. Token sent to user\\.",
        parse_mode=ParseMode.MARKDOWN_V2
    )

async def cb_deny(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if not is_admin(query.from_user.id):
        await query.answer("Not authorized.", show_alert=True); return

    target_id = int(query.data.split("_")[1])
    db_deny(target_id)

    try:
        await ctx.bot.send_message(target_id, "❌ Your VPN access request was denied.")
    except Exception:
        pass

    await query.edit_message_text(f"🗑 Denied request from ID `{target_id}`\\.", parse_mode=ParseMode.MARKDOWN_V2)

# =============================================================================
# Admin: show all users
# =============================================================================
async def cb_admin_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if not is_admin(query.from_user.id):
        return

    db = load_db()
    approved = db["approved"]
    pending  = db["pending"]

    lines = ["*👥 VPN Users*\n"]
    if approved:
        lines.append("*Approved:*")
        for tid, info in approved.items():
            vpn = info.get("vpn_username", "?")
            name = info.get("first_name", "?")
            lines.append(f"  • `{vpn}` — {name} \\(ID: `{tid}`\\)")
    else:
        lines.append("No approved users yet\\.")

    if pending:
        lines.append("\n*Pending:*")
        for tid, info in pending.items():
            name = info.get("first_name", "?")
            lines.append(f"  • {name} \\(ID: `{tid}`\\)")

    kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="back_admin")]])
    await query.edit_message_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN_V2, reply_markup=kb)

# =============================================================================
# Admin: pending requests list
# =============================================================================
async def cb_admin_pending(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if not is_admin(query.from_user.id):
        return

    db = load_db()
    pending = db["pending"]
    if not pending:
        await query.edit_message_text(
            "📬 No pending requests\\.",
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="back_admin")]])
        )
        return

    buttons = []
    for tid, info in pending.items():
        name = info.get("first_name", "?")
        uname = info.get("username", "")
        label = f"{name} (@{uname})" if uname else name
        buttons.append([
            InlineKeyboardButton(f"✅ {label}", callback_data=f"approve_{tid}"),
            InlineKeyboardButton("❌",           callback_data=f"deny_{tid}")
        ])
    buttons.append([InlineKeyboardButton("🔙 Back", callback_data="back_admin")])
    await query.edit_message_text(
        f"*📬 Pending Requests* \\({len(pending)}\\)",
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=InlineKeyboardMarkup(buttons)
    )

# =============================================================================
# Admin: add user (conversation)
# =============================================================================
async def cb_admin_add(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if not is_admin(query.from_user.id): return
    await query.edit_message_text("👤 Enter the VPN *username* to create:", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_keyboard())
    return AWAIT_USERNAME

async def recv_username(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["new_username"] = sanitize_username(update.message.text.strip())
    if not ctx.user_data["new_username"]:
        await update.message.reply_text("⚠️ Invalid username. Letters, numbers, _ and - only. Try again:", reply_markup=cancel_keyboard())
        return AWAIT_USERNAME
    await update.message.reply_text(f"🔒 Enter a *password* for `{ctx.user_data['new_username']}`:", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_keyboard())
    return AWAIT_PASSWORD

async def recv_password(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pw = update.message.text.strip()
    if len(pw) < 6:
        await update.message.reply_text("⚠️ Password must be at least 6 characters. Try again:", reply_markup=cancel_keyboard())
        return AWAIT_PASSWORD
    ctx.user_data["new_password"] = pw
    await update.message.reply_text(f"📶 Bandwidth in Mbps? \\(default: {DEFAULT_BW}\\):", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_keyboard())
    return AWAIT_BW

async def recv_bw(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    bw = update.message.text.strip() or DEFAULT_BW
    if not bw.isdigit():
        await update.message.reply_text("⚠️ Enter a number (e.g. 100):", reply_markup=cancel_keyboard())
        return AWAIT_BW

    username = ctx.user_data["new_username"]
    password = ctx.user_data["new_password"]

    await update.message.reply_text(f"⏳ Creating VPN user `{username}`…", parse_mode=ParseMode.MARKDOWN_V2)
    ok = vpn_add_user(username, password, bw)
    if not ok:
        await update.message.reply_text("❌ Failed to create user. Check server logs.", reply_markup=admin_keyboard())
        return ConversationHandler.END

    token = vpn_generate_token(username, password)
    msg = f"✅ User `{username}` created\\!\n\n"
    if token:
        msg += f"*Token:*\n`{token}`"
    else:
        msg += "_Token generation failed — use /gentoken to retry\\._"
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_keyboard())
    return ConversationHandler.END

# =============================================================================
# Admin: delete user (conversation)
# =============================================================================
async def cb_admin_del(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if not is_admin(query.from_user.id): return
    await query.edit_message_text("🗑 Enter the VPN *username* to delete:", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_keyboard())
    return AWAIT_DEL_USER

async def recv_del_user(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    username = sanitize_username(update.message.text.strip())
    await update.message.reply_text(f"⏳ Deleting `{username}`…", parse_mode=ParseMode.MARKDOWN_V2)
    ok = vpn_del_user(username)
    db_remove_approved(username)
    if ok:
        await update.message.reply_text(f"✅ User `{username}` deleted\\.", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_keyboard())
    else:
        await update.message.reply_text(f"⚠️ Could not delete `{username}` \\(may not exist\\)\\.", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_keyboard())
    return ConversationHandler.END

# =============================================================================
# Admin: generate token (conversation)
# =============================================================================
async def cb_admin_token(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if not is_admin(query.from_user.id): return
    await query.edit_message_text("🔑 Enter VPN *username*:", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_keyboard())
    return AWAIT_TOKEN_USER

async def recv_token_user(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["token_username"] = sanitize_username(update.message.text.strip())
    await update.message.reply_text("🔒 Enter the VPN *password*:", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_keyboard())
    return AWAIT_TOKEN_PASS

async def recv_token_pass(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    username = ctx.user_data["token_username"]
    password = update.message.text.strip()
    await update.message.reply_text(f"⏳ Generating token for `{username}`…", parse_mode=ParseMode.MARKDOWN_V2)
    token = vpn_generate_token(username, password)
    if token:
        await update.message.reply_text(
            f"✅ Token for `{username}`:\n\n`{token}`",
            parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_keyboard()
        )
    else:
        await update.message.reply_text(
            "❌ Token generation failed\\. Check username/password and server status\\.",
            parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_keyboard()
        )
    return ConversationHandler.END

# =============================================================================
# Admin: restart server
# =============================================================================
async def cb_admin_restart(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if not is_admin(query.from_user.id): return
    await query.edit_message_text("🔄 Restarting FPTN server…")
    rc, out, err = dc("restart", "fptn-server", timeout=60)
    if rc == 0:
        await query.edit_message_text("✅ Server restarted successfully\\.", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_keyboard())
    else:
        await query.edit_message_text(f"❌ Restart failed:\n```\n{err[:300]}\n```", parse_mode=ParseMode.MARKDOWN_V2, reply_markup=admin_keyboard())

# =============================================================================
# Navigation callbacks
# =============================================================================
async def cb_back_admin(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await query.edit_message_text("What would you like to do?", reply_markup=admin_keyboard())

async def cb_back_user(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await query.edit_message_text("What would you like to do?", reply_markup=user_keyboard())

async def cb_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    uid = query.from_user.id
    kb = admin_keyboard() if is_admin(uid) else user_keyboard()
    await query.edit_message_text("❌ Cancelled.", reply_markup=kb)
    return ConversationHandler.END

# =============================================================================
# /status command (direct)
# =============================================================================
async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await show_status(update, ctx)

# =============================================================================
# Callback router
# =============================================================================
async def cb_router(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    data = query.data

    if data == "user_status"   : await show_status(update, ctx)
    elif data == "admin_status": await show_status(update, ctx)
    elif data == "user_request": await cb_user_request(update, ctx)
    elif data == "admin_users" : await cb_admin_users(update, ctx)
    elif data == "admin_pending": await cb_admin_pending(update, ctx)
    elif data == "admin_restart": await cb_admin_restart(update, ctx)
    elif data == "back_admin"  : await cb_back_admin(update, ctx)
    elif data == "back_user"   : await cb_back_user(update, ctx)
    elif data == "cancel"      : await cb_cancel(update, ctx)
    elif data.startswith("approve_"): await cb_approve(update, ctx)
    elif data.startswith("deny_")   : await cb_deny(update, ctx)

# =============================================================================
# Build and run the application
# =============================================================================
def main():
    log.info("Starting fptnbot…  Admins: %s", ADMIN_IDS)

    app = Application.builder().token(BOT_TOKEN).build()

    # Add user conversation
    add_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(cb_admin_add, pattern="^admin_add$")],
        states={
            AWAIT_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_username)],
            AWAIT_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_password)],
            AWAIT_BW:       [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_bw)],
        },
        fallbacks=[CallbackQueryHandler(cb_cancel, pattern="^cancel$")],
        allow_reentry=True,
    )

    # Delete user conversation
    del_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(cb_admin_del, pattern="^admin_del$")],
        states={
            AWAIT_DEL_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_del_user)],
        },
        fallbacks=[CallbackQueryHandler(cb_cancel, pattern="^cancel$")],
        allow_reentry=True,
    )

    # Generate token conversation
    token_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(cb_admin_token, pattern="^admin_token$")],
        states={
            AWAIT_TOKEN_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_token_user)],
            AWAIT_TOKEN_PASS: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_token_pass)],
        },
        fallbacks=[CallbackQueryHandler(cb_cancel, pattern="^cancel$")],
        allow_reentry=True,
    )

    app.add_handler(CommandHandler("start",  cmd_start))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(add_conv)
    app.add_handler(del_conv)
    app.add_handler(token_conv)
    app.add_handler(CallbackQueryHandler(cb_router))

    log.info("Bot polling started.")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
