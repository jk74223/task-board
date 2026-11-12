# -*- coding: utf-8 -*-
"""任务看板后端（部署在线上服务器 121.42.14.135，端口 16676，nginx /task-board）

职责边界：
  本服务 = 卡片状态的唯一真相源（SQLite），只做 CRUD + 原子领取，不发任何消息
  （微信网关在 Hermes 宿主，不在本机）；通知由 Hermes 宿主的调度器统一发送。

鉴权：
  用户侧  ?t=<board_token> 换 cookie / Cookie tb
  机器侧  X-Board-Token: <internal_token>（dispatcher 领取、worker 回写）
"""
import hashlib
import hmac
import json
import os
import sqlite3
import time
import urllib.parse
import urllib.request
import secrets as pysecrets
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "taskboard.db")
SECRETS = os.path.join(BASE, "secrets.json")
TPL = os.path.join(BASE, "templates", "board.html")
PREFIX = "/task-board"

PUBLIC_BASE = "https://service-dp.boogcloud.com"
OAUTH_CALLBACK = PUBLIC_BASE + "/task-board/oauth/callback"
ALLOW_USERIDS = ["ZhuYing"]      # 可访问看板的企微成员（secrets.json 的 allow_userids 可覆盖）
COOKIE_NAME = "tbu"
_TOKEN_CACHE = {"token": "", "exp": 0}

STATUS_CN = {
    "pool": "需求池", "dev": "开发中", "review": "待验收", "done": "已完成",
    "blocked": "待确认", "failed": "失败", "cancelled": "已取消", "stalled": "超时中断",
}
BOARD_STATUSES = ["pool", "dev", "review", "done"]

app = FastAPI(title="任务看板")


def load_secrets():
    with open(SECRETS, encoding="utf-8") as f:
        return json.load(f)


def db():
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      detail TEXT DEFAULT '',
      system TEXT DEFAULT '',
      priority INTEGER DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'pool',
      created_at TEXT NOT NULL,
      started_at TEXT,
      finished_at TEXT,
      worker_pid INTEGER,
      session_id TEXT,
      result TEXT,
      evidence TEXT,
      block_reason TEXT,
      log_path TEXT,
      note TEXT,
      notified TEXT DEFAULT '',
      immediate INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id INTEGER NOT NULL,
      ts TEXT NOT NULL,
      from_status TEXT,
      to_status TEXT NOT NULL,
      actor TEXT DEFAULT '',
      note TEXT DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_status ON tasks(status);
    """)
    # 轻量迁移：旧库补列（CREATE TABLE IF NOT EXISTS 不会改已有表）
    cols = {r[1] for r in conn.execute("PRAGMA table_info(tasks)")}
    for col, ddl in (("notified", "ALTER TABLE tasks ADD COLUMN notified TEXT DEFAULT ''"),
                     ("immediate", "ALTER TABLE tasks ADD COLUMN immediate INTEGER DEFAULT 0"),):
        if col not in cols:
            conn.execute(ddl)
            print("[migrate] tasks 增加列", col)
    conn.close()


def log_event(conn, task_id, from_status, to_status, actor="", note=""):
    conn.execute("INSERT INTO events(task_id, ts, from_status, to_status, actor, note) VALUES(?,?,?,?,?,?)",
                 (task_id, now(), from_status, to_status, actor, note))


def corp_cfg():
    c = (load_secrets().get("corp") or {})
    ids = load_secrets().get("allow_userids") or ALLOW_USERIDS
    return c, ids


def access_token():
    """企微应用 access_token（带进程内缓存）"""
    c, _ = corp_cfg()
    if _TOKEN_CACHE["token"] and time.time() < _TOKEN_CACHE["exp"]:
        return _TOKEN_CACHE["token"]
    q = urllib.parse.urlencode({"corpid": c.get("corpid"), "corpsecret": c.get("secret")})
    try:
        with urllib.request.urlopen("https://qyapi.weixin.qq.com/cgi-bin/gettoken?" + q, timeout=15) as r:
            d = json.loads(r.read().decode())
    except Exception as e:
        print("[oauth] gettoken 异常:", e)
        return ""
    tok = d.get("access_token") or ""
    if tok:
        _TOKEN_CACHE["token"] = tok
        _TOKEN_CACHE["exp"] = time.time() + int(d.get("expires_in", 7200)) - 300
    return tok


def code_to_userid(code):
    """企微 OAuth code → 成员 userid"""
    tok = access_token()
    if not tok:
        return "", "取 access_token 失败"
    q = urllib.parse.urlencode({"access_token": tok, "code": code})
    try:
        with urllib.request.urlopen("https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?" + q, timeout=15) as r:
            d = json.loads(r.read().decode())
    except Exception as e:
        return "", "getuserinfo 异常: %s" % e
    if d.get("errcode") != 0:
        return "", "getuserinfo 失败: %s" % str(d)[:120]
    return (d.get("userid") or d.get("UserId") or ""), ""


def sign_user(userid):
    sec = load_secrets()
    sig = hmac.new(sec["internal_token"].encode(), userid.encode(), hashlib.sha256).hexdigest()[:32]
    return "%s.%s" % (userid, sig)


def cookie_user(request):
    raw = request.cookies.get(COOKIE_NAME) or ""
    if "." not in raw:
        return ""
    userid, sig = raw.rsplit(".", 1)
    _, allowed = corp_cfg()
    if userid not in allowed:
        return ""
    return userid if hmac.compare_digest(sign_user(userid), raw) else ""


def user_ok(request):
    """两种合法身份：① 企微免登会话 cookie ② 带 token 的链接（非企微浏览器/调试用）"""
    if cookie_user(request):
        return True
    sec = load_secrets()
    tok = request.query_params.get("t") or request.cookies.get("tb") or ""
    return bool(tok) and pysecrets.compare_digest(tok, sec["board_token"])


def internal_ok(request):
    sec = load_secrets()
    tok = request.headers.get("x-board-token", "")
    return bool(tok) and pysecrets.compare_digest(tok, sec["internal_token"])


# ------------------------------ 页面 ------------------------------
@app.get(PREFIX, response_class=HTMLResponse)
@app.get(PREFIX + "/", response_class=HTMLResponse)
async def board_page(request: Request):
    if not user_ok(request):
        # 非企微环境（没带 token）直接提示，不把用户甩去企微授权页
        ua = (request.headers.get("user-agent") or "").lower()
        in_wecom = ("wxwork" in ua) or ("micromessenger" in ua and "wxwork" in ua)
        if request.query_params.get("direct") == "1" or not in_wecom:
            return HTMLResponse(
                "<div style='padding:36px 24px;font-family:-apple-system,sans-serif;line-height:1.9'>"
                "<h3 style='margin:0 0 12px'>请在企业微信里打开</h3>"
                "<div style='color:#646a73;font-size:14px'>本页支持企微免登：从工作台「任务看板」进入即可自动登录。<br>"
                "电脑浏览器请使用带访问密钥的链接（<code>?t=…</code>）。</div></div>", status_code=403)
        c, _ = corp_cfg()
        state = "board"
        url = ("https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s"
               "&response_type=code&scope=snsapi_base&agentid=%s&state=%s#wechat_redirect"
               % (c.get("corpid"), urllib.parse.quote(OAUTH_CALLBACK, safe=""), c.get("agentid"), state))
        return RedirectResponse(url=url, status_code=302)

    with open(TPL, encoding="utf-8") as f:
        html = f.read()
    resp = HTMLResponse(html, headers={"Cache-Control": "no-store, must-revalidate"})
    if request.query_params.get("t"):
        resp.set_cookie("tb", load_secrets()["board_token"], max_age=90 * 24 * 3600, samesite="lax")
    return resp


@app.get(PREFIX + "/oauth/callback")
async def oauth_callback(request: Request, code: str = "", state: str = ""):
    """企微 OAuth 回调：code → userid → 签发会话 cookie"""
    if not code:
        return HTMLResponse("<h3 style='padding:40px'>缺少 code，授权未完成，请从企微工作台重新进入</h3>", status_code=400)
    userid, err = code_to_userid(code)
    if not userid:
        return HTMLResponse("<h3 style='padding:40px;font-family:sans-serif'>企微授权失败：%s</h3>" % err, status_code=403)
    _, allowed = corp_cfg()
    if userid not in allowed:
        return HTMLResponse("<h3 style='padding:40px;font-family:sans-serif'>已识别企微成员 %s，但未被允许访问本看板</h3>"
                            % userid, status_code=403)
    resp = RedirectResponse(url=PREFIX, status_code=302)
    resp.set_cookie(COOKIE_NAME, sign_user(userid), max_age=7 * 24 * 3600, httponly=True, samesite="lax")
    return resp


@app.get(PREFIX + "/health")
async def health():
    return {"ok": True, "service": "task-board", "ts": now()}


# ------------------------------ 列表 / 事件 ------------------------------
@app.get(PREFIX + "/api/tasks")
async def list_tasks(request: Request):
    if not (user_ok(request) or internal_ok(request)):
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=403)
    conn = db()
    rows = conn.execute("SELECT * FROM tasks ORDER BY priority DESC, id DESC").fetchall()
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    conn.close()
    return {"ok": True, "tasks": [dict(r) for r in rows], "counts": counts,
            "status_cn": STATUS_CN, "board_statuses": BOARD_STATUSES, "now": now()}


@app.get(PREFIX + "/api/tasks/{task_id}/events")
async def task_events(request: Request, task_id: int):
    if not (user_ok(request) or internal_ok(request)):
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=403)
    conn = db()
    rows = conn.execute("SELECT * FROM events WHERE task_id=? ORDER BY id", (task_id,)).fetchall()
    conn.close()
    return {"ok": True, "events": [dict(r) for r in rows]}


# ------------------------------ 用户操作 ------------------------------
@app.post(PREFIX + "/api/tasks")
async def create_task(request: Request):
    if not (user_ok(request) or internal_ok(request)):
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=403)
    body = await request.json()
    title = (body.get("title") or "").strip()
    detail = (body.get("detail") or "").strip()
    system = (body.get("system") or "").strip()
    try:
        priority = int(body.get("priority") or 0)
    except Exception:
        priority = 0
    if not title:
        return JSONResponse({"ok": False, "error": "标题必填"}, status_code=400)
    if len(title) > 120:
        return JSONResponse({"ok": False, "error": "标题过长（≤120字）"}, status_code=400)
    immediate = 1 if body.get("immediate") else 0
    conn = db()
    cur = conn.execute(
        "INSERT INTO tasks(title, detail, system, priority, immediate, status, created_at) "
        "VALUES(?,?,?,?,?, 'pool', ?)",
        (title, detail, system, priority, immediate, now()))
    tid = cur.lastrowid
    log_event(conn, tid, None, "pool", "user")
    conn.close()
    return {"ok": True, "id": tid}


@app.post(PREFIX + "/api/tasks/{task_id}/accept")
async def accept_task(request: Request, task_id: int):
    """验收通过 → 已完成"""
    if not user_ok(request):
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=403)
    conn = db()
    r = conn.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()
    if not r:
        conn.close()
        return JSONResponse({"ok": False, "error": "任务不存在"}, status_code=404)
    if r["status"] not in ("review", "blocked", "failed", "stalled"):
        conn.close()
        return JSONResponse({"ok": False, "error": "当前状态不可验收: " + r["status"]}, status_code=400)
    conn.execute("UPDATE tasks SET status='done', finished_at=? WHERE id=?", (now(), task_id))
    log_event(conn, task_id, r["status"], "done", "user")
    conn.close()
    return {"ok": True}


@app.post(PREFIX + "/api/tasks/{task_id}/reject")
async def reject_task(request: Request, task_id: int):
    """打回需求池（带批注）"""
    if not user_ok(request):
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=403)
    body = await request.json()
    note = (body.get("note") or "").strip()
    conn = db()
    r = conn.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()
    if not r:
        conn.close()
        return JSONResponse({"ok": False, "error": "任务不存在"}, status_code=404)
    conn.execute("UPDATE tasks SET status='pool', result=NULL, evidence=NULL, block_reason=NULL, "
                 "started_at=NULL, finished_at=NULL, worker_pid=NULL, session_id=NULL, log_path=NULL, "
                 "notified='', note=? WHERE id=?", (note, task_id))
    log_event(conn, task_id, r["status"], "pool", "user", note)
    conn.close()
    return {"ok": True}


@app.post(PREFIX + "/api/tasks/{task_id}/cancel")
async def cancel_task(request: Request, task_id: int):
    if not (user_ok(request) or internal_ok(request)):
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=403)
    conn = db()
    r = conn.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()
    if not r:
        conn.close()
        return JSONResponse({"ok": False, "error": "任务不存在"}, status_code=404)
    if r["status"] in ("done", "cancelled"):
        conn.close()
        return JSONResponse({"ok": False, "error": "已结束的任务不可取消"}, status_code=400)
    conn.execute("UPDATE tasks SET status='cancelled', finished_at=? WHERE id=?", (now(), task_id))
    log_event(conn, task_id, r["status"], "cancelled", "user")
    conn.close()
    return {"ok": True}


@app.post(PREFIX + "/api/tasks/{task_id}/priority")
async def set_priority(request: Request, task_id: int):
    """修改需求池中任务的优先级 / 立刻执行（插队）"""
    if not (user_ok(request) or internal_ok(request)):
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=403)
    body = await request.json()
    try:
        priority = int(body.get("priority"))
    except Exception:
        return JSONResponse({"ok": False, "error": "priority 必须是整数"}, status_code=400)
    if priority < 0 or priority > 2:
        return JSONResponse({"ok": False, "error": "priority 取值 0/1/2"}, status_code=400)
    immediate = 1 if body.get("immediate") else 0
    conn = db()
    r = conn.execute("SELECT status, priority, immediate FROM tasks WHERE id=?", (task_id,)).fetchone()
    if not r:
        conn.close()
        return JSONResponse({"ok": False, "error": "任务不存在"}, status_code=404)
    if r["status"] != "pool":
        conn.close()
        return JSONResponse({"ok": False, "error": "仅需求池中的任务可改优先级（当前: %s）" % r["status"]}, status_code=400)
    conn.execute("UPDATE tasks SET priority=?, immediate=? WHERE id=?", (priority, immediate, task_id))
    note = "优先级 %s→%s" % (r["priority"], priority)
    if immediate and not r["immediate"]:
        note += "，设为插队"
    log_event(conn, task_id, "pool", "pool", "user", note)
    conn.close()
    return {"ok": True}


# ------------------------------ 机器侧接口 ------------------------------
@app.post(PREFIX + "/api/tasks/claim")
async def claim_task(request: Request):
    """原子领取下一张卡片（并发闸 + 同系统串行）。dispatcher 调用。"""
    if not internal_ok(request):
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=403)
    sec = load_secrets()
    max_parallel = int(sec.get("max_parallel", 1))
    conn = db()
    running = conn.execute("SELECT id, system FROM tasks WHERE status='dev'").fetchall()
    if len(running) >= max_parallel:
        conn.close()
        return {"ok": False, "reason": "并发已满 %d/%d" % (len(running), max_parallel)}
    busy = {r["system"] for r in running if r["system"]}
    rows = conn.execute("SELECT id, system FROM tasks WHERE status='pool' "
                        "ORDER BY immediate DESC, priority DESC, id ASC").fetchall()
    cand = None
    for r in rows:
        if r["system"] and r["system"] in busy:
            continue
        cand = r
        break
    if not cand:
        conn.close()
        return {"ok": False, "reason": "无可领取任务"}
    conn.execute("BEGIN IMMEDIATE")
    cur = conn.execute("UPDATE tasks SET status='dev', started_at=? WHERE id=? AND status='pool'",
                       (now(), cand["id"]))
    if cur.rowcount != 1:
        conn.execute("ROLLBACK")
        conn.close()
        return {"ok": False, "reason": "领取竞争失败"}
    log_event(conn, cand["id"], "pool", "dev", "dispatcher")
    conn.execute("COMMIT")
    task = dict(conn.execute("SELECT * FROM tasks WHERE id=?", (cand["id"],)).fetchone())
    conn.close()
    return {"ok": True, "task": task}


@app.post(PREFIX + "/api/tasks/{task_id}/worker")
async def set_worker(request: Request, task_id: int):
    """dispatcher 回填 worker pid / 日志路径"""
    if not internal_ok(request):
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=403)
    body = await request.json()
    conn = db()
    conn.execute("UPDATE tasks SET worker_pid=?, log_path=? WHERE id=?",
                 (body.get("worker_pid"), body.get("log_path"), task_id))
    conn.close()
    return {"ok": True}


@app.post(PREFIX + "/api/tasks/{task_id}/stall")
async def stall_task(request: Request, task_id: int):
    """dispatcher 判定进程已死/超时 → 超时中断"""
    if not internal_ok(request):
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=403)
    body = await request.json()
    reason = (body.get("reason") or "执行进程已中断").strip()
    conn = db()
    r = conn.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()
    if not r or r["status"] != "dev":
        conn.close()
        return {"ok": False, "reason": "状态不是 dev"}
    conn.execute("UPDATE tasks SET status='stalled', finished_at=?, block_reason=? WHERE id=?",
                 (now(), reason, task_id))
    log_event(conn, task_id, "dev", "stalled", "watchdog", reason)
    conn.close()
    return {"ok": True}


@app.post(PREFIX + "/api/tasks/{task_id}/result")
async def worker_result(request: Request, task_id: int):
    """worker 收尾回写：status=review|blocked|failed"""
    if not internal_ok(request):
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=403)
    body = await request.json()
    status = (body.get("status") or "").strip()
    if status not in ("review", "blocked", "failed"):
        return JSONResponse({"ok": False, "error": "status 只能是 review/blocked/failed"}, status_code=400)
    conn = db()
    r = conn.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()
    if not r:
        conn.close()
        return JSONResponse({"ok": False, "error": "任务不存在"}, status_code=404)
    conn.execute("UPDATE tasks SET status=?, finished_at=?, result=?, evidence=?, block_reason=?, "
                 "session_id=COALESCE(?, session_id) WHERE id=?",
                 (status, now(), body.get("result"), body.get("evidence"),
                  body.get("block_reason"), body.get("session_id") or None, task_id))
    log_event(conn, task_id, r["status"], status, "worker",
              (body.get("result") or body.get("block_reason") or "")[:200])
    conn.close()
    return {"ok": True}


@app.post(PREFIX + "/api/wecom-notify")
async def wecom_notify(request: Request):
    """企微应用消息代发：本机（Hermes 宿主）IP 不在企微白名单，故由线上代发"""
    if not internal_ok(request):
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=403)
    body = await request.json()
    text = (body.get("text") or "").strip()
    md = (body.get("markdown") or "").strip()
    if not text and not md:
        return JSONResponse({"ok": False, "error": "text 或 markdown 必填"}, status_code=400)
    w, _ = corp_cfg()
    if not (w.get("corpid") and w.get("secret")):
        return JSONResponse({"ok": False, "error": "未配置企微凭据"}, status_code=400)
    try:
        tok = access_token()
        if not tok:
            return JSONResponse({"ok": False, "error": "gettoken 失败"}, status_code=502)
        touser = body.get("touser") or load_secrets().get("wecom_userid") or ""
        if not touser:
            return JSONResponse({"ok": False, "error": "未配置收件人 wecom_userid"}, status_code=400)

        def _send(token, agentid):
            if md:
                # 企微 markdown 消息（content 上限 2048 字节，按字节安全截断）
                content = md.encode("utf-8")[:2000].decode("utf-8", "ignore")
                payload = {"touser": touser, "msgtype": "markdown",
                           "agentid": int(agentid), "markdown": {"content": content}}
            else:
                payload = {"touser": touser, "msgtype": "text",
                           "agentid": int(agentid), "text": {"content": text}}
            req = urllib.request.Request(
                "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=" + token,
                data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read().decode())

        res = _send(tok, w["agentid"])
        used = "新应用%s" % w["agentid"]
        # 新应用可信 IP 未配好（60020）时回落旧应用，保证通知不断
        if res.get("errcode") == 60020:
            fb = (load_secrets().get("corp_fallback") or {})
            if fb.get("corpid") and fb.get("secret"):
                q = urllib.parse.urlencode({"corpid": fb["corpid"], "corpsecret": fb["secret"]})
                with urllib.request.urlopen("https://qyapi.weixin.qq.com/cgi-bin/gettoken?" + q, timeout=15) as r:
                    ftok = json.loads(r.read().decode()).get("access_token")
                if ftok:
                    res = _send(ftok, fb["agentid"])
                    used = "旧应用%s(回落)" % fb["agentid"]
        if res.get("errcode") == 0:
            return {"ok": True, "via": used}
        return JSONResponse({"ok": False, "error": "%s via %s" % (str(res)[:160], used)}, status_code=502)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)[:200]}, status_code=502)


@app.post(PREFIX + "/api/tasks/{task_id}/notified")
async def mark_notified(request: Request, task_id: int):
    """dispatcher 记录「这次状态变更已通知过」，防重复推送"""
    if not internal_ok(request):
        return JSONResponse({"ok": False, "error": "未授权"}, status_code=403)
    body = await request.json()
    conn = db()
    conn.execute("UPDATE tasks SET notified=? WHERE id=?", (body.get("notified") or "", task_id))
    conn.close()
    return {"ok": True}


init_db()   # 启动即建表 + 迁移（uvicorn 直接载入 app:app 时也生效）


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=16676, log_level="info")
