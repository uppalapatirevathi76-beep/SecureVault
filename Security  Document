
import os
import sqlite3
import secrets
import hashlib
import hmac
import html
import json
import mimetypes
import uuid
from pathlib import Path
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from email.parser import BytesParser
from email.policy import default

BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "documents"
UPLOAD_DIR.mkdir(exist_ok=True)

DB = BASE_DIR / "documents.db"
HOST = "127.0.0.1"
PORT = 8000
MAX_UPLOAD = 10 * 1024 * 1024

def connect():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            csrf TEXT NOT NULL,
            expires TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            UNIQUE(document_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        );
        """)

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 200000
    )
    return salt.hex() + ":" + key.hex()

def verify_password(password, saved):
    try:
        salt_hex, key_hex = saved.split(":")
        salt = bytes.fromhex(salt_hex)
        check = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, 200000
        )
        return hmac.compare_digest(check.hex(), key_hex)
    except Exception:
        return False

def audit(user_id, action, details=""):
    with connect() as con:
        con.execute(
            "INSERT INTO audit(user_id, action, details, created_at) VALUES(?,?,?,?)",
            (user_id, action, details, datetime.now().isoformat())
        )

def page(title, content, user=None, csrf=""):
    nav = ""
    if user:
        nav = f"""
        <p>Welcome, <b>{html.escape(user['username'])}</b>
        ({html.escape(user['role'])})</p>
        <a href="/">Home</a> |
        <a href="/upload">Upload</a> |
        <a href="/logout">Logout</a>
        """
        if user["role"] == "admin":
            nav += ' | <a href="/audit">Audit Logs</a>'

    return f"""<!DOCTYPE html>
<html>
<head>
<title>{html.escape(title)}</title>
<style>
body {{font-family:Arial;background:#f1f5f9;margin:0;padding:30px}}
.container {{max-width:850px;margin:auto;background:white;padding:25px;
border-radius:12px;box-shadow:0 2px 12px #ccc}}
h1 {{color:#173b65}}
input,button,select {{padding:10px;margin:7px 0;width:95%}}
button {{background:#173b65;color:white;border:0;cursor:pointer}}
a {{color:#0756a0}}
.item {{padding:12px;border-bottom:1px solid #ddd}}
.error {{color:red}}
</style>
</head>
<body>
<div class="container">
<h1>Secure Document Management System</h1>
{nav}
<hr>
{content}
</div>
</body>
</html>"""

class App(BaseHTTPRequestHandler):

    def send_page(self, content, status=200, user=None, csrf=""):
        data = page("Document Management", content, user, csrf).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()

    def current_user(self):
        cookie = self.headers.get("Cookie", "")
        token = None
        for part in cookie.split(";"):
            if part.strip().startswith("session="):
                token = part.strip().split("=", 1)[1]

        if not token:
            return None, None

        with connect() as con:
            row = con.execute("""
                SELECT users.*, sessions.csrf, sessions.expires
                FROM sessions JOIN users ON users.id=sessions.user_id
                WHERE sessions.token=?
            """, (token,)).fetchone()

        if not row:
            return None, None

        if row["expires"] < datetime.now().isoformat():
            with connect() as con:
                con.execute("DELETE FROM sessions WHERE token=?", (token,))
            return None, None

        return row, token

    def require_login(self):
        user, token = self.current_user()
        if not user:
            self.redirect("/login")
            return None, None
        return user, token

    def check_csrf(self, user):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        data = parse_qs(raw.decode(errors="replace"))
        submitted = data.get("csrf", [""])[0]

        if not hmac.compare_digest(submitted, user["csrf"]):
            self.send_page("<h2>Invalid request. Please try again.</h2>", 403)
            return None

        return data

    def do_GET(self):
        path = urlparse(self.path).path
        user, token = self.current_user()

        if path == "/":
            if not user:
                self.redirect("/login")
                return

            with connect() as con:
                docs = con.execute("""
                    SELECT DISTINCT documents.*, users.username
                    FROM documents
                    JOIN users ON users.id=documents.owner_id
                    LEFT JOIN shares ON shares.document_id=documents.id
                    WHERE documents.owner_id=? OR shares.user_id=?
                    ORDER BY documents.id DESC
                """, (user["id"], user["id"])).fetchall()

            content = "<h2>Your Documents</h2><div>"
            if not docs:
                content += "<p>No documents uploaded yet.</p>"

            for doc in docs:
                content += f"""
                <div class="item">
                <b>{html.escape(doc['filename'])}</b><br>
                Owner: {html.escape(doc['username'])}<br>
                Uploaded: {html.escape(doc['uploaded_at'])}<br>
                <a href="/download/{doc['id']}">Download</a>
                """
                if user["role"] == "admin":
                    content += f' | <a href="/share/{doc["id"]}">Share</a>'
                content += "</div>"

            content += "</div>"
            self.send_page(content, user=user)
            return

        if path == "/login":
            self.send_page("""
            <h2>Login</h2>
            <form method="POST" action="/login">
            <input name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
            </form>
            <p>New user? <a href="/register">Register here</a></p>
            """)
            return

        if path == "/register":
            self.send_page("""
            <h2>Create Account</h2>
            <form method="POST" action="/register">
            <input name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password (minimum 8 characters)" required>
            <button type="submit">Register</button>
            </form>
            <a href="/login">Back to Login</a>
            """)
            return

        if path == "/logout":
            if token:
                with connect() as con:
                    con.execute("DELETE FROM sessions WHERE token=?", (token,))
                audit(user["id"], "LOGOUT")
            self.send_response(303)
            self.send_header("Set-Cookie", "session=; Max-Age=0; HttpOnly; SameSite=Strict")
            self.send_header("Location", "/login")
            self.end_headers()
            return

        if path == "/upload":
            if not user:
                self.redirect("/login")
                return
            content = """
            <h2>Upload Document</h2>
            <form method="POST" action="/upload" enctype="multipart/form-data">
            <input type="file" name="document" required>
            <button type="submit">Upload Document</button>
            </form>
            """
            self.send_page(content, user=user)
            return

        if path.startswith("/download/"):
            if not user:
                self.redirect("/login")
                return

            try:
                doc_id = int(path.split("/")[-1])
            except ValueError:
                self.send_page("<h2>Invalid document</h2>", 400)
                return

            with connect() as con:
                doc = con.execute("""
                    SELECT * FROM documents
                    WHERE id=? AND (
                        owner_id=? OR id IN (
                            SELECT document_id FROM shares WHERE user_id=?
                        ) OR ?='admin'
                    )
                """, (doc_id, user["id"], user["id"], user["role"])).fetchone()

            if not doc:
                audit(user["id"], "DENIED_DOWNLOAD", str(doc_id))
                self.send_page("<h2>Access denied</h2>", 403, user)
                return

            file_path = UPLOAD_DIR / doc["stored_name"]
            if not file_path.is_file():
                self.send_page("<h2>File not found</h2>", 404, user)
                return

            data = file_path.read_bytes()
            filename = doc["filename"].replace('"', "")
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="{filename}"'
            )
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            audit(user["id"], "DOWNLOAD", filename)
            return

        if path == "/share":
            self.send_page("<h2>Invalid document</h2>", 404)
            return

        if path.startswith("/share/"):
            if not user or user["role"] != "admin":
                self.send_page("<h2>Admin access required</h2>", 403, user)
                return

            try:
                doc_id = int(path.split("/")[-1])
            except ValueError:
                self.send_page("<h2>Invalid document</h2>", 400, user)
                return

            with connect() as con:
                doc = con.execute(
                    "SELECT * FROM documents WHERE id=?", (doc_id,)
                ).fetchone()
                users = con.execute(
                    "SELECT id, username FROM users WHERE id != ?",
                    (user["id"],)
                ).fetchall()

            if not doc:
                self.send_page("<h2>Document not found</h2>", 404, user)
                return

            options = ""
            for item in users:
                options += f'<option value="{item["id"]}">{html.escape(item["username"])}</option>'

            content = f"""
            <h2>Share Document: {html.escape(doc['filename'])}</h2>
            <form method="POST" action="/share/{doc_id}">
            <input type="hidden" name="csrf" value="{user['csrf']}">
            <select name="user_id" required>{options}</select>
            <button type="submit">Share Document</button>
            </form>
            """
            self.send_page(content, user=user)
            return

        if path == "/audit":
            if not user or user["role"] != "admin":
                self.send_page("<h2>Admin access required</h2>", 403, user)
                return

            with connect() as con:
                logs = con.execute("""
                    SELECT audit.*, users.username
                    FROM audit LEFT JOIN users ON users.id=audit.user_id
                    ORDER BY audit.id DESC LIMIT 200
                """).fetchall()

            content = "<h2>Audit Logs</h2>"
            for log in logs:
                content += f"""
                <div class="item">
                User: {html.escape(log['username'] or 'System')} |
                Action: {html.escape(log['action'])}<br>
                Details: {html.escape(log['details'] or '')}<br>
                Date: {html.escape(log['created_at'])}
                </div>
                """
            self.send_page(content, user=user)
            return

        self.send_page("<h2>Page Not Found</h2>", 404)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/register":
            length = int(self.headers.get("Content-Length", 0))
            data = parse_qs(self.rfile.read(length).decode(errors="replace"))
            username = data.get("username", [""])[0].strip()
            password = data.get("password", [""])[0]

            if len(username) < 3 or len(password) < 8:
                self.send_page("<h2>Username must be 3+ characters and password 8+ characters.</h2>", 400)
                return

            with connect() as con:
                count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                role = "admin" if count == 0 else "employee"
                try:
                    con.execute(
                        "INSERT INTO users(username,password,role) VALUES(?,?,?)",
                        (username, hash_password(password), role)
                    )
                except sqlite3.IntegrityError:
                    self.send_page("<h2>Username already exists.</h2>", 400)
                    return

            self.send_page(f"""
            <h2>Registration successful!</h2>
            <p>Your role is: {role}</p>
            <a href="/login">Login here</a>
            """)
            return

        if path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            data = parse_qs(self.rfile.read(length).decode(errors="replace"))
            username = data.get("username", [""])[0].strip()
            password = data.get("password", [""])[0]

            with connect() as con:
                account = con.execute(
                    "SELECT * FROM users WHERE username=?", (username,)
                ).fetchone()

            if not account or not verify_password(password, account["password"]):
                audit(None, "FAILED_LOGIN", username)
                self.send_page("<h2 class='error'>Invalid username or password.</h2><a href='/login'>Try again</a>", 401)
                return

            token = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(24)
            expires = (datetime.now() + timedelta(hours=8)).isoformat()

            with connect() as con:
                con.execute(
                    "INSERT INTO sessions(token,user_id,csrf,expires) VALUES(?,?,?,?)",
                    (token, account["id"], csrf, expires)
                )

            audit(account["id"], "LOGIN")
            self.send_response(303)
            self.send_header("Set-Cookie", f"session={token}; HttpOnly; SameSite=Strict; Path=/")
            self.send_header("Location", "/")
            self.end_headers()
            return

        user, token = self.current_user()
        if not user:
            self.redirect("/login")
            return

        if path == "/upload":
            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in content_type:
                self.send_page("<h2>Invalid upload request</h2>", 400, user)
                return

            length = int(self.headers.get("Content-Length", 0))
            if length <= 0 or length > MAX_UPLOAD:
                self.send_page("<h2>File size must be below 10 MB.</h2>", 400, user)
                return

            raw = self.rfile.read(length)
            message = BytesParser(policy=default).parsebytes(
                b"Content-Type: " + content_type.encode() +
                b"\r\nMIME-Version: 1.0\r\n\r\n" + raw
            )

            uploaded = None
            for part in message.iter_parts():
                if part.get_param("name", header="content-disposition") == "document":
                    uploaded = part
                    break

            if not uploaded or not uploaded.get_filename():
                self.send_page("<h2>No file selected</h2>", 400, user)
                return

            original = Path(uploaded.get_filename()).name
            if not original or original in (".", ".."):
                self.send_page("<h2>Invalid filename</h2>", 400, user)
                return

            file_data = uploaded.get_payload(decode=True) or b""
            if not file_data:
                self.send_page("<h2>Empty file</h2>", 400, user)
                return

            stored = uuid.uuid4().hex
            (UPLOAD_DIR / stored).write_bytes(file_data)

            with connect() as con:
                con.execute("""
                    INSERT INTO documents(filename,stored_name,owner_id,uploaded_at)
                    VALUES(?,?,?,?)
                """, (original, stored, user["id"], datetime.now().isoformat()))

            audit(user["id"], "UPLOAD", original)
            self.redirect("/")
            return

        if path.startswith("/share/"):
            if user["role"] != "admin":
                self.send_page("<h2>Admin access required</h2>", 403, user)
                return

            data = self.check_csrf(user)
            if data is None:
                return

            try:
                doc_id = int(path.split("/")[-1])
                target_id = int(data.get("user_id", ["0"])[0])
            except ValueError:
                self.send_page("<h2>Invalid details</h2>", 400, user)
                return

            with connect() as con:
                doc = con.execute(
                    "SELECT id FROM documents WHERE id=?", (doc_id,)
                ).fetchone()
                target = con.execute(
                    "SELECT id FROM users WHERE id=?", (target_id,)
                ).fetchone()

                if not doc or not target:
                    self.send_page("<h2>Document or user not found</h2>", 404, user)
                    return

                con.execute(
                    "INSERT OR IGNORE INTO shares(document_id,user_id) VALUES(?,?)",
                    (doc_id, target_id)
                )

            audit(user["id"], "SHARE", f"Document {doc_id} to user {target_id}")
            self.redirect("/")
            return

        self.send_page("<h2>Page Not Found</h2>", 404, user)

    def log_message(self, format, *args):
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), format % args)


if __name__ == "__main__":
    init_db()
    print("Secure Document Management System started!")
    print("Open: http://127.0.0.1:8000")
    HTTPServer((HOST, PORT), App).serve_forever()
