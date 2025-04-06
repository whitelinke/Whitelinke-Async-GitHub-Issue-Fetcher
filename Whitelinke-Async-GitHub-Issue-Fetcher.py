import subprocess
import sys
import os
import time
import logging
from flask import Flask, request, jsonify, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_caching import Cache
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from marshmallow import Schema, fields, ValidationError
import aiohttp
import asyncio
import bcrypt

# List of required packages
REQUIRED_PACKAGES = [
    "flask",
    "flask_sqlalchemy",
    "flask_jwt_extended",
    "flask_caching",
    "flask_migrate",
    "flask_limiter",
    "requests",
    "python-dotenv",
    "werkzeug",
    "marshmallow",
    "aiohttp",
    "bcrypt"
]

# Function to install missing packages
def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Install any missing packages
for pkg in REQUIRED_PACKAGES:
    try:
        __import__(pkg.replace("-", "_"))
    except ImportError:
        print(f"Package '{pkg}' is missing. Installing...")
        install_package(pkg)

# ------------------ CONFIGURATION ------------------
load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "super-secret")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "postgresql://localhost/appdb")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    CACHE_TYPE = "redis"
    CACHE_DEFAULT_TIMEOUT = 300
    CACHE_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    # Enable SQLAlchemy Echo for debugging
    SQLALCHEMY_ECHO = os.getenv("SQLALCHEMY_ECHO", "False").lower() == 'true'

# ------------------ APP INITIALIZATION ------------------
app = Flask(__name__)
app.config.from_object(Config)

# Core extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
cache = Cache(app)
migrate = Migrate(app, db)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

# ------------------ DATABASE MODEL ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# ------------------ SCHEMAS ------------------
class UserSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)

user_schema = UserSchema()

# ------------------ UTILS ------------------
async def fetch_github_issues(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    headers = {"Authorization": f"token {Config.GITHUB_TOKEN}"} if Config.GITHUB_TOKEN else {}
    params = {"state": "open", "per_page": 100, "page": 1}
    all_issues = []

    async with aiohttp.ClientSession() as session:
        while True:
            try:
                async with session.get(url, headers=headers, params=params, timeout=10) as response:
                    if response.status == 403:
                        reset_time = int(response.headers.get('X-RateLimit-Reset', time.time() + 60))
                        sleep_time = max(reset_time - time.time() + 5, 5)
                        logger.warning(f"Rate limited. Sleeping for {sleep_time:.0f}s.")
                        await asyncio.sleep(sleep_time)
                        continue

                    if response.status != 200:
                        logger.error(f"GitHub API error: {response.status}")
                        return None

                    issues = await response.json()
                    if not issues:
                        break

                    all_issues.extend([ 
                        {
                            "id": i["number"],
                            "title": i["title"],
                            "body": i["body"],
                            "labels": [label["name"] for label in i["labels"]],
                            "created_at": i["created_at"],
                            "url": i["html_url"]
                        } for i in issues if "pull_request" not in i
                    ])

                    if 'link' in response.headers and 'rel="next"' in response.headers["link"]:
                        params["page"] += 1
                    else:
                        break
            except asyncio.TimeoutError:
                logger.error("GitHub API request timed out")
                return None

    return all_issues

@cache.memoize(timeout=300)
async def cached_fetch(owner, repo):
    return await fetch_github_issues(owner, repo)

# ------------------ ERROR HANDLING ------------------
@app.errorhandler(Exception)
def handle_exception(e):
    logger.exception("Unhandled exception occurred")
    return jsonify({"error": "Internal Server Error"}), 500

# ------------------ HEALTH CHECK ------------------
@app.route("/health")
def health():
    return jsonify(status="ok"), 200

# ------------------ AUTH ROUTES ------------------
auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["POST"])
async def register():
    try:
        data = user_schema.load(request.get_json())
    except ValidationError as err:
        return jsonify(err.messages), 400

    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"msg": "User already exists"}), 409

    hashed_pw = bcrypt.hashpw(data["password"].encode('utf-8'), bcrypt.gensalt())
    user = User(username=data["username"], password=hashed_pw.decode('utf-8'))
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "User registered successfully"}), 201

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
async def login():
    try:
        data = user_schema.load(request.get_json())
    except ValidationError as err:
        return jsonify(err.messages), 400

    user = User.query.filter_by(username=data["username"]).first()
    if user and bcrypt.checkpw(data["password"].encode('utf-8'), user.password.encode('utf-8')):
        token = create_access_token(identity=user.username)
        return jsonify(access_token=token)
    return jsonify({"msg": "Invalid credentials"}), 401

# ------------------ GITHUB ROUTES ------------------
github_bp = Blueprint("github", __name__)

@github_bp.route("/issues", methods=["GET"])
@jwt_required()
async def get_issues():
    owner = request.args.get("owner")
    repo = request.args.get("repo")
    username = get_jwt_identity()
    logger.info(f"{username} requested issues for {owner}/{repo}")

    if not owner or not repo:
        return jsonify({"error": "Missing owner or repo"}), 400

    issues = await cached_fetch(owner, repo)
    if issues is None:
        return jsonify({"error": "Could not fetch issues"}), 500

    return jsonify(issues)

# ------------------ ROUTE REGISTRATION ------------------
app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(github_bp, url_prefix="/github")

# ------------------ MAIN ------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    logger.info("App is running at http://127.0.0.1:5000")
    app.run(debug=True, use_reloader=False)  # Added `use_reloader=False` to prevent issues with async
