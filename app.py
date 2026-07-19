import os
import re
import uuid
import smtplib
import math
import hashlib
import hmac
from html import escape
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from urllib.parse import urljoin, urlparse
from email.message import EmailMessage
from datetime import UTC, datetime, timedelta
import stripe

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
    make_response,
    send_from_directory,
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    current_user,
    login_required,
    UserMixin,
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func, desc, or_
from sqlalchemy.exc import IntegrityError

from flask import current_app

# -------------------------------------------------------------------
# App & config
# -------------------------------------------------------------------

app = Flask(__name__)

# Secret key
is_production = (
    os.getenv("FLASK_ENV", "").lower() == "production"
    or bool(os.getenv("RAILWAY_ENVIRONMENT"))
    or bool(os.getenv("RAILWAY_ENVIRONMENT_NAME"))
)
secret_key = os.getenv("SECRET_KEY")
if is_production and not secret_key:
    raise RuntimeError("SECRET_KEY must be configured in production.")
app.config["SECRET_KEY"] = secret_key or "development-only-secret-key"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = is_production
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_SECURE"] = is_production
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=30)
app.config["MAX_CONTENT_LENGTH"] = int(
    os.getenv("MAX_CONTENT_LENGTH", str(16 * 1024 * 1024))
)

# Public legal identity. Configure the optional registration fields before launch.
app.config["LEGAL_ENTITY_NAME"] = os.getenv("LEGAL_ENTITY_NAME", "Ownerlane")
app.config["LEGAL_COMPANY_NUMBER"] = os.getenv("LEGAL_COMPANY_NUMBER")
app.config["LEGAL_REGISTERED_ADDRESS"] = os.getenv("LEGAL_REGISTERED_ADDRESS")
app.config["LEGAL_ICO_NUMBER"] = os.getenv("LEGAL_ICO_NUMBER")
app.config["LEGAL_CONTACT_EMAIL"] = os.getenv(
    "LEGAL_CONTACT_EMAIL", "hello@ownerlane.uk"
)
app.config["LEGAL_LAST_UPDATED"] = os.getenv(
    "LEGAL_LAST_UPDATED", "17 July 2026"
)
railway_public_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN")
public_base_url = os.getenv("PUBLIC_BASE_URL") or (
    f"https://{railway_public_domain}" if railway_public_domain else ""
)
app.config["PUBLIC_BASE_URL"] = public_base_url.rstrip("/")
if is_production and not app.config["PUBLIC_BASE_URL"]:
    raise RuntimeError(
        "PUBLIC_BASE_URL must be configured in production for secure authentication links."
    )

# -------------------------------------------------------------------
# Database (SQLite fallback, pg8000 for Railway/Postgres)
# -------------------------------------------------------------------
raw_db_url = os.getenv("DATABASE_URL", "sqlite:///care_broker.db")

# Convert to SQLAlchemy pg8000 format so it never tries to use psycopg2
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql+pg8000://", 1)
elif raw_db_url.startswith("postgresql://"):
    raw_db_url = raw_db_url.replace("postgresql://", "postgresql+pg8000://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = raw_db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)



login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

# Task token & email config
app.config["DIGEST_TASK_TOKEN"] = os.getenv("DIGEST_TASK_TOKEN")

# SMTP / email config
app.config["SMTP_SERVER"] = os.getenv("SMTP_SERVER", "localhost")
app.config["SMTP_PORT"] = int(os.getenv("SMTP_PORT", "25"))
app.config["SMTP_USERNAME"] = os.getenv("SMTP_USERNAME")
app.config["SMTP_PASSWORD"] = os.getenv("SMTP_PASSWORD")
app.config["SMTP_USE_TLS"] = os.getenv("SMTP_USE_TLS", "0") == "1"
app.config["SMTP_DEFAULT_FROM"] = os.getenv(
    "SMTP_DEFAULT_FROM", "no-reply@example.com"
)

app.config["LEADS_NOTIFICATION_EMAIL"] = os.getenv(
    "LEADS_NOTIFICATION_EMAIL",
    app.config.get("SMTP_USERNAME"),
)

# Authentication security controls
app.config["EMAIL_VERIFICATION_MAX_AGE"] = int(
    os.getenv("EMAIL_VERIFICATION_MAX_AGE", str(24 * 60 * 60))
)
app.config["PASSWORD_RESET_MAX_AGE"] = int(
    os.getenv("PASSWORD_RESET_MAX_AGE", str(60 * 60))
)
app.config["LOGIN_FAILURE_LIMIT"] = int(os.getenv("LOGIN_FAILURE_LIMIT", "5"))
app.config["LOGIN_FAILURE_WINDOW"] = int(
    os.getenv("LOGIN_FAILURE_WINDOW", str(15 * 60))
)
app.config["LOGIN_LOCKOUT_SECONDS"] = int(
    os.getenv("LOGIN_LOCKOUT_SECONDS", str(15 * 60))
)
app.config["AUTH_EMAIL_LIMIT"] = int(os.getenv("AUTH_EMAIL_LIMIT", "3"))
app.config["AUTH_EMAIL_WINDOW"] = int(os.getenv("AUTH_EMAIL_WINDOW", str(15 * 60)))
app.config["ADMIN_IDLE_TIMEOUT"] = int(os.getenv("ADMIN_IDLE_TIMEOUT", str(30 * 60)))
app.config["ADMIN_ABSOLUTE_TIMEOUT"] = int(
    os.getenv("ADMIN_ABSOLUTE_TIMEOUT", str(8 * 60 * 60))
)

# Stripe config
app.config["STRIPE_SECRET_KEY"] = os.getenv("STRIPE_SECRET_KEY")
app.config["STRIPE_WEBHOOK_SECRET"] = os.getenv("STRIPE_WEBHOOK_SECRET")

# Price IDs for each role / tier
app.config["STRIPE_PRICE_BUYER_BASIC"] = os.getenv("STRIPE_PRICE_BUYER_BASIC")
app.config["STRIPE_PRICE_BUYER_PREMIUM"] = os.getenv("STRIPE_PRICE_BUYER_PREMIUM")
app.config["STRIPE_PRICE_SELLER_BASIC"] = os.getenv("STRIPE_PRICE_SELLER_BASIC")
app.config["STRIPE_PRICE_SELLER_PREMIUM"] = os.getenv("STRIPE_PRICE_SELLER_PREMIUM")
app.config["STRIPE_PRICE_VALUER_BASIC"] = os.getenv("STRIPE_PRICE_VALUER_BASIC")
app.config["STRIPE_PRICE_VALUER_PREMIUM"] = os.getenv("STRIPE_PRICE_VALUER_PREMIUM")

stripe.api_key = app.config["STRIPE_SECRET_KEY"]

STRIPE_PRICE_MAP = {
    ("buyer", "basic"):   os.getenv("STRIPE_PRICE_BUYER_BASIC"),
    ("buyer", "premium"): os.getenv("STRIPE_PRICE_BUYER_PREMIUM"),

    ("seller", "basic"):   os.getenv("STRIPE_PRICE_SELLER_BASIC"),
    ("seller", "premium"): os.getenv("STRIPE_PRICE_SELLER_PREMIUM"),

    ("valuer", "basic"):   os.getenv("STRIPE_PRICE_VALUER_BASIC"),
    ("valuer", "premium"): os.getenv("STRIPE_PRICE_VALUER_PREMIUM"),
}

# Upload config
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ALLOWED_EXTENSIONS"] = {"png", "jpg", "jpeg", "gif", "webp"}
app.config["ALLOWED_DOCUMENT_EXTENSIONS"] = {"pdf", "doc", "docx", "xls", "xlsx"}
app.config["ALLOWED_DOCUMENT_MIME_TYPES"] = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

# Private seller and deal-document storage. These files must never be served by
# Flask's public static route.
PRIVATE_UPLOAD_ROOT = os.getenv("PRIVATE_UPLOAD_ROOT") or os.path.join(
    app.instance_path, "private_uploads"
)
PRIVATE_UPLOAD_ROOT = os.path.abspath(PRIVATE_UPLOAD_ROOT)
os.makedirs(PRIVATE_UPLOAD_ROOT, exist_ok=True)

SELLER_DOCS_FOLDER = os.path.join(PRIVATE_UPLOAD_ROOT, "seller_docs")
os.makedirs(SELLER_DOCS_FOLDER, exist_ok=True)
app.config["SELLER_DOCS_FOLDER"] = SELLER_DOCS_FOLDER

# Heads of Terms / deal docs upload folder
OFFER_DOCS_FOLDER = os.path.join(PRIVATE_UPLOAD_ROOT, "offer_docs")
os.makedirs(OFFER_DOCS_FOLDER, exist_ok=True)
app.config["OFFER_DOCS_FOLDER"] = OFFER_DOCS_FOLDER

DATA_ROOM_FOLDER = os.path.join(PRIVATE_UPLOAD_ROOT, "data_room")
os.makedirs(DATA_ROOM_FOLDER, exist_ok=True)
app.config["DATA_ROOM_FOLDER"] = DATA_ROOM_FOLDER

BUYER_EVIDENCE_FOLDER = os.path.join(PRIVATE_UPLOAD_ROOT, "buyer_evidence")
os.makedirs(BUYER_EVIDENCE_FOLDER, exist_ok=True)
app.config["BUYER_EVIDENCE_FOLDER"] = BUYER_EVIDENCE_FOLDER

# -------------------------------------------------------------------
# Deal / introduction status pipeline
# -------------------------------------------------------------------

INTRO_STATUSES = [
    ("pending_seller_request", "Pending seller request"),
    ("initiated", "Initiated"),
    ("nda_signed", "NDA signed"),
    ("viewing", "Viewing"),
    ("offer_made", "Offer made"),
    ("offer_accepted", "Offer accepted"),
    ("completed", "Completed"),
    ("declined", "Declined"),
    ("failed", "Failed"),
]

DATA_ROOM_STAGES = (
    ("teaser", "Teaser", 0),
    ("nda", "NDA signed", 1),
    ("due_diligence", "Due diligence", 2),
    ("transaction", "Transaction", 3),
)
DATA_ROOM_CATEGORIES = (
    ("overview", "Business overview", "teaser"),
    ("financial", "Financial information", "nda"),
    ("legal", "Legal and corporate", "due_diligence"),
    ("operational", "Operational due diligence", "due_diligence"),
    ("property", "Property and assets", "due_diligence"),
    ("offer", "Offers and transaction documents", "transaction"),
    ("other", "Other", "nda"),
)




# -------------------------------------------------------------------
# Models
# -------------------------------------------------------------------


DEFAULT_SECTORS = (
    {
        "slug": "healthcare-social-care",
        "name": "Healthcare & Social Care",
        "attributes": [
            {"key": "unit_count", "label": "Beds / registered places", "type": "integer"},
            {"key": "capacity_utilisation", "label": "Occupancy / utilisation (%)", "type": "percent"},
            {"key": "regulatory_rating", "label": "Regulatory rating", "type": "text"},
        ],
    },
    {
        "slug": "hospitality-leisure",
        "name": "Hospitality & Leisure",
        "attributes": [
            {"key": "unit_count", "label": "Rooms / trading units", "type": "integer"},
            {"key": "capacity_utilisation", "label": "Occupancy / utilisation (%)", "type": "percent"},
            {"key": "location_count", "label": "Number of locations", "type": "integer"},
        ],
    },
    {
        "slug": "professional-services",
        "name": "Professional Services",
        "attributes": [
            {"key": "employee_count", "label": "Employees", "type": "integer"},
            {"key": "location_count", "label": "Number of offices", "type": "integer"},
            {"key": "recurring_revenue_percent", "label": "Recurring revenue (%)", "type": "percent"},
        ],
    },
    {
        "slug": "retail-ecommerce",
        "name": "Retail & E-commerce",
        "attributes": [
            {"key": "employee_count", "label": "Employees", "type": "integer"},
            {"key": "location_count", "label": "Stores / locations", "type": "integer"},
            {"key": "online_revenue_percent", "label": "Online revenue (%)", "type": "percent"},
        ],
    },
    {
        "slug": "technology-software",
        "name": "Technology & Software",
        "attributes": [
            {"key": "employee_count", "label": "Employees", "type": "integer"},
            {"key": "recurring_revenue_percent", "label": "Recurring revenue (%)", "type": "percent"},
            {"key": "customer_count", "label": "Active customers", "type": "integer"},
        ],
    },
    {
        "slug": "manufacturing",
        "name": "Manufacturing",
        "attributes": [
            {"key": "employee_count", "label": "Employees", "type": "integer"},
            {"key": "location_count", "label": "Production sites", "type": "integer"},
            {"key": "capacity_utilisation", "label": "Capacity utilisation (%)", "type": "percent"},
        ],
    },
    {
        "slug": "construction-property",
        "name": "Construction & Property",
        "attributes": [
            {"key": "employee_count", "label": "Employees", "type": "integer"},
            {"key": "location_count", "label": "Operating locations", "type": "integer"},
            {"key": "contracted_revenue_percent", "label": "Contracted revenue (%)", "type": "percent"},
        ],
    },
    {
        "slug": "recruitment",
        "name": "Recruitment",
        "attributes": [
            {"key": "employee_count", "label": "Employees", "type": "integer"},
            {"key": "location_count", "label": "Offices", "type": "integer"},
            {"key": "contract_revenue_percent", "label": "Contract revenue (%)", "type": "percent"},
        ],
    },
    {"slug": "other", "name": "Other", "attributes": []},
)


class Sector(db.Model):
    __tablename__ = "sector"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    attribute_schema = db.Column(db.JSON, nullable=False, default=list)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    sort_order = db.Column(db.Integer, nullable=False, default=0)


def format_minor_units(value, currency="GBP"):
    if value is None:
        return None
    symbols = {"GBP": "£", "EUR": "€", "USD": "$"}
    code = (currency or "GBP").upper()
    amount = Decimal(value) / Decimal(100)
    formatted = (
        f"{amount:,.0f}"
        if amount == amount.to_integral_value()
        else f"{amount:,.2f}"
    )
    return f"{symbols.get(code, code + ' ')}{formatted}"


def parse_major_units(value):
    raw = (value or "").strip().replace(",", "")
    if not raw:
        return None
    try:
        amount = Decimal(raw)
    except InvalidOperation as exc:
        raise ValueError("Enter a valid monetary amount.") from exc
    if amount < 0:
        raise ValueError("Monetary amounts cannot be negative.")
    return int((amount * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'seller','buyer','admin','valuer'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    email_verified_at = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    security_stamp = db.Column(db.Integer, nullable=False, default=0)

    # Flask-Login methods
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    # Password helpers
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def email_is_verified(self):
        return self.email_verified_at is not None


class LoginAttempt(db.Model):
    __tablename__ = "login_attempt"

    id = db.Column(db.Integer, primary_key=True)
    key_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    failed_count = db.Column(db.Integer, nullable=False, default=0)
    first_failed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    blocked_until = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Listing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )
    listing_code = db.Column(db.String(20), unique=True)
    title = db.Column(db.String(255), nullable=False)
    region = db.Column(db.String(100))
    sector_id = db.Column(db.Integer, db.ForeignKey("sector.id"), index=True)
    attributes = db.Column(db.JSON, nullable=False, default=dict)
    asking_price_minor = db.Column(db.BigInteger)
    revenue_minor = db.Column(db.BigInteger)
    ebitda_minor = db.Column(db.BigInteger)
    currency = db.Column(db.String(3), nullable=False, default="GBP")
    care_type = db.Column(db.String(100))
    beds = db.Column(db.Integer)
    occupancy_percent = db.Column(db.Integer)
    cqc_rating = db.Column(db.String(50))
    tenure = db.Column(db.String(50))
    revenue_band = db.Column(db.String(50))
    ebitda_band = db.Column(db.String(50))
    guide_price_band = db.Column(db.String(50))
    short_description = db.Column(db.Text)
    is_confidential = db.Column(db.Boolean, default=True)
    status = db.Column(
        db.String(20), default="draft", index=True
    )  # 'draft','live','under_offer','sold','archived'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # legacy single photo (keep so older code still works)
    photo_filename = db.Column(db.String(255))

    seller = db.relationship("User", backref="listings", lazy=True)
    sector = db.relationship("Sector", backref="listings", lazy=True)

    photos = db.relationship(
        "ListingPhoto",
        backref="listing",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="ListingPhoto.created_at",
    )

    @property
    def sector_name(self):
        return self.sector.name if self.sector else self.care_type

    @property
    def guide_price_display(self):
        return format_minor_units(self.asking_price_minor, self.currency) or self.guide_price_band

    @property
    def revenue_display(self):
        return format_minor_units(self.revenue_minor, self.currency) or self.revenue_band

    @property
    def ebitda_display(self):
        return format_minor_units(self.ebitda_minor, self.currency) or self.ebitda_band

    @property
    def headline_metric(self):
        values = self.attributes or {}
        for key in ("unit_count", "employee_count", "location_count", "customer_count"):
            if values.get(key) not in (None, ""):
                labels = {
                    "unit_count": "units",
                    "employee_count": "employees",
                    "location_count": "locations",
                    "customer_count": "customers",
                }
                return f"{values[key]} {labels[key]}"
        if self.beds is not None:
            return f"{self.beds} units"
        return None


def get_sector_options():
    rows = Sector.query.filter_by(is_active=True).order_by(
        Sector.sort_order.asc(), Sector.name.asc()
    ).all()
    if rows:
        return rows
    return [
        {
            "slug": item["slug"],
            "name": item["name"],
            "attribute_schema": item["attributes"],
        }
        for item in DEFAULT_SECTORS
    ]


def resolve_sector(value):
    value = (value or "").strip()[:120]
    if not value:
        return None
    sector = Sector.query.filter(
        (Sector.slug == value) | (Sector.name == value)
    ).first()
    if sector:
        return sector
    default = next(
        (item for item in DEFAULT_SECTORS if value in (item["slug"], item["name"])),
        None,
    )
    name = default["name"] if default else value
    slug = default["slug"] if default else re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    sector = Sector(
        slug=slug[:100] or f"sector-{uuid.uuid4().hex[:8]}",
        name=name,
        attribute_schema=(default or {}).get("attributes", []),
        sort_order=len(DEFAULT_SECTORS),
    )
    db.session.add(sector)
    db.session.flush()
    return sector


def parse_listing_attributes(form, sector):
    values = {}
    for field in (sector.attribute_schema if sector else []):
        key = field.get("key")
        raw = (form.get(f"attribute_{key}") or "").strip()
        if not key or raw == "":
            continue
        if field.get("type") in ("integer", "percent"):
            try:
                number = int(raw)
            except ValueError as exc:
                raise ValueError(f"{field.get('label', key)} must be a whole number.") from exc
            if number < 0 or (field.get("type") == "percent" and number > 100):
                raise ValueError(f"Enter a valid value for {field.get('label', key)}.")
            values[key] = number
        else:
            values[key] = raw[:255]
    return values


def merge_legacy_listing_attributes(form, values):
    """Accept the old care-focused form fields during the transition."""
    for form_key, attribute_key, is_percent in (
        ("beds", "unit_count", False),
        ("occupancy_percent", "capacity_utilisation", True),
    ):
        raw = (form.get(form_key) or "").strip()
        if not raw or attribute_key in values:
            continue
        try:
            number = int(raw)
        except ValueError as exc:
            raise ValueError(f"{form_key.replace('_', ' ').title()} must be a whole number.") from exc
        if number < 0 or (is_percent and number > 100):
            raise ValueError(f"Enter a valid {form_key.replace('_', ' ')}.")
        values[attribute_key] = number
    legacy_rating = (form.get("cqc_rating") or "").strip()
    if legacy_rating and "regulatory_rating" not in values:
        values["regulatory_rating"] = legacy_rating[:255]
    return values


class ListingPhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    listing_id = db.Column(
        db.Integer,
        db.ForeignKey("listing.id"),
        nullable=False,
        index=True,
    )
    filename = db.Column(db.String(255), nullable=False)
    is_cover = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ShortlistItem(db.Model):
    __tablename__ = "shortlist_item"

    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False, index=True
    )
    listing_id = db.Column(
        db.Integer, db.ForeignKey("listing.id"), nullable=False, index=True
    )
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    buyer = db.relationship("User", backref="shortlist_items", lazy=True)
    listing = db.relationship("Listing", backref="shortlist_items", lazy=True)

    __table_args__ = (
        db.UniqueConstraint(
            "buyer_id", "listing_id", name="uq_shortlist_item_buyer_listing"
        ),
    )


class SavedSearch(db.Model):
    __tablename__ = "saved_search"

    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False, index=True
    )
    name = db.Column(db.String(120), nullable=False)
    search_term = db.Column(db.String(120))
    region = db.Column(db.String(100))
    care_type = db.Column(db.String(100))
    email_alerts = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    buyer = db.relationship("User", backref="saved_searches", lazy=True)

    __table_args__ = (
        db.UniqueConstraint(
            "buyer_id", "name", name="uq_saved_search_buyer_name"
        ),
    )


class NotificationPreference(db.Model):
    __tablename__ = "notification_preference"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False
    )
    email_mode = db.Column(db.String(20), nullable=False, default="weekly")
    updated_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    user = db.relationship(
        "User", backref=db.backref("notification_preference", uselist=False)
    )


class Notification(db.Model):
    __tablename__ = "notification"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False, index=True
    )
    event_type = db.Column(db.String(50), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    target_url = db.Column(db.String(500))
    dedupe_key = db.Column(db.String(255), nullable=False)
    email_eligible = db.Column(db.Boolean, nullable=False, default=True)
    read_at = db.Column(db.DateTime)
    email_sent_at = db.Column(db.DateTime)
    digest_sent_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User", backref="notifications")

    __table_args__ = (
        db.UniqueConstraint(
            "user_id", "dedupe_key", name="uq_notification_user_dedupe"
        ),
        db.Index("ix_notification_user_unread", "user_id", "read_at"),
    )


class AuditEvent(db.Model):
    """Append-only record of security and operational activity."""

    __tablename__ = "audit_event"

    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    subject_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    event_type = db.Column(db.String(80), nullable=False, index=True)
    resource_type = db.Column(db.String(50), index=True)
    resource_id = db.Column(db.String(100))
    summary = db.Column(db.String(255), nullable=False)
    details = db.Column(db.JSON, nullable=False, default=dict)
    ip_hash = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    actor = db.relationship("User", foreign_keys=[actor_id])
    subject_user = db.relationship("User", foreign_keys=[subject_user_id])


class Enquiry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    listing_id = db.Column(
        db.Integer,
        db.ForeignKey("listing.id"),
        nullable=False,
        index=True,
    )
    buyer_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )
    message = db.Column(db.Text, nullable=False)
    nda_accepted = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default="new")  # 'new','read','archived'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    listing = db.relationship("Listing", backref="enquiries", lazy=True)
    buyer = db.relationship("User", backref="buyer_enquiries", lazy=True)


class BuyerProfile(db.Model):
    __tablename__ = "buyer_profile"  # keep the existing table name

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False
    )

    # ---- Legacy/simple fields (kept for backwards compatibility) ----
    region = db.Column(db.String(100))          # old single-region field
    care_type = db.Column(db.String(100))       # old single-care-type field
    min_price_band = db.Column(db.String(50))   # e.g. "<£500k"
    max_price_band = db.Column(db.String(50))   # e.g. "£3m+"
    experience_level = db.Column(db.String(50)) # e.g. "First-time buyer"

    # ---- New professional buyer intake fields ----

    # Basic details
    business_name = db.Column(db.String(255))
    contact_person = db.Column(db.String(255))
    phone = db.Column(db.String(50))

    # Deal appetite
    investment_type = db.Column(db.String(50))   # acquisition / lease / dev / mixed
    deal_structure = db.Column(db.String(50))    # asset / share / leasehold / freehold / either

    # Financial capacity
    min_budget = db.Column(db.String(50))        # e.g. "£1m"
    max_budget = db.Column(db.String(50))        # e.g. "£10m+"
    proof_of_funds = db.Column(db.String(20))    # "yes", "no", or None
    preferred_multiple = db.Column(db.String(50))# e.g. "5–7x EBITDA"
    funding_source = db.Column(db.String(50))    # cash / bank / private equity / mixed

    # Target criteria (stored as comma-separated lists)
    preferred_regions = db.Column(db.String(255))  # CSV of regions
    care_types = db.Column(db.String(255))         # CSV of care types

    beds_min = db.Column(db.Integer)
    beds_max = db.Column(db.Integer)
    quality_preference = db.Column(db.String(100))  # e.g. "Good and above"
    turnaround_interest = db.Column(db.String(50))  # e.g. "Yes", "Selected", "No"

    # Timing & strategy
    transaction_timeline = db.Column(db.String(50))  # 0–3m / 3–6m / 6–12m / flexible
    expansion_strategy = db.Column(db.Text)          # narrative

    # Advisors & due diligence
    has_buy_side_advisor = db.Column(db.Boolean, default=False)
    advisor_details = db.Column(db.Text)
    requirements_dd = db.Column(db.String(255))      # CSV of DD requirements

    # Confidentiality
    nda_signed = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship(
        "User",
        backref=db.backref("buyer_profile", uselist=False),
    )

    def is_complete(self) -> bool:
        """
        Heuristic for 'good enough' profile completion.
        We don’t need perfection, just enough to be useful.
        """
        core_fields = [
            self.business_name,
            self.investment_type,
            self.min_budget,
            self.max_budget,
            self.preferred_regions,
            self.care_types,
            self.transaction_timeline,
        ]

        # All core fields present & NDA ticked
        if any(not (f and str(f).strip()) for f in core_fields):
            return False
        if not self.nda_signed:
            return False
        return True


class BuyerQualification(db.Model):
    __tablename__ = "buyer_qualification"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    legal_name = db.Column(db.String(255))
    company_number = db.Column(db.String(50))
    website = db.Column(db.String(255))
    acquisitions_completed = db.Column(db.Integer, nullable=False, default=0)
    track_record_summary = db.Column(db.Text)
    identity_status = db.Column(db.String(20), nullable=False, default="not_submitted", index=True)
    business_status = db.Column(db.String(20), nullable=False, default="not_submitted", index=True)
    funds_status = db.Column(db.String(20), nullable=False, default="not_submitted", index=True)
    funds_filename = db.Column(db.String(255))
    funds_original_filename = db.Column(db.String(255))
    funds_mime_type = db.Column(db.String(100))
    funds_size_bytes = db.Column(db.Integer)
    submitted_at = db.Column(db.DateTime)
    reviewed_at = db.Column(db.DateTime)
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    review_notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship(
        "User", foreign_keys=[user_id],
        backref=db.backref("buyer_qualification", uselist=False),
    )
    reviewed_by = db.relationship("User", foreign_keys=[reviewed_by_id])

    @property
    def overall_status(self):
        statuses = {self.identity_status, self.business_status, self.funds_status}
        if statuses == {"verified"}:
            return "verified"
        if "rejected" in statuses:
            return "action_required"
        if statuses & {"pending", "verified"}:
            return "in_review"
        return "not_submitted"


class Lead(db.Model):
    __tablename__ = "leads"

    id = db.Column(db.Integer, primary_key=True)
    listing_id = db.Column(
        db.Integer,
        db.ForeignKey("listing.id"),
        nullable=False,
        index=True,
    )
    buyer_name = db.Column(db.String(200), nullable=False)
    buyer_email = db.Column(db.String(200), nullable=False)
    buyer_phone = db.Column(db.String(100))
    buyer_company = db.Column(db.String(200))
    message = db.Column(db.Text, nullable=False)

    status = db.Column(db.String(50), default="new", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    listing = db.relationship("Listing", backref=db.backref("leads", lazy=True))


# -------------------------------------------------------------------
# Expanded Marketplace Models (Buyers, Sellers, Valuers, Subscriptions)
# -------------------------------------------------------------------


class ValuerProfile(db.Model):
    __tablename__ = "valuer_profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False
    )

    company_name = db.Column(db.String(255))
    accreditation = db.Column(db.String(255))
    regions = db.Column(db.String(255))  # comma-separated list or JSON
    pricing_notes = db.Column(db.Text)
    bio = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship(
        "User",
        backref=db.backref("valuer_profile", uselist=False),
    )

# -------------------------------------------------------------------
# Seller Profile Models (Business-Level Seller Information)
# -------------------------------------------------------------------

class SellerProfile(db.Model):
    __tablename__ = "seller_profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False
    )

    business_name = db.Column(db.String(255))

    turnover = db.Column(db.String(100))
    ebitda = db.Column(db.String(100))
    profit = db.Column(db.String(100))
    loss = db.Column(db.String(100))
    assets = db.Column(db.String(255))
    debts = db.Column(db.String(255))
    staff_count = db.Column(db.Integer)

    regions = db.Column(db.String(255))     # comma-separated list
    care_type = db.Column(db.String(100))

    summary = db.Column(db.Text)

    nda_accepted = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    user = db.relationship(
        "User",
        backref=db.backref("seller_profile", uselist=False),
    )


class SellerProfileDocument(db.Model):
    __tablename__ = "seller_profile_documents"

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(
        db.Integer,
        db.ForeignKey("seller_profiles.id"),
        nullable=False,
        index=True,
    )
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    profile = db.relationship("SellerProfile", backref="documents")


class Subscription(db.Model):
    __tablename__ = "subscriptions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )

    # "basic" or "premium"
    tier = db.Column(db.String(20), nullable=False)

    # "buyer", "seller", "valuer"
    role = db.Column(db.String(20), nullable=False)

    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    renews_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    # Stripe integration
    stripe_subscription_id = db.Column(db.String(255), unique=True)
    stripe_customer_id = db.Column(db.String(255))

    user = db.relationship("User", backref="subscriptions")


class Payment(db.Model):
    __tablename__ = "payments"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )

    amount = db.Column(db.Integer)  # pence
    currency = db.Column(db.String(10), default="GBP")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    stripe_payment_id = db.Column(db.String(255), unique=True)
    description = db.Column(db.String(255))

    user = db.relationship("User", backref="payments")

def upsert_subscription_from_stripe(
    user_id: int,
    role: str,
    tier: str,
    stripe_subscription_id: str,
    stripe_customer_id: str,
    current_period_end: int | None = None,
    active: bool = True,
):
    """
    Create or update a Subscription row based on Stripe subscription info.
    """
    sub = (
        Subscription.query
        .filter_by(user_id=user_id, role=role, tier=tier)
        .first()
    )

    renews_at = None
    if current_period_end:
        # Stripe gives unix timestamp seconds
        renews_at = datetime.utcfromtimestamp(current_period_end)

    if sub is None:
        sub = Subscription(
            user_id=user_id,
            role=role,
            tier=tier,
            stripe_subscription_id=stripe_subscription_id,
            stripe_customer_id=stripe_customer_id,
            renews_at=renews_at,
            is_active=active,
        )
        db.session.add(sub)
    else:
        sub.stripe_subscription_id = stripe_subscription_id
        sub.stripe_customer_id = stripe_customer_id
        sub.renews_at = renews_at
        sub.is_active = active

    db.session.commit()

class Financials(db.Model):
    __tablename__ = "financials"

    id = db.Column(db.Integer, primary_key=True)
    listing_id = db.Column(
        db.Integer,
        db.ForeignKey("listing.id"),
        unique=True,
        nullable=False,
    )

    turnover = db.Column(db.String(100))
    ebitda = db.Column(db.String(100))
    profit = db.Column(db.String(100))
    loss = db.Column(db.String(100))
    assets = db.Column(db.String(255))
    debts = db.Column(db.String(255))
    staff_count = db.Column(db.Integer)

    year_end = db.Column(db.String(50))  # e.g. "YE Mar 2024"

    listing = db.relationship(
        "Listing",
        backref=db.backref("financials", uselist=False),
    )


class BuyerCriteria(db.Model):
    __tablename__ = "buyer_criteria"

    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        unique=True,
        nullable=False,
    )

    regions = db.Column(db.String(255))  # comma-separated
    care_types = db.Column(db.String(255))  # comma-separated

    min_turnover = db.Column(db.String(50))
    max_turnover = db.Column(db.String(50))
    min_beds = db.Column(db.Integer)
    max_beds = db.Column(db.Integer)

    funding_ready = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)

    buyer = db.relationship(
        "User",
        backref=db.backref("criteria", uselist=False),
    )


class Introduction(db.Model):
    __tablename__ = "introductions"
    __table_args__ = (
        db.UniqueConstraint(
            "buyer_id",
            "seller_id",
            "listing_id",
            name="uq_introduction_parties_listing",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)

    buyer_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )
    seller_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )
    listing_id = db.Column(
        db.Integer,
        db.ForeignKey("listing.id"),
        nullable=False,
        index=True,
    )

    # Deal status pipeline
    status = db.Column(
        db.String(20),
        default="initiated",
        index=True,
        # initiated → nda_signed → viewing → offer_made → offer_accepted → completed → failed
    )

    # --- NEW: Offer-stage fields ---
    # Keep these deliberately string-y for now; we can normalise later if needed.
    offer_amount = db.Column(db.String(100))        # e.g. "£3,250,000"
    offer_date = db.Column(db.DateTime)            # date the offer was made/received
    offer_terms = db.Column(db.Text)               # headline conditional terms
    funding_confirmed = db.Column(db.Boolean, default=False)
    heads_of_terms_filename = db.Column(db.String(255))  # stored in OFFER_DOCS_FOLDER

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    buyer = db.relationship("User", foreign_keys=[buyer_id])
    seller = db.relationship("User", foreign_keys=[seller_id])
    listing = db.relationship("Listing")


class WorkspaceMessage(db.Model):
    __tablename__ = "workspace_message"

    id = db.Column(db.Integer, primary_key=True)
    introduction_id = db.Column(db.Integer, db.ForeignKey("introductions.id"), nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    message_type = db.Column(db.String(20), nullable=False, default="message", index=True)
    body = db.Column(db.Text, nullable=False)
    resolved_at = db.Column(db.DateTime)
    resolved_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    introduction = db.relationship("Introduction", backref="workspace_messages")
    author = db.relationship("User", foreign_keys=[author_id])
    resolved_by = db.relationship("User", foreign_keys=[resolved_by_id])


class WorkspaceTask(db.Model):
    __tablename__ = "workspace_task"

    id = db.Column(db.Integer, primary_key=True)
    introduction_id = db.Column(db.Integer, db.ForeignKey("introductions.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="todo", index=True)
    due_date = db.Column(db.Date, index=True)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    introduction = db.relationship("Introduction", backref="workspace_tasks")
    owner = db.relationship("User", foreign_keys=[owner_id])
    created_by = db.relationship("User", foreign_keys=[created_by_id])


class WorkspaceMilestone(db.Model):
    __tablename__ = "workspace_milestone"

    id = db.Column(db.Integer, primary_key=True)
    introduction_id = db.Column(db.Integer, db.ForeignKey("introductions.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    due_date = db.Column(db.Date)
    status = db.Column(db.String(20), nullable=False, default="planned", index=True)
    sort_order = db.Column(db.Integer, nullable=False, default=0)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    introduction = db.relationship("Introduction", backref="workspace_milestones")
    created_by = db.relationship("User", foreign_keys=[created_by_id])


class StructuredOffer(db.Model):
    """Append-only commercial offer record for an introduction."""

    __tablename__ = "structured_offer"
    __table_args__ = (
        db.UniqueConstraint(
            "introduction_id", "sequence", name="uq_structured_offer_sequence"
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    introduction_id = db.Column(
        db.Integer, db.ForeignKey("introductions.id"), nullable=False, index=True
    )
    parent_offer_id = db.Column(
        db.Integer, db.ForeignKey("structured_offer.id"), index=True
    )
    sequence = db.Column(db.Integer, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    amount_minor = db.Column(db.BigInteger, nullable=False)
    currency = db.Column(db.String(3), nullable=False, default="GBP")
    terms = db.Column(db.Text)
    conditions = db.Column(db.Text)
    expires_on = db.Column(db.Date, index=True)
    status = db.Column(db.String(20), nullable=False, default="submitted", index=True)
    responded_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    introduction = db.relationship("Introduction", backref="structured_offers")
    creator = db.relationship("User", foreign_keys=[created_by_id])
    recipient = db.relationship("User", foreign_keys=[recipient_id])
    parent = db.relationship("StructuredOffer", remote_side=[id], backref="counter_offers")

    @property
    def display_amount(self):
        return format_minor_units(self.amount_minor, self.currency)


class DataRoomDocument(db.Model):
    __tablename__ = "data_room_document"

    id = db.Column(db.Integer, primary_key=True)
    listing_id = db.Column(db.Integer, db.ForeignKey("listing.id"), nullable=False, index=True)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    document_key = db.Column(db.String(32), nullable=False, index=True)
    version = db.Column(db.Integer, nullable=False, default=1)
    category = db.Column(db.String(30), nullable=False, index=True)
    disclosure_stage = db.Column(db.String(30), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(100))
    size_bytes = db.Column(db.Integer)
    is_current = db.Column(db.Boolean, nullable=False, default=True, index=True)
    archived_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    listing = db.relationship("Listing", backref="data_room_documents")
    uploaded_by = db.relationship("User", foreign_keys=[uploaded_by_id])

    __table_args__ = (
        db.UniqueConstraint("document_key", "version", name="uq_data_room_document_version"),
    )


class DataRoomAccess(db.Model):
    __tablename__ = "data_room_access"

    id = db.Column(db.Integer, primary_key=True)
    introduction_id = db.Column(
        db.Integer, db.ForeignKey("introductions.id"), unique=True, nullable=False
    )
    disclosure_stage = db.Column(db.String(30), nullable=False, default="teaser")
    granted_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    granted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    revoked_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    introduction = db.relationship(
        "Introduction", backref=db.backref("data_room_access", uselist=False)
    )
    granted_by = db.relationship("User", foreign_keys=[granted_by_id])


class IntroductionStatusHistory(db.Model):
    __tablename__ = "introduction_status_history"

    id = db.Column(db.Integer, primary_key=True)
    introduction_id = db.Column(
        db.Integer,
        db.ForeignKey("introductions.id"),
        nullable=False,
        index=True,
    )
    old_status = db.Column(db.String(20))
    new_status = db.Column(db.String(20))
    changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    changed_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    note = db.Column(db.Text)

    introduction = db.relationship("Introduction", backref="status_history")
    changed_by = db.relationship("User", foreign_keys=[changed_by_user_id])




class ValuationRequest(db.Model):
    __tablename__ = "valuation_requests"

    id = db.Column(db.Integer, primary_key=True)

    listing_id = db.Column(
        db.Integer,
        db.ForeignKey("listing.id"),
        nullable=False,
        index=True,
    )
    seller_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )
    valuer_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=True,
        index=True,
    )

    status = db.Column(
        db.String(20),
        default="pending",
        index=True,
        # pending → accepted → completed → declined
    )

    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    listing = db.relationship("Listing", backref="valuation_requests")
    seller = db.relationship("User", foreign_keys=[seller_id])
    valuer = db.relationship("User", foreign_keys=[valuer_id])


class Deal(db.Model):
    __tablename__ = "deals"

    id = db.Column(db.Integer, primary_key=True)
    introduction_id = db.Column(
        db.Integer,
        db.ForeignKey("introductions.id"),
        unique=True,
        nullable=False,
    )

    agreed_price = db.Column(db.String(100))      # e.g. "£3,500,000"
    completion_date = db.Column(db.DateTime)
    broker_commission_percent = db.Column(db.Float, default=2.0)
    broker_commission_amount = db.Column(db.Integer)  # pence

    status = db.Column(
        db.String(20),
        default="in_progress"   # in_progress → completed → aborted
    )

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    introduction = db.relationship(
        "Introduction",
        backref=db.backref("deal", uselist=False),
    )


class PageContent(db.Model):
    __tablename__ = "page_content"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(255), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)

    description = db.Column(db.String(255))
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )
    updated_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    updated_by = db.relationship("User")


def get_page_content(slug: str, default: str = "") -> str:
    """
    Look up copy block by slug, create it with default if missing.
    """
    block = PageContent.query.filter_by(slug=slug).first()
    if block:
        return block.content

    # Create on first use so admin can edit later
    block = PageContent(slug=slug, content=default)
    db.session.add(block)
    db.session.commit()
    return block.content


# -------------------------------------------------------------------
# Flask-Login & helpers
# -------------------------------------------------------------------


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def role_required(*roles):
    """Decorator to require one of the given roles."""
    from functools import wraps

    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash("You don't have access to that page.")
                return redirect(url_for("login"))
            return f(*args, **kwargs)

        return decorated

    return wrapper


def has_active_subscription(user, role: str, tier: str = "premium") -> bool:
    """
    Return True if the user has an active subscription for the given role/tier.
    Safe even if the Subscription model isn't available (returns False).
    """
    SubscriptionModel = globals().get("Subscription")
    if SubscriptionModel is None:
        return False

    if not getattr(user, "is_authenticated", False):
        return False

    now = datetime.utcnow()
    sub = (
        SubscriptionModel.query
        .filter_by(user_id=user.id, role=role, tier=tier, is_active=True)
        .filter(
            (SubscriptionModel.renews_at.is_(None))
            | (SubscriptionModel.renews_at > now)
        )
        .first()
    )
    return sub is not None

def get_active_subscription(user, role: str | None = None) -> Subscription | None:
    """
    Return the most recent active subscription for this user.
    If role is given, restrict to that role ('buyer'/'seller'/'valuer').
    """
    SubscriptionModel = globals().get("Subscription")
    if SubscriptionModel is None:
        return None

    if not getattr(user, "is_authenticated", False):
        return None

    query = SubscriptionModel.query.filter_by(
        user_id=user.id,
        is_active=True,
    ).filter(
        (SubscriptionModel.renews_at.is_(None))
        | (SubscriptionModel.renews_at > datetime.utcnow())
    )

    if role:
        query = query.filter_by(role=role)

    return query.order_by(SubscriptionModel.started_at.desc()).first()




def get_stripe_price_id(role: str, tier: str) -> str | None:
    """
    Map (role, tier) -> Stripe Price ID from config.
    role: buyer|seller|valuer
    tier: basic|premium
    """
    role = (role or "").lower()
    tier = (tier or "").lower()

    key = f"STRIPE_PRICE_{role.upper()}_{tier.upper()}"
    return app.config.get(key)

def get_active_subscription_for_role(user, role: str):
    """
    Return the currently active Subscription for this user+role,
    preferring 'premium' over 'basic' if multiple exist.
    """
    SubscriptionModel = globals().get("Subscription")
    if SubscriptionModel is None or not getattr(user, "is_authenticated", False):
        return None

    q = (
        SubscriptionModel.query
        .filter_by(user_id=user.id, role=role, is_active=True)
        .filter(
            (SubscriptionModel.renews_at.is_(None))
            | (SubscriptionModel.renews_at > datetime.utcnow())
        )
    )

    # Prefer premium if both exist
    subs = q.all()
    if not subs:
        return None

    # Tiny preference logic
    premium = [s for s in subs if s.tier == "premium"]
    if premium:
        return premium[0]
    return subs[0]


def require_subscription(role: str, tier: str = "premium"):
    """
    Decorator to protect routes behind an active subscription.
    Example: @require_subscription("buyer", "premium")
    """
    from functools import wraps

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in to access this page.")
                return redirect(url_for("login", next=request.path))

            if current_user.role != role:
                flash("You don't have access to this area.")
                return redirect(url_for("index"))

            if not has_active_subscription(current_user, role, tier):
                flash("You need an active subscription to access this page.", "warning")
                try:
                    return redirect(url_for("pricing"))
                except Exception:
                    return redirect(url_for("index"))

            return f(*args, **kwargs)

        return wrapped

    return decorator

def upsert_subscription(user_id: int, role: str, tier: str = "premium", months: int = 1):
    """
    Create or update an active subscription for a user.
    - role: 'buyer' | 'seller' | 'valuer'
    - tier: 'basic' | 'premium' (we mostly care about 'premium' for gating)
    """
    SubscriptionModel = globals().get("Subscription")
    if SubscriptionModel is None:
        return None

    now = datetime.utcnow()
    renews_at = now + timedelta(days=30 * months)

    sub = (
        SubscriptionModel.query
        .filter_by(user_id=user_id, role=role, tier=tier)
        .first()
    )

    if sub:
        sub.is_active = True
        sub.started_at = sub.started_at or now
        sub.renews_at = renews_at
    else:
        sub = SubscriptionModel(
            user_id=user_id,
            role=role,
            tier=tier,
            started_at=now,
            renews_at=renews_at,
            is_active=True,
        )
        db.session.add(sub)

    db.session.commit()
    return sub




def is_premium_seller(user) -> bool:
    return has_active_subscription(user, "seller", "premium")


def is_premium_buyer(user) -> bool:
    return has_active_subscription(user, "buyer", "premium")


def can_view_listing_sensitive(user, listing: Listing) -> bool:
    """Central disclosure policy for confidential listing fields."""
    if not listing.is_confidential and listing.status == "live":
        return True
    if not getattr(user, "is_authenticated", False):
        return False
    if user.role == "admin":
        return True
    if user.role == "seller" and listing.seller_id == user.id:
        return True
    return user.role == "buyer" and is_premium_buyer(user)


def can_access_listing(user, listing: Listing) -> bool:
    """Allow public live listings plus owners/admins for non-live records."""
    if listing.status == "live":
        return True
    if not getattr(user, "is_authenticated", False):
        return False
    return user.role == "admin" or (
        user.role == "seller" and listing.seller_id == user.id
    )


def is_safe_redirect_target(target: str | None) -> bool:
    if not target:
        return False
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return (
        redirect_url.scheme in {"http", "https"}
        and host_url.netloc == redirect_url.netloc
    )


def generate_listing_code():
    """Generate codes like CH-0001, CH-0002, etc."""
    last = Listing.query.order_by(Listing.id.desc()).first()
    next_num = (last.id + 1) if last else 1
    return f"CH-{next_num:04d}"

def parse_amount_to_pence(amount_str: str | None) -> int | None:
    """
    Converts something like:
      "£3,500,000" or "3500000" or "3.5m"
    into an integer number of pence (approx).
    If parsing fails, returns None.
    """
    if not amount_str:
        return None

    s = amount_str.strip().lower()
    if not s:
        return None

    # Handle 'm' or 'k' shorthand loosely: "3.5m", "750k"
    multiplier = 1.0
    if s.endswith("m"):
        multiplier = 1_000_000.0
        s = s[:-1]
    elif s.endswith("k"):
        multiplier = 1_000.0
        s = s[:-1]

    # Strip all non-digit / non-dot characters
    s = re.sub(r"[^\d.]", "", s)
    if not s:
        return None

    try:
        base = float(s)
        pounds = base * multiplier
        return int(round(pounds * 100))
    except ValueError:
        return None


def send_email(
    to_addresses,
    subject: str,
    html_body: str,
    text_body: str | None = None,
    reply_to: str | None = None,
) -> bool:
    if isinstance(to_addresses, str):
        to_addresses = [to_addresses]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = app.config["SMTP_DEFAULT_FROM"]
    msg["To"] = ", ".join(to_addresses)

    if reply_to:
        msg["Reply-To"] = reply_to

    if not text_body:
        text_body = (
            html_body.replace("<br>", "\n")
            .replace("<br/>", "\n")
            .replace("<br />", "\n")
        )

    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(app.config["SMTP_SERVER"], app.config["SMTP_PORT"]) as smtp:
            if app.config["SMTP_USE_TLS"]:
                smtp.starttls()

            if app.config["SMTP_USERNAME"] and app.config["SMTP_PASSWORD"]:
                smtp.login(
                    app.config["SMTP_USERNAME"], app.config["SMTP_PASSWORD"]
                )

            smtp.send_message(msg)

        return True
    except Exception as e:
        app.logger.error(f"Error sending email: {e}")
        return False

# -------- Introduction status notifications --------

def _label_for_intro_status(status_key: str) -> str:
    """Map internal status key to human-readable label."""
    mapping = {k: v for k, v in INTRO_STATUSES}
    return mapping.get(status_key, status_key.capitalize() if status_key else "Unknown")


def notify_introduction_status_change(intro: Introduction, old_status: str, new_status: str):
    """
    Send the operational broker email when an introduction changes status.
    Buyer and seller delivery is handled by persisted notification preferences.
    """
    internal_email = app.config.get("LEADS_NOTIFICATION_EMAIL")
    if not internal_email:
        # Nothing to send to if internal isn't configured
        return

    old_label = _label_for_intro_status(old_status or "initiated")
    new_label = _label_for_intro_status(new_status or "initiated")

    listing = intro.listing
    buyer = intro.buyer
    seller = intro.seller

    title = listing.title
    code = listing.listing_code or f"Ref {listing.id}"

    subject = f"[Intro #{intro.id}] Status changed: {old_label} → {new_label}"

    html_body = f"""
        <h2>Introduction status updated</h2>
        <p>
          <strong>Introduction ID:</strong> {intro.id}<br>
          <strong>Listing:</strong> {code} – {title}<br>
          <strong>Buyer:</strong> {buyer.email}<br>
          <strong>Seller:</strong> {seller.email}<br>
        </p>
        <p>
          <strong>Old status:</strong> {old_label}<br>
          <strong>New status:</strong> {new_label}<br>
          <strong>Changed at (UTC):</strong> {datetime.utcnow()}<br>
        </p>
        <p>
          View in admin: (log into Ownerlane and open Introductions).
        </p>
    """

    # 1) Internal broker notification
    send_email(
        to_addresses=internal_email,
        subject=subject,
        html_body=html_body,
    )

def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in app.config["ALLOWED_EXTENSIONS"]


def allowed_document(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in app.config["ALLOWED_DOCUMENT_EXTENSIONS"]


def data_room_stage_rank(stage: str | None) -> int:
    return {key: rank for key, _label, rank in DATA_ROOM_STAGES}.get(stage, -1)


def data_room_stage_label(stage: str | None) -> str:
    return {key: label for key, label, _rank in DATA_ROOM_STAGES}.get(stage, "No access")


def data_room_category_label(category: str | None) -> str:
    return {key: label for key, label, _stage in DATA_ROOM_CATEGORIES}.get(category, "Other")


def can_manage_data_room(user, listing: Listing) -> bool:
    return bool(
        getattr(user, "is_authenticated", False)
        and (user.role == "admin" or (user.role == "seller" and listing.seller_id == user.id))
    )


def can_access_deal_workspace(user, introduction: Introduction) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    if user.role == "admin":
        return True
    return bool(
        user.id in {introduction.buyer_id, introduction.seller_id}
        and introduction.status not in {"pending_seller_request", "declined", "failed"}
    )


def workspace_recipients(introduction: Introduction, exclude_user_id=None):
    return [
        user for user in (introduction.buyer, introduction.seller)
        if user.id != exclude_user_id
    ]


def can_negotiate_offer(user, introduction: Introduction) -> bool:
    return bool(
        can_access_deal_workspace(user, introduction)
        and user.role in {"buyer", "seller"}
        and user.id in {introduction.buyer_id, introduction.seller_id}
        and introduction.status != "completed"
    )


def _next_offer_sequence(introduction_id: int) -> int:
    latest = db.session.query(func.max(StructuredOffer.sequence)).filter_by(
        introduction_id=introduction_id
    ).scalar()
    return (latest or 0) + 1


def _offer_recipient(introduction: Introduction, creator_id: int) -> User:
    return introduction.seller if creator_id == introduction.buyer_id else introduction.buyer


def _parse_offer_form():
    currency = (request.form.get("currency") or "GBP").strip().upper()
    if currency not in {"GBP", "EUR", "USD"}:
        raise ValueError("Choose a supported currency.")
    amount_minor = parse_major_units(request.form.get("amount"))
    if not amount_minor:
        raise ValueError("Enter an offer greater than zero.")
    expires_on = None
    expires_raw = (request.form.get("expires_on") or "").strip()
    if expires_raw:
        try:
            expires_on = datetime.strptime(expires_raw, "%Y-%m-%d").date()
        except ValueError as exc:
            raise ValueError("Choose a valid expiry date.") from exc
        if expires_on < utcnow().date():
            raise ValueError("The expiry date cannot be in the past.")
    return {
        "amount_minor": amount_minor,
        "currency": currency,
        "terms": ((request.form.get("terms") or "").strip()[:5000] or None),
        "conditions": ((request.form.get("conditions") or "").strip()[:5000] or None),
        "expires_on": expires_on,
    }


def expire_structured_offers(introduction_id=None):
    """Expire open offers and return them for post-commit notifications."""
    query = StructuredOffer.query.filter(
        StructuredOffer.status == "submitted",
        StructuredOffer.expires_on.isnot(None),
        StructuredOffer.expires_on < utcnow().date(),
    )
    if introduction_id is not None:
        query = query.filter(StructuredOffer.introduction_id == introduction_id)
    expired = query.all()
    if not expired:
        return []
    now = utcnow()
    for offer in expired:
        offer.status = "expired"
        offer.responded_at = now
    db.session.commit()
    for offer in expired:
        record_audit_event(
            "offer.expired", "Structured offer expired",
            subject_user_id=offer.created_by_id, resource_type="structured_offer",
            resource_id=offer.id, actor_id=None,
            details={"introduction_id": offer.introduction_id, "sequence": offer.sequence},
        )
        publish_notification(
            offer.creator, event_type="offer_expired", title="Offer expired",
            body=f"Offer #{offer.sequence} for {offer.introduction.listing.listing_code or 'an introduction'} expired.",
            target_url=url_for("deal_workspace", intro_id=offer.introduction_id),
            dedupe_key=f"offer:{offer.id}:expired",
        )
    return expired


def buyer_data_room_access(user, listing: Listing):
    if not getattr(user, "is_authenticated", False) or user.role != "buyer":
        return None
    return (
        DataRoomAccess.query.join(Introduction)
        .filter(
            Introduction.buyer_id == user.id,
            Introduction.listing_id == listing.id,
            DataRoomAccess.revoked_at.is_(None),
        )
        .order_by(DataRoomAccess.updated_at.desc())
        .first()
    )


def can_download_data_room_document(user, document: DataRoomDocument) -> bool:
    if document.archived_at or not document.is_current:
        return False
    if can_manage_data_room(user, document.listing):
        return True
    access = buyer_data_room_access(user, document.listing)
    return bool(
        access
        and data_room_stage_rank(document.disclosure_stage)
        <= data_room_stage_rank(access.disclosure_stage)
    )


# Simple UK-ish region coordinates for map view
DEFAULT_COORD = (53.5, -2.5)  # Roughly North England

REGION_COORDS = {
    "North West": (53.8, -2.5),
    "North East": (54.9, -1.6),
    "Yorkshire & Humber": (53.9, -1.1),
    "Midlands": (52.5, -1.8),
    "East Midlands": (52.8, -1.3),
    "West Midlands": (52.5, -2.0),
    "South West": (51.0, -3.5),
    "South East": (51.3, -0.5),
    "London": (51.5, -0.1),
    "Scotland": (56.0, -4.0),
    "Wales": (52.3, -3.8),
}


def get_shortlist_ids():
    """Return a buyer's persistent shortlist, importing legacy session items once."""
    if current_user.is_authenticated and current_user.role == "buyer":
        legacy_ids = session.pop("shortlist", [])
        imported_legacy_item = False
        if isinstance(legacy_ids, list):
            existing_ids = {
                row.listing_id
                for row in ShortlistItem.query.filter_by(
                    buyer_id=current_user.id
                ).all()
            }
            for raw_id in legacy_ids:
                try:
                    listing_id = int(raw_id)
                except (TypeError, ValueError):
                    continue
                if listing_id not in existing_ids and db.session.get(Listing, listing_id):
                    db.session.add(
                        ShortlistItem(
                            buyer_id=current_user.id,
                            listing_id=listing_id,
                        )
                    )
                    existing_ids.add(listing_id)
                    imported_legacy_item = True
            if imported_legacy_item:
                db.session.commit()

        return {
            row[0]
            for row in db.session.query(ShortlistItem.listing_id)
            .filter_by(buyer_id=current_user.id)
            .all()
        }

    ids = session.get("shortlist", [])
    if not isinstance(ids, list):
        ids = []
    try:
        return {int(i) for i in ids}
    except Exception:
        return set()


def listing_matches_saved_search(listing, saved_search):
    """Return whether a live listing satisfies every populated saved-search filter."""
    if listing.status != "live":
        return False
    if saved_search.region and listing.region != saved_search.region:
        return False
    if saved_search.care_type and saved_search.care_type not in {
        listing.care_type,
        listing.sector_name,
        listing.sector.slug if listing.sector else None,
    }:
        return False
    if saved_search.search_term:
        haystack = f"{listing.title or ''} {listing.short_description or ''}".lower()
        if saved_search.search_term.lower() not in haystack:
            return False
    return True


def compute_matches_for_buyer(buyer, limit=None):
    """
    Return a list of (listing, score, reasons) tuples for this buyer.
    Sorted by descending score.

    - Uses BuyerProfile.preferred_regions / care_types / beds_min/max
    - Falls back to recency if no profile exists.
    """
    profile = BuyerProfile.query.filter_by(user_id=buyer.id).first()

    # No profile → just show live listings by recency
    if not profile:
        base_q = Listing.query.filter_by(status="live").order_by(Listing.created_at.desc())
        listings = base_q.limit(limit).all() if limit else base_q.all()
        return [
            (l, 0, ["No buyer profile – sorted by recency"])
            for l in listings
        ]

    # Base: live listings
    q = Listing.query.filter_by(status="live")

    # Decode CSV fields
    region_list = []
    if profile.preferred_regions:
        region_list = [
            r.strip() for r in profile.preferred_regions.split(",") if r.strip()
        ]
        if region_list:
            q = q.filter(Listing.region.in_(region_list))

    care_list = []
    if profile.care_types:
        care_list = [
            c.strip() for c in profile.care_types.split(",") if c.strip()
        ]
        if care_list:
            q = q.filter(Listing.care_type.in_(care_list))

    if profile.beds_min is not None:
        q = q.filter(Listing.beds >= profile.beds_min)
    if profile.beds_max is not None:
        q = q.filter(Listing.beds <= profile.beds_max)

    listings = q.order_by(Listing.created_at.desc()).all()

    results = []
    for l in listings:
        score = 0
        reasons = []

        # Region match
        if region_list and l.region in region_list:
            score += 30
            reasons.append("Region match")

        # Care type match
        if care_list and l.care_type in care_list:
            score += 30
            reasons.append("Sector / industry match")

        # Beds range
        if profile.beds_min is not None and l.beds is not None:
            if l.beds >= profile.beds_min:
                score += 10
                reasons.append("Meets minimum size")
        if profile.beds_max is not None and l.beds is not None:
            if l.beds <= profile.beds_max:
                score += 10
                reasons.append("Within size range")

        # Rough quality match
        if profile.quality_preference and l.cqc_rating:
            if profile.quality_preference.lower() in l.cqc_rating.lower():
                score += 10
                reasons.append("Quality / accreditation match")

        # If no specific matches triggered, still include with a low base score
        if score == 0:
            score = 5
            reasons.append("General match (live & within broad filters)")

        results.append((l, score, reasons))

    results.sort(key=lambda t: t[1], reverse=True)

    if limit is not None:
        results = results[:limit]

    return results


def compute_buyer_listing_match(listing: Listing, profile: BuyerProfile):
    """Score one listing using the same profile signals used by matching views."""
    score = 0
    reasons = []
    regions = parse_csv(profile.preferred_regions)
    care_types = parse_csv(profile.care_types)

    if regions:
        if listing.region not in regions:
            return 0, "No match", ["Region outside buyer mandate"]
        score += 30
        reasons.append("Region match")

    if care_types:
        if listing.care_type not in care_types:
            return 0, "No match", ["Sector / industry outside buyer mandate"]
        score += 30
        reasons.append("Sector / industry match")

    if profile.beds_min is not None:
        if listing.beds is None or listing.beds < profile.beds_min:
            return 0, "No match", ["Below minimum size"]
        score += 10
        reasons.append("Meets minimum size")

    if profile.beds_max is not None:
        if listing.beds is None or listing.beds > profile.beds_max:
            return 0, "No match", ["Above maximum size"]
        score += 10
        reasons.append("Within maximum size")

    if profile.quality_preference and listing.cqc_rating:
        if profile.quality_preference.lower() in listing.cqc_rating.lower():
            score += 10
            reasons.append("Quality preference match")

    if score == 0:
        score = 5
        reasons.append("General live opportunity")

    label = "Strong match" if score >= 60 else "Good match" if score >= 30 else "Possible match"
    return score, label, reasons



def parse_csv(value: str | None) -> set[str]:
    """
    Turn a comma-separated string into a set of trimmed values.
    Safe if value is None or empty.
    """
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def send_introduction_status_email(intro: Introduction):
    """
    Notify buyer and seller when an introduction status changes.
    Keeps the email simple and generic for now.
    """
    try:
        listing = intro.listing
        buyer = intro.buyer
        seller = intro.seller

        human_status = intro.status.replace("_", " ").title()

        subject = f"Introduction update: {listing.listing_code or listing.id} – {human_status}"

        html_body = f"""
            <h2>Introduction update</h2>
            <p><strong>Listing:</strong> {listing.title} ({listing.listing_code or listing.id})</p>
            <p><strong>Buyer:</strong> {buyer.email}</p>
            <p><strong>Seller:</strong> {seller.email}</p>
            <p><strong>New status:</strong> {human_status}</p>
            <p>This introduction is being managed through Ownerlane.</p>
        """

        # Send to both buyer & seller; bcc broker if configured
        recipients = [buyer.email, seller.email]
        broker_email = app.config.get("LEADS_NOTIFICATION_EMAIL")
        if broker_email:
            recipients.append(broker_email)

        send_email(
            to_addresses=recipients,
            subject=subject,
            html_body=html_body,
        )
    except Exception as e:
        current_app.logger.error(f"Error sending intro status email: {e}")





# -------- Password strength validation --------
PASSWORD_MIN_LENGTH = 10
DUMMY_PASSWORD_HASH = generate_password_hash("Ownerlane-Dummy-Password-Only")


def valid_email_address(email: str) -> bool:
    return bool(
        email
        and len(email) <= 254
        and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
    )


def validate_password_strength(password: str):
    """
    Returns (ok: bool, message: str).
    Enforces: length, upper, lower, digit, special char.
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."

    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."

    if not re.search(r"[^\w\s]", password):
        return False, "Password must contain at least one symbol (e.g. !, ?, #, @)."

    return True, ""


def utcnow():
    """Return a naive UTC timestamp for the application's existing DB columns."""
    return datetime.now(UTC).replace(tzinfo=None)


def _audit_ip_hash() -> str | None:
    """Create a stable, non-reversible network identifier without storing an IP."""
    address = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    address = address.split(",", 1)[0].strip()
    if not address:
        return None
    return hmac.new(
        app.config["SECRET_KEY"].encode(), address.encode(), hashlib.sha256
    ).hexdigest()


def record_audit_event(
    event_type: str,
    summary: str,
    *,
    subject_user_id: int | None = None,
    resource_type: str | None = None,
    resource_id=None,
    details: dict | None = None,
    actor_id: int | None = None,
) -> AuditEvent | None:
    """Append an audit record after a completed action; never break that action."""
    try:
        if actor_id is None:
            actor_id = session.get("impersonator_id")
            if actor_id is None and current_user.is_authenticated:
                actor_id = current_user.id
        event = AuditEvent(
            actor_id=actor_id,
            subject_user_id=subject_user_id,
            event_type=event_type[:80],
            resource_type=(resource_type or "")[:50] or None,
            resource_id=str(resource_id)[:100] if resource_id is not None else None,
            summary=summary[:255],
            details=details or {},
            ip_hash=_audit_ip_hash(),
        )
        db.session.add(event)
        db.session.commit()
        return event
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Could not append audit event")
        return None


def _auth_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"])


def auth_external_url(endpoint: str, **values) -> str:
    path = url_for(endpoint, **values)
    if app.config["PUBLIC_BASE_URL"]:
        return f"{app.config['PUBLIC_BASE_URL']}{path}"
    return url_for(endpoint, _external=True, **values)


def generate_auth_token(user: User, purpose: str) -> str:
    return _auth_serializer().dumps(
        {"uid": user.id, "stamp": user.security_stamp or 0},
        salt=f"ownerlane-{purpose}",
    )


def load_auth_token(token: str, purpose: str, max_age: int):
    try:
        data = _auth_serializer().loads(
            token,
            salt=f"ownerlane-{purpose}",
            max_age=max_age,
        )
    except (BadSignature, SignatureExpired):
        return None
    user = db.session.get(User, data.get("uid"))
    if not user or (user.security_stamp or 0) != data.get("stamp"):
        return None
    return user


def send_verification_email(user: User) -> bool:
    token = generate_auth_token(user, "verify-email")
    link = auth_external_url("verify_email", token=token)
    return send_email(
        user.email,
        "Verify your Ownerlane email",
        f"""
        <p>Welcome to Ownerlane.</p>
        <p>Confirm your email address to activate your account:</p>
        <p><a href="{link}">Verify my email</a></p>
        <p>This link expires in 24 hours. If you did not create this account, you can ignore this email.</p>
        """,
    )


def send_password_reset_email(user: User) -> bool:
    token = generate_auth_token(user, "password-reset")
    link = auth_external_url("reset_password", token=token)
    return send_email(
        user.email,
        "Reset your Ownerlane password",
        f"""
        <p>We received a request to reset your Ownerlane password.</p>
        <p><a href="{link}">Choose a new password</a></p>
        <p>This link expires in one hour and stops working after your password changes. If you did not request it, no action is required.</p>
        """,
    )


def notification_email_mode(user_id: int) -> str:
    preference = NotificationPreference.query.filter_by(user_id=user_id).first()
    return preference.email_mode if preference else "weekly"


def _notification_absolute_url(target_url: str | None) -> str | None:
    if not target_url or not target_url.startswith("/") or target_url.startswith("//"):
        return None
    if app.config["PUBLIC_BASE_URL"]:
        return f"{app.config['PUBLIC_BASE_URL']}{target_url}"
    return urljoin(request.host_url, target_url.lstrip("/"))


def deliver_notification_email(notification: Notification) -> bool:
    if (
        not notification.email_eligible
        or notification.email_sent_at
        or notification_email_mode(notification.user_id) != "immediate"
    ):
        return False
    target = _notification_absolute_url(notification.target_url)
    link = f'<p><a href="{escape(target)}">Open in Ownerlane</a></p>' if target else ""
    sent = send_email(
        notification.user.email,
        notification.title,
        f"<p>{escape(notification.body)}</p>{link}",
    )
    if sent:
        notification.email_sent_at = utcnow()
        db.session.commit()
        record_audit_event(
            "notification.email_delivered",
            "Immediate notification email delivered",
            subject_user_id=notification.user_id,
            resource_type="notification",
            resource_id=notification.id,
            actor_id=None,
            details={"delivery": "immediate", "event_type": notification.event_type},
        )
    return sent


def publish_notification(
    user: User,
    event_type: str,
    title: str,
    body: str,
    target_url: str | None,
    dedupe_key: str,
    email_eligible: bool = True,
):
    """Persist one event after its business transaction commits, then deliver it."""
    target_url = (
        target_url
        if target_url and target_url.startswith("/") and not target_url.startswith("//")
        else None
    )
    notification = Notification.query.filter_by(
        user_id=user.id, dedupe_key=dedupe_key
    ).first()
    if notification:
        return notification, False
    notification = Notification(
        user_id=user.id,
        event_type=event_type[:50],
        title=title[:200],
        body=body,
        target_url=target_url,
        dedupe_key=dedupe_key[:255],
        email_eligible=email_eligible,
    )
    db.session.add(notification)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        notification = Notification.query.filter_by(
            user_id=user.id, dedupe_key=dedupe_key[:255]
        ).first()
        return notification, False
    deliver_notification_email(notification)
    return notification, True


def publish_role_notification(role: str, **notification_data):
    created = []
    for user in User.query.filter_by(role=role).all():
        notification, was_created = publish_notification(user, **notification_data)
        if was_created:
            created.append(notification)
    return created


def publish_listing_match_notifications(listing: Listing):
    """Create one deduplicated alert per buyer when a listing becomes live."""
    if listing.status != "live":
        return []
    created = []
    for buyer in User.query.filter_by(role="buyer").all():
        searches = SavedSearch.query.filter_by(buyer_id=buyer.id).all()
        matched_searches = [
            saved_search
            for saved_search in searches
            if listing_matches_saved_search(listing, saved_search)
        ]
        profile = BuyerProfile.query.filter_by(user_id=buyer.id).first()
        profile_score = 0
        if profile:
            profile_score, _label, _reasons = compute_buyer_listing_match(
                listing, profile
            )
        if not matched_searches and profile_score < 30:
            continue

        search_names = ", ".join(search.name for search in matched_searches[:3])
        reason = (
            f"Saved search: {search_names}."
            if search_names
            else "This opportunity matches your buyer profile."
        )
        body = f"{reason} {listing.region or 'UK'} · {listing.sector_name or 'Business'}"
        email_eligible = (
            any(search.email_alerts for search in matched_searches)
            if matched_searches
            else profile_score >= 30
        )
        notification, was_created = publish_notification(
            buyer,
            event_type="listing_match",
            title="New opportunity matching your criteria",
            body=body,
            target_url=url_for("listing_detail", listing_id=listing.id),
            dedupe_key=f"listing-match:{listing.id}",
            email_eligible=email_eligible,
        )
        if was_created:
            created.append(notification)
    return created


def _auth_attempt_key(identity: str, purpose: str) -> str:
    scoped_identity = (
        f"{purpose}|{identity.strip().lower()}|{request.remote_addr or 'unknown'}"
    )
    return hmac.new(
        app.config["SECRET_KEY"].encode(),
        scoped_identity.encode(),
        hashlib.sha256,
    ).hexdigest()


def _login_attempt_key(email: str) -> str:
    return _auth_attempt_key(email, "login")


def login_is_blocked(email: str) -> bool:
    attempt = LoginAttempt.query.filter_by(key_hash=_login_attempt_key(email)).first()
    return bool(attempt and attempt.blocked_until and attempt.blocked_until > utcnow())


def record_login_failure(email: str) -> bool:
    now = utcnow()
    attempt = LoginAttempt.query.filter_by(key_hash=_login_attempt_key(email)).first()
    window = timedelta(seconds=app.config["LOGIN_FAILURE_WINDOW"])
    if not attempt:
        attempt = LoginAttempt(
            key_hash=_login_attempt_key(email),
            failed_count=0,
            first_failed_at=now,
        )
        db.session.add(attempt)
    elif now - attempt.first_failed_at > window:
        attempt.failed_count = 0
        attempt.first_failed_at = now
        attempt.blocked_until = None

    attempt.failed_count += 1
    attempt.updated_at = now
    if attempt.failed_count >= app.config["LOGIN_FAILURE_LIMIT"]:
        attempt.blocked_until = now + timedelta(
            seconds=app.config["LOGIN_LOCKOUT_SECONDS"]
        )
    db.session.commit()
    return bool(attempt.blocked_until and attempt.blocked_until > now)


def clear_login_failures(email: str):
    LoginAttempt.query.filter_by(key_hash=_login_attempt_key(email)).delete()
    db.session.commit()


def auth_email_request_allowed(email: str, purpose: str) -> bool:
    """Limit reset/verification email generation without revealing account state."""
    now = utcnow()
    key_hash = _auth_attempt_key(email, purpose)
    attempt = LoginAttempt.query.filter_by(key_hash=key_hash).first()
    window = timedelta(seconds=app.config["AUTH_EMAIL_WINDOW"])
    if attempt and attempt.blocked_until and attempt.blocked_until > now:
        return False
    if not attempt:
        attempt = LoginAttempt(
            key_hash=key_hash,
            failed_count=0,
            first_failed_at=now,
        )
        db.session.add(attempt)
    elif now - attempt.first_failed_at > window:
        attempt.failed_count = 0
        attempt.first_failed_at = now
        attempt.blocked_until = None

    attempt.failed_count += 1
    attempt.updated_at = now
    allowed = attempt.failed_count <= app.config["AUTH_EMAIL_LIMIT"]
    if not allowed:
        attempt.blocked_until = now + window
    db.session.commit()
    return allowed


@app.before_request
def enforce_admin_session_limits():
    if not current_user.is_authenticated:
        return None
    if current_user.role != "admin" and not session.get("impersonator_id"):
        return None

    now = int(utcnow().timestamp())
    started = session.get("admin_session_started", now)
    last_seen = session.get("admin_last_activity", now)
    expired = (
        now - last_seen > app.config["ADMIN_IDLE_TIMEOUT"]
        or now - started > app.config["ADMIN_ABSOLUTE_TIMEOUT"]
    )
    if expired:
        user_id = current_user.id
        record_audit_event(
            "auth.admin_session_expired", "Admin session expired",
            subject_user_id=user_id, resource_type="user", resource_id=user_id,
            details={"reason": "idle_or_absolute_timeout"},
        )
        logout_user()
        session.clear()
        flash("Your admin session expired. Please log in again.", "warning")
        return redirect(url_for("login", next=request.path))

    session["admin_session_started"] = started
    session["admin_last_activity"] = now
    return None


# -------- Admin seeding helpers --------


def seed_admin_user(email: str | None = None, password: str | None = None):
    """
    Seed an admin user.
    Email/password can be passed in or taken from env:
      ADMIN_EMAIL, ADMIN_PASSWORD
    """
    email = (email or os.environ.get("ADMIN_EMAIL") or "").strip().lower()
    password = password or os.environ.get("ADMIN_PASSWORD") or ""
    if not email or not password:
        raise RuntimeError(
            "ADMIN_EMAIL and ADMIN_PASSWORD must be configured before seeding."
        )

    existing = User.query.filter_by(email=email).first()
    if existing:
        print(f"[seed-admin] Admin user already exists: {email}")
        return existing

    ok, msg = validate_password_strength(password)
    if not ok:
        raise ValueError(f"ADMIN_PASSWORD is not strong enough: {msg}")

    admin = User(
        email=email,
        password_hash=generate_password_hash(password),
        role="admin",
        email_verified_at=utcnow(),
    )
    db.session.add(admin)
    db.session.commit()
    print(f"[seed-admin] Admin user created: {email}")
    return admin


@app.cli.command("seed-admin")
def seed_admin_command():
    """
    Flask CLI command:
      flask seed-admin
    Uses ADMIN_EMAIL / ADMIN_PASSWORD env vars if set.
    """
    with app.app_context():
        seed_admin_user()



# -------------------------------------------------------------------
# Template helpers
# -------------------------------------------------------------------

@app.context_processor
def inject_subscription_helpers():
    return {
        "has_active_subscription": has_active_subscription,
        "is_premium_seller": is_premium_seller,
        "get_active_subscription": get_active_subscription,
    }



@app.context_processor
def inject_template_globals():
    """
    Make helpers available directly in Jinja templates.
    - datetime: for {{ datetime.utcnow().year }}
    - has_active_subscription: for premium checks in templates
    - _label_for_intro_status: for status history rendering
    """
    return {
        "datetime": datetime,
        "has_active_subscription": has_active_subscription,
        "_label_for_intro_status": _label_for_intro_status,
        "data_room_stage_label": data_room_stage_label,
        "data_room_category_label": data_room_category_label,
    }





@app.context_processor
def inject_valuer_request_count():
    """
    Expose `valuer_request_count` to templates:
    number of open (pending/accepted) valuation requests for the current valuer.
    """
    count = 0
    try:
        if current_user.is_authenticated and current_user.role == "valuer":
            count = (
                ValuationRequest.query
                .filter(
                    ValuationRequest.valuer_id == current_user.id,
                    ValuationRequest.status.in_(["pending", "accepted"]),
                )
                .count()
            )
    except Exception:
        # Avoid template explosions if DB not ready
        count = 0

    return {"valuer_request_count": count}

@app.context_processor
def inject_page_text_helper():
    def page_text(slug: str, default: str = "") -> str:
        return get_page_content(slug, default)
    return {"page_text": page_text}


@app.context_processor
def inject_legal_details():
    return {
        "legal_entity_name": app.config["LEGAL_ENTITY_NAME"],
        "legal_company_number": app.config["LEGAL_COMPANY_NUMBER"],
        "legal_registered_address": app.config["LEGAL_REGISTERED_ADDRESS"],
        "legal_ico_number": app.config["LEGAL_ICO_NUMBER"],
        "legal_contact_email": app.config["LEGAL_CONTACT_EMAIL"],
        "legal_last_updated": app.config["LEGAL_LAST_UPDATED"],
    }


@app.context_processor
def inject_notification_state():
    unread_count = 0
    try:
        if current_user.is_authenticated:
            unread_count = Notification.query.filter_by(
                user_id=current_user.id, read_at=None
            ).count()
    except Exception:
        unread_count = 0
    return {"unread_notification_count": unread_count}




@app.template_filter("date_short")
def date_short(value):
    if not value:
        return ""
    try:
        return value.strftime("%d %b %Y")  # e.g. 24 Nov 2025
    except Exception:
        return str(value)



# -------------------------------------------------------------------
# Public routes
# -------------------------------------------------------------------


@app.route("/")
def index():
    listings = (
        Listing.query.filter_by(status="live")
        .order_by(Listing.created_at.desc())
        .limit(6)
        .all()
    )

    is_premium_buyer = False
    if current_user.is_authenticated and current_user.role == "buyer":
        is_premium_buyer = has_active_subscription(current_user, "buyer", "premium")

    return render_template(
        "index.html",
        listings=listings,
        is_premium_buyer=is_premium_buyer
    )


@app.route("/privacy")
def privacy_notice():
    return render_template("legal/privacy.html")


@app.route("/cookies")
def cookie_notice():
    return render_template("legal/cookies.html")


@app.route("/terms")
def terms_of_use():
    return render_template("legal/terms.html")


@app.route("/marketplace-terms")
def marketplace_terms():
    return render_template("legal/marketplace_terms.html")


@app.route("/acceptable-use")
def acceptable_use():
    return render_template("legal/acceptable_use.html")


@app.route("/legal-notice")
def legal_notice():
    return render_template("legal/legal_notice.html")


@app.route("/accessibility")
def accessibility_statement():
    return render_template("legal/accessibility.html")


@app.route("/complaints")
def complaints_procedure():
    return render_template("legal/complaints.html")



@app.route("/listings")
def listings():
    # Base query: live listings only
    query = Listing.query.filter_by(status="live")

    search_q = (request.args.get("q") or "").strip()
    selected_region = request.args.get("region") or ""
    selected_sector = request.args.get("sector") or request.args.get("care_type") or ""
    min_price = (request.args.get("min_price") or "").strip()
    max_price = (request.args.get("max_price") or "").strip()
    sort = request.args.get("sort") or "newest"
    view_mode = request.args.get("view") or "list"
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = 6

    if search_q:
        like = f"%{search_q}%"
        query = query.filter(
            (Listing.title.ilike(like)) | (Listing.short_description.ilike(like))
        )

    if selected_region:
        query = query.filter(Listing.region == selected_region)
    if selected_sector:
        query = query.outerjoin(Sector).filter(
            or_(
                Sector.slug == selected_sector,
                Sector.name == selected_sector,
                Listing.care_type == selected_sector,
            )
        )
    try:
        min_price_minor = parse_major_units(min_price)
        max_price_minor = parse_major_units(max_price)
    except ValueError:
        min_price_minor = max_price_minor = None
        flash("Price filters must be valid positive amounts.")
    if min_price_minor is not None:
        query = query.filter(Listing.asking_price_minor >= min_price_minor)
    if max_price_minor is not None:
        query = query.filter(Listing.asking_price_minor <= max_price_minor)

    total = query.count()
    pages = max(1, math.ceil(total / per_page)) if total else 1
    if page > pages:
        page = pages

    if sort == "price_low":
        ordering = (Listing.asking_price_minor.is_(None), Listing.asking_price_minor.asc())
    elif sort == "price_high":
        ordering = (Listing.asking_price_minor.is_(None), Listing.asking_price_minor.desc())
    else:
        ordering = (Listing.created_at.desc(),)

    listings_data = (
        query.order_by(*ordering)
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    # Filter options from all live listings
    base_live = Listing.query.filter_by(status="live")
    regions = sorted(
        {
            r[0]
            for r in base_live.with_entities(Listing.region).distinct()
            if r[0] is not None and r[0] != ""
        }
    )
    sector_options = {}
    for listing in base_live.all():
        name = listing.sector_name
        if name:
            sector_options[listing.sector.slug if listing.sector else name] = name

    # Shortlist IDs for this buyer
    shortlist_ids = set()
    if current_user.is_authenticated and current_user.role == "buyer":
        shortlist_ids = get_shortlist_ids()

    # PREMIUM ACCESS FLAG (IMPORTANT)
    is_premium_buyer = (
        current_user.is_authenticated
        and current_user.role == "buyer"
        and has_active_subscription(current_user, "buyer", "premium")
    )

    # Map data (all filtered results, not just current page)
    map_data = []
    if view_mode == "map":
        for l in query.order_by(Listing.created_at.desc()).all():
            lat, lng = REGION_COORDS.get(l.region or "", DEFAULT_COORD)
            can_view_map_sensitive = can_view_listing_sensitive(current_user, l)
            map_data.append(
                {
                    "id": l.id,
                    "title": l.title if can_view_map_sensitive else "Confidential opportunity",
                    "lat": lat,
                    "lng": lng,
                    "region": l.region or "",
                    "care_type": l.sector_name or "",
                    "beds": l.headline_metric or "",
                    "guide_price": (
                        l.guide_price_display or "On request"
                        if can_view_map_sensitive
                        else "Premium only"
                    ),
                    "code": l.listing_code or "",
                }
            )

    return render_template(
        "listings.html",
        listings=listings_data,
        search_q=search_q,
        selected_region=selected_region,
        selected_care_type=selected_sector,
        selected_sector=selected_sector,
        min_price=min_price,
        max_price=max_price,
        sort=sort,
        view_mode=view_mode,
        page=page,
        pages=pages,
        total=total,
        regions=regions,
        care_types=sorted(sector_options.values()),
        sector_options=sorted(sector_options.items(), key=lambda item: item[1]),
        shortlist_ids=shortlist_ids,
        map_data=map_data,
        is_premium_buyer=is_premium_buyer,   # <-- ADDED
    )



@app.route("/listings/<int:listing_id>", methods=["GET", "POST"])
def listing_detail(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    if not can_access_listing(current_user, listing):
        abort(404)

    # ---- Work out buyer flags for the template ----
    is_premium_buyer = False
    is_shortlisted = False

    if current_user.is_authenticated and current_user.role == "buyer":
        # Subscription check
        is_premium_buyer = has_active_subscription(current_user, "buyer", "premium")

        # Shortlist check (session-based)
        shortlist_ids = get_shortlist_ids()
        is_shortlisted = listing.id in shortlist_ids

    # Can this user actually send an enquiry?
    can_enquire = (
        current_user.is_authenticated
        and current_user.role == "buyer"
        and is_premium_buyer
    )
    can_view_sensitive = can_view_listing_sensitive(current_user, listing)

    if (
        request.method == "GET"
        and listing.is_confidential
        and can_view_sensitive
        and current_user.is_authenticated
    ):
        record_audit_event(
            "listing.sensitive_viewed",
            "Confidential listing details viewed",
            subject_user_id=current_user.id,
            resource_type="listing",
            resource_id=listing.id,
            details={"listing_code": listing.listing_code},
        )

    # ---- Handle enquiry POST (inline form on detail page) ----
    if request.method == "POST":
        # Hard gate: must be logged in as buyer
        if not current_user.is_authenticated:
            flash("Log in as a buyer to send an enquiry.")
            return redirect(url_for("login", next=request.path))

        if current_user.role != "buyer":
            flash("Only registered buyers can send enquiries.")
            return redirect(url_for("index"))

        # Must be premium
        if not is_premium_buyer:
            flash(
                "You need an active Buyer Premium subscription to send detailed enquiries.",
                "warning",
            )
            try:
                return redirect(url_for("pricing"))
            except Exception:
                return redirect(url_for("buyer_dashboard"))

        # Basic validation
        message = (request.form.get("message") or "").strip()
        nda_accepted = bool(request.form.get("nda_accepted"))

        if not message:
            flash("Please include a message before sending your enquiry.")
        else:
            enquiry = Enquiry(
                listing_id=listing.id,
                buyer_id=current_user.id,
                message=message,
                nda_accepted=nda_accepted,
            )
            db.session.add(enquiry)
            db.session.commit()
            publish_notification(
                listing.seller,
                event_type="new_enquiry",
                title="New buyer enquiry",
                body=f"A buyer enquired about {listing.listing_code or 'your listing'}.",
                target_url=url_for("seller_enquiries"),
                dedupe_key=f"enquiry:{enquiry.id}",
            )
            flash("Your enquiry has been sent.")
            return redirect(url_for("buyer_dashboard"))

    # ---- GET (or POST with validation errors) → render template ----
    return render_template(
        "listing_detail.html",
        listing=listing,
        is_premium_buyer=is_premium_buyer,
        is_shortlisted=is_shortlisted,
        can_enquire=can_enquire,
        can_view_sensitive=can_view_sensitive,
    )


@app.route("/listing/<int:listing_id>/enquire", methods=["GET", "POST"])
def enquire(listing_id):
    listing = Listing.query.get_or_404(listing_id)

    if listing.status != "live":
        abort(404)
    if not current_user.is_authenticated:
        flash("Log in as a premium buyer to send an enquiry.", "warning")
        return redirect(url_for("login", next=request.path))
    if current_user.role != "buyer" or not is_premium_buyer(current_user):
        flash("Buyer Premium is required to send an enquiry.", "warning")
        return redirect(url_for("pricing", role="buyer"))

    if request.method == "POST":
        buyer_name = request.form.get("buyer_name", "").strip()
        buyer_email = request.form.get("buyer_email", "").strip()
        buyer_phone = request.form.get("buyer_phone", "").strip()
        buyer_company = request.form.get("buyer_company", "").strip()
        message = request.form.get("message", "").strip()

        errors = []
        if not buyer_name:
            errors.append("Name is required.")
        if not buyer_email:
            errors.append("Email is required.")
        if not message:
            errors.append("Message is required.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template(
                "enquire.html",
                listing=listing,
                form_data=request.form,
            )

        lead = Lead(
            listing_id=listing.id,
            buyer_name=buyer_name,
            buyer_email=buyer_email,
            buyer_phone=buyer_phone,
            buyer_company=buyer_company,
            message=message,
        )
        db.session.add(lead)
        db.session.commit()
        publish_notification(
            listing.seller,
            event_type="new_enquiry",
            title="New buyer enquiry",
            body=f"A buyer enquired about {listing.listing_code or 'your listing'}.",
            target_url=url_for("listing_detail", listing_id=listing.id),
            dedupe_key=f"lead:{lead.id}",
        )

        # Send notification email
        to_email = app.config["LEADS_NOTIFICATION_EMAIL"]
        if to_email:
            subject = (
                f"New enquiry for listing #{listing.id}: "
                f"{getattr(listing, 'name', 'Business')}"
            )

            safe_message_html = message.replace("\n", "<br>")

            html_body = f"""
                <h2>New enquiry for listing #{listing.id}</h2>
                <p><strong>Listing:</strong> {getattr(listing, 'name', '')}</p>
                <p><strong>Region:</strong> {getattr(listing, 'region', '')}</p>
                <p><strong>Buyer name:</strong> {buyer_name}</p>
                <p><strong>Email:</strong> {buyer_email}</p>
                <p><strong>Phone:</strong> {buyer_phone}</p>
                <p><strong>Company:</strong> {buyer_company}</p>
                <p><strong>Message:</strong></p>
                <p>{safe_message_html}</p>
                <p><strong>Created at:</strong> {lead.created_at}</p>
            """

            send_email(
                to_addresses=to_email,
                subject=subject,
                html_body=html_body,
                reply_to=buyer_email,
            )

        flash("Thanks, your enquiry has been sent. We’ll be in touch shortly.", "success")
        return redirect(url_for("listing_detail", listing_id=listing.id))

    # GET
    return render_template(
        "enquire.html",
        listing=listing,
        form_data={},
    )


@app.route("/pricing")
def pricing():
    # Optional role hint from querystring, e.g. ?role=buyer
    role = (request.args.get("role") or "").strip().lower()
    if role not in {"buyer", "seller", "valuer"}:
        role = ""

    return render_template("pricing.html", selected_role=role)

# -------------------------------------------------------------------
# Billing / Stripe subscription routes
# -------------------------------------------------------------------


@app.route("/billing/checkout", methods=["POST"])
@login_required
def billing_checkout():
    """
    Create a Stripe Checkout Session for a subscription.
    Form must send: role, tier (e.g. role=buyer, tier=premium).
    """
    # Role/tier the user is trying to buy
    role = (request.form.get("role") or "").strip().lower()
    tier = (request.form.get("tier") or "").strip().lower()

    if role not in {"buyer", "seller", "valuer"}:
        flash("Invalid subscription role.", "error")
        return redirect(url_for("pricing"))

    if tier not in {"basic", "premium"}:
        flash("Invalid subscription tier.", "error")
        return redirect(url_for("pricing"))

    # Make sure user is buying for their own role (no cross-role chaos)
    if current_user.role != role and current_user.role != "admin":
        flash("You can only buy a subscription for your own account type.")
        return redirect(url_for("pricing"))

    price_id = STRIPE_PRICE_MAP.get((role, tier))
    if not stripe.api_key or not price_id:
        flash("Billing configuration incomplete – contact support.", "error")
        return redirect(url_for("pricing"))

    # URLs for after checkout
    success_url = url_for("billing_success", _external=True)
    cancel_url = url_for("pricing", _external=True)

    try:
        checkout_session = stripe.checkout.Session.create(
            mode="subscription",
            success_url=success_url + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=cancel_url,
            line_items=[
                {"price": price_id, "quantity": 1},
            ],
            customer_email=current_user.email,
            metadata={
                "user_id": str(current_user.id),
                "role": role,
                "tier": tier,
            },
        )
    except Exception as e:
        current_app.logger.error(f"Stripe checkout error: {e}")
        flash("Unable to start checkout. Please try again later.", "error")
        return redirect(url_for("pricing"))

    return redirect(checkout_session.url, code=303)

@app.route("/billing/success")
@login_required
def billing_success():
    """
    Landing page after successful checkout; the real source of truth
    is the webhook, but this reassures the user.
    """
    flash("Thanks – your subscription is being activated.", "success")
    # Redirect them to their dashboard based on role
    if current_user.role == "buyer":
        return redirect(url_for("buyer_dashboard"))
    if current_user.role == "seller":
        return redirect(url_for("seller_dashboard"))
    if current_user.role == "valuer":
        return redirect(url_for("valuer_dashboard"))
    if current_user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("index"))


@app.route("/billing/portal", methods=["POST"])
@login_required
def billing_portal():
    """
    Launch Stripe Customer Billing Portal for the current user's active subscription.
    """
    if not app.config.get("STRIPE_SECRET_KEY"):
        flash("Billing is not configured yet. Contact support.", "error")
        return redirect(url_for("pricing"))

    # Prefer a subscription matching their current role, fall back to any active one
    active_sub = get_active_subscription(current_user, current_user.role)
    if not active_sub:
        active_sub = get_active_subscription(current_user, None)

    if not active_sub or not active_sub.stripe_customer_id:
        flash("We couldn’t find an active subscription to manage.", "warning")
        return redirect(url_for("pricing"))

    # Where Stripe sends them back after managing billing
    if current_user.role == "buyer":
        return_url = url_for("buyer_dashboard", _external=True)
    elif current_user.role == "seller":
        return_url = url_for("seller_dashboard", _external=True)
    elif current_user.role == "valuer":
        return_url = url_for("valuer_dashboard", _external=True)
    else:
        return_url = url_for("index", _external=True)

    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=active_sub.stripe_customer_id,
            return_url=return_url,
        )
    except Exception as e:
        app.logger.error(f"Stripe portal error: {e}")
        flash("There was a problem opening the billing portal. Try again.", "error")
        return redirect(return_url)

    return redirect(portal_session.url, code=303)






# -------------------------------------------------------------------
# Auth routes
# -------------------------------------------------------------------


@app.route("/register/buyer", methods=["GET", "POST"])
def register_buyer():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not valid_email_address(email):
            flash("Enter a valid email address.")
            return redirect(request.url)

        ok, msg = validate_password_strength(password)
        if not ok:
            flash(msg)
            return redirect(request.url)

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("An account with that email already exists.")
            return redirect(request.url)

        user = User(
            email=email,
            password_hash=generate_password_hash(password),
            role="buyer",
            email_verified_at=None,
        )
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)
        flash("Buyer account created. Check your email to verify it before logging in.")
        return redirect(url_for("login"))

    return render_template("auth/register_buyer.html")


@app.route("/register/seller", methods=["GET", "POST"])
def register_seller():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not valid_email_address(email):
            flash("Enter a valid email address.")
            return redirect(request.url)

        ok, msg = validate_password_strength(password)
        if not ok:
            flash(msg)
            return redirect(request.url)

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("An account with that email already exists.")
            return redirect(request.url)

        user = User(
            email=email,
            password_hash=generate_password_hash(password),
            role="seller",
            email_verified_at=None,
        )
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)
        flash("Seller account created. Check your email to verify it before logging in.")
        return redirect(url_for("login"))

    return render_template("auth/register_seller.html")


@app.route("/register/valuer", methods=["GET", "POST"])
def register_valuer():
    """
    Valuer registration:
    - Creates a User with role='valuer'
    - Immediately creates a ValuerProfile with basic fields
    - No subscription requirement yet (that comes later)
    """
    region_choices = sorted(REGION_COORDS.keys())

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        company_name = (request.form.get("company_name") or "").strip()
        accreditation = (request.form.get("accreditation") or "").strip()
        pricing_notes = (request.form.get("pricing_notes") or "").strip()
        bio = (request.form.get("bio") or "").strip()
        selected_regions = request.form.getlist("regions")

        if not valid_email_address(email):
            flash("Enter a valid email address.")
            return redirect(request.url)

        ok, msg = validate_password_strength(password)
        if not ok:
            flash(msg)
            return redirect(request.url)

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("An account with that email already exists.")
            return redirect(request.url)

        # Create the valuer user
        user = User(
            email=email,
            password_hash=generate_password_hash(password),
            role="valuer",
            email_verified_at=None,
        )
        db.session.add(user)
        db.session.flush()  # get user.id

        # Create the profile
        profile = ValuerProfile(
            user_id=user.id,
            company_name=company_name or None,
            accreditation=accreditation or None,
            regions=", ".join(selected_regions) if selected_regions else None,
            pricing_notes=pricing_notes or None,
            bio=bio or None,
        )
        db.session.add(profile)
        db.session.commit()

        send_verification_email(user)
        flash("Valuer account created. Check your email to verify it before logging in.")
        return redirect(url_for("login"))

    # GET
    return render_template(
        "auth/register_valuer.html",
        region_choices=region_choices,
    )

# -------------------------------------------------------------------
# Valuer – valuation requests inbox
# -------------------------------------------------------------------

@app.route("/valuer/requests")
@login_required
@role_required("valuer")
def valuer_requests():
    """
    List all valuation requests for the current valuer.
    """
    requests_q = (
        ValuationRequest.query
        .filter_by(valuer_id=current_user.id)
        .order_by(ValuationRequest.created_at.desc())
        .all()
    )

    return render_template(
        "valuer/requests.html",
        requests=requests_q,
    )


@app.route("/valuer/requests/<int:request_id>", methods=["GET", "POST"])
@login_required
@role_required("valuer")
def valuer_request_detail(request_id):
    """
    View a single valuation request and update its status.
    """
    vr = ValuationRequest.query.get_or_404(request_id)

    # Hard guard – make sure this belongs to the current valuer
    if vr.valuer_id != current_user.id:
        flash("You do not have access to this valuation request.")
        return redirect(url_for("valuer_requests"))

    allowed_statuses = ["pending", "accepted", "completed", "declined"]

    if request.method == "POST":
        new_status = (request.form.get("status") or "").strip().lower()
        if new_status not in allowed_statuses:
            flash("Invalid status.", "error")
            return redirect(request.url)

        previous_status = vr.status
        vr.status = new_status
        vr.created_at = vr.created_at  # unchanged; SQLAlchemy will track
        db.session.commit()
        if new_status != previous_status:
            publish_notification(
                vr.seller,
                event_type="valuation_status",
                title=f"Valuation request {new_status}",
                body=f"The valuation for {vr.listing.listing_code or 'your listing'} is now {new_status}.",
                target_url=url_for("seller_dashboard"),
                dedupe_key=f"valuation:{vr.id}:{new_status}",
            )
        flash("Valuation request updated.", "success")
        return redirect(url_for("valuer_request_detail", request_id=vr.id))

    return render_template(
        "valuer/request_detail.html",
        vr=vr,
        allowed_statuses=allowed_statuses,
    )


@app.route("/verify-email/<token>")
def verify_email(token):
    user = load_auth_token(
        token,
        "verify-email",
        app.config["EMAIL_VERIFICATION_MAX_AGE"],
    )
    if not user:
        flash("That verification link is invalid or has expired.", "warning")
        return redirect(url_for("resend_verification"))
    if not user.email_verified_at:
        user.email_verified_at = utcnow()
        db.session.commit()
        record_audit_event(
            "auth.email_verified", "Email address verified", subject_user_id=user.id,
            resource_type="user", resource_id=user.id, actor_id=user.id,
        )
    flash("Email verified. You can now log in.", "success")
    return redirect(url_for("login"))


@app.route("/verify-email/resend", methods=["GET", "POST"])
def resend_verification():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        allowed = bool(email) and auth_email_request_allowed(email, "verify-email")
        user = User.query.filter_by(email=email).first() if email else None
        if allowed and user and not user.email_verified_at:
            send_verification_email(user)
        flash(
            "If an unverified account exists for that email, a new verification link has been sent.",
            "info",
        )
        return redirect(url_for("login"))
    return render_template("auth/resend_verification.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        allowed = bool(email) and auth_email_request_allowed(email, "password-reset")
        user = User.query.filter_by(email=email).first() if email else None
        if allowed and user:
            send_password_reset_email(user)
        flash(
            "If an account exists for that email, a password-reset link has been sent.",
            "info",
        )
        return redirect(url_for("login"))
    return render_template("auth/forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = load_auth_token(
        token,
        "password-reset",
        app.config["PASSWORD_RESET_MAX_AGE"],
    )
    if not user:
        flash("That password-reset link is invalid or has expired.", "warning")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password") or ""
        confirmation = request.form.get("password_confirmation") or ""
        if password != confirmation:
            flash("The passwords do not match.", "danger")
            return render_template("auth/reset_password.html", token=token)
        ok, message = validate_password_strength(password)
        if not ok:
            flash(message, "danger")
            return render_template("auth/reset_password.html", token=token)

        user.set_password(password)
        user.password_changed_at = utcnow()
        user.security_stamp = (user.security_stamp or 0) + 1
        db.session.commit()
        record_audit_event(
            "auth.password_changed", "Password changed", subject_user_id=user.id,
            resource_type="user", resource_id=user.id, actor_id=user.id,
        )
        logout_user()
        session.clear()
        send_email(
            user.email,
            "Your Ownerlane password was changed",
            "<p>Your Ownerlane password has been changed. If this was not you, contact Ownerlane immediately.</p>",
        )
        flash("Password changed. Log in with your new password.", "success")
        return redirect(url_for("login"))

    return render_template("auth/reset_password.html", token=token)

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login view:
    - On GET: render login form
    - On POST: authenticate and redirect based on role
    """
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email or not password:
            flash("Please enter both email and password.", "danger")
            return render_template("auth/login.html")

        if login_is_blocked(email):
            user = User.query.filter_by(email=email).first()
            record_audit_event(
                "auth.login_blocked", "Login blocked after repeated failures",
                subject_user_id=user.id if user else None,
                resource_type="user", resource_id=user.id if user else None,
                actor_id=None,
            )
            lockout_minutes = max(
                1, math.ceil(app.config["LOGIN_LOCKOUT_SECONDS"] / 60)
            )
            flash(
                f"Too many login attempts. Try again in {lockout_minutes} minutes or reset your password.",
                "danger",
            )
            return render_template("auth/login.html"), 429

        user = User.query.filter_by(email=email).first()

        password_is_valid = (
            user.check_password(password)
            if user is not None
            else check_password_hash(DUMMY_PASSWORD_HASH, password)
        )
        if user is None or not password_is_valid:
            flash("Invalid email or password.", "danger")
            blocked = record_login_failure(email)
            record_audit_event(
                "auth.login_failed", "Unsuccessful login attempt",
                subject_user_id=user.id if user else None,
                resource_type="user", resource_id=user.id if user else None,
                actor_id=None, details={"lockout_triggered": blocked},
            )
            return render_template("auth/login.html"), (429 if blocked else 200)

        if not getattr(user, "is_active", True):
            flash("Your account is inactive. Please contact support.", "warning")
            return render_template("auth/login.html")

        if not user.email_verified_at:
            clear_login_failures(email)
            flash(
                "Verify your email before logging in. You can request a new link below.",
                "warning",
            )
            return render_template("auth/login.html"), 403

        clear_login_failures(email)
        next_page = request.args.get("next")
        remember = bool(request.form.get("remember")) and user.role != "admin"
        session.clear()
        login_user(user, remember=remember, fresh=True)
        user.last_login_at = utcnow()
        if user.role == "admin":
            now = int(utcnow().timestamp())
            session["admin_session_started"] = now
            session["admin_last_activity"] = now
            session.permanent = False
        db.session.commit()
        record_audit_event(
            "auth.login_succeeded", "Signed in", subject_user_id=user.id,
            resource_type="user", resource_id=user.id, actor_id=user.id,
            details={"role": user.role},
        )

        # Honour ?next=... if present
        if is_safe_redirect_target(next_page):
            return redirect(next_page)

        # Role-aware redirect
        if user.role == "buyer":
            return redirect(url_for("buyer_dashboard"))
        elif user.role == "seller":
            return redirect(url_for("seller_dashboard"))
        elif user.role == "valuer":
            return redirect(url_for("valuer_dashboard"))
        elif user.role == "admin":
            return redirect(url_for("admin_dashboard"))
        else:
            # Fallback: treat as buyer-ish
            return redirect(url_for("buyer_dashboard"))

    # GET request (or any non-POST fallthrough)
    return render_template("auth/login.html")




@app.route("/logout", methods=["POST"])
@login_required
def logout():
    user_id = current_user.id
    record_audit_event(
        "auth.logout", "Signed out", subject_user_id=user_id,
        resource_type="user", resource_id=user_id,
    )
    logout_user()
    flash("Logged out.")
    return redirect(url_for("index"))


@app.route("/account/security-activity")
@login_required
def security_activity():
    events = (
        AuditEvent.query.filter(
            AuditEvent.subject_user_id == current_user.id,
            or_(
                AuditEvent.event_type.like("auth.%"),
                AuditEvent.event_type.like("document.%"),
                AuditEvent.event_type.like("admin.impersonation%"),
            ),
        )
        .order_by(AuditEvent.created_at.desc())
        .limit(100)
        .all()
    )
    return render_template("account/security_activity.html", events=events)


@app.route("/notifications")
@login_required
def notification_center():
    items = (
        Notification.query.filter_by(user_id=current_user.id)
        .order_by(Notification.created_at.desc())
        .limit(100)
        .all()
    )
    preference = NotificationPreference.query.filter_by(
        user_id=current_user.id
    ).first()
    return render_template(
        "notifications/index.html",
        notifications=items,
        email_mode=preference.email_mode if preference else "weekly",
    )


@app.route("/notifications/<int:notification_id>/open", methods=["POST"])
@login_required
def open_notification(notification_id):
    notification = Notification.query.filter_by(
        id=notification_id, user_id=current_user.id
    ).first_or_404()
    if not notification.read_at:
        notification.read_at = utcnow()
        db.session.commit()
    if notification.target_url and is_safe_redirect_target(notification.target_url):
        return redirect(notification.target_url)
    return redirect(url_for("notification_center"))


@app.route("/notifications/read-all", methods=["POST"])
@login_required
def read_all_notifications():
    Notification.query.filter_by(user_id=current_user.id, read_at=None).update(
        {"read_at": utcnow()}, synchronize_session=False
    )
    db.session.commit()
    flash("All notifications marked as read.", "success")
    return redirect(url_for("notification_center"))


@app.route("/notifications/preferences", methods=["POST"])
@login_required
def update_notification_preferences():
    email_mode = (request.form.get("email_mode") or "weekly").strip().lower()
    if email_mode not in {"immediate", "weekly", "off"}:
        flash("Choose a valid email preference.", "error")
        return redirect(url_for("notification_center"))
    preference = NotificationPreference.query.filter_by(
        user_id=current_user.id
    ).first()
    if not preference:
        preference = NotificationPreference(user_id=current_user.id)
        db.session.add(preference)
    preference.email_mode = email_mode
    preference.updated_at = utcnow()
    db.session.commit()
    flash("Notification preferences updated.", "success")
    return redirect(url_for("notification_center"))


# -------------------------------------------------------------------
# Seller routes
# -------------------------------------------------------------------

@app.route("/seller/dashboard")
@login_required
@role_required("seller")
def seller_dashboard():
    # Seller business profile
    profile = SellerProfile.query.filter_by(user_id=current_user.id).first()

    # Get listings with enquiry counts
    raw = (
        db.session.query(Listing, func.count(Enquiry.id).label("total_enquiries"))
        .outerjoin(Enquiry, Enquiry.listing_id == Listing.id)
        .filter(Listing.seller_id == current_user.id)
        .group_by(Listing.id)
        .order_by(Listing.created_at.desc())
        .all()
    )

    listings = []
    for listing, total in raw:
        listing.total_enquiries = total
        listings.append(listing)

    # Simple completion heuristic
    profile_incomplete = (
        not profile
        or not profile.business_name
        or not profile.turnover
        or not profile.nda_accepted
    )

    # Seller premium flag (mirrors buyer gating)
    seller_is_premium = is_premium_seller(current_user)

    # Subscription badge
    active_sub = get_active_subscription(current_user, "seller")
    current_plan_label = None
    if active_sub:
        current_plan_label = f"{active_sub.role.capitalize()} {active_sub.tier.capitalize()}"
    workspace_introductions = (
        Introduction.query.filter_by(seller_id=current_user.id)
        .filter(~Introduction.status.in_(["pending_seller_request", "declined", "failed"]))
        .order_by(Introduction.updated_at.desc()).limit(10).all()
    )

    return render_template(
        "seller/dashboard.html",
        listings=listings,
        profile=profile,
        profile_incomplete=profile_incomplete,
        current_plan_label=current_plan_label,
        active_sub=active_sub,
        workspace_introductions=workspace_introductions,
        # optional: expose this if you want in template later
        # seller_is_premium=seller_is_premium,
    )



@app.route("/seller/request_introduction/<int:buyer_id>", methods=["POST"])
@login_required
@role_required("seller")
@require_subscription("seller", "premium")
def seller_request_introduction(buyer_id):
    """
    Seller requests an introduction between their listing and a premium buyer.
    This creates a 'pending_seller_request' introduction for admin to approve.
    Admin is notified by email.

    Expects a hidden 'listing_id' field in the POST form.
    """
    listing_id = request.form.get("listing_id")
    if not listing_id:
        flash("Missing listing ID for introduction request.", "danger")
        return redirect(url_for("seller_dashboard"))

    listing = Listing.query.get_or_404(listing_id)

    # Ensure listing belongs to this seller
    if listing.seller_id != current_user.id:
        flash("You can only request introductions for your own listings.", "danger")
        return redirect(url_for("seller_dashboard"))

    # Ensure buyer exists and is a buyer
    buyer = User.query.get_or_404(buyer_id)
    if buyer.role != "buyer":
        flash("Selected user is not a buyer.", "danger")
        return redirect(url_for("seller_dashboard"))

    # Check buyer is premium (belt-and-braces check; you already have @require_subscription)
    if not is_premium_buyer(buyer):
        flash("You can only request introductions for premium buyers.", "warning")
        return redirect(url_for("seller_dashboard"))

    # Ensure no duplicate introduction
    existing = Introduction.query.filter_by(
        buyer_id=buyer.id,
        seller_id=current_user.id,
        listing_id=listing.id,
    ).first()

    if existing:
        flash("An introduction already exists for this buyer and listing.", "info")
        return redirect(url_for("seller_dashboard"))

    intro = Introduction(
        buyer_id=buyer.id,
        seller_id=current_user.id,
        listing_id=listing.id,
        status="pending_seller_request",
    )
    db.session.add(intro)
    db.session.commit()

    publish_role_notification(
        "admin",
        event_type="introduction_request",
        title="New introduction request",
        body=f"A seller requested an introduction for {listing.listing_code or 'a listing'}.",
        target_url=url_for("admin_introduction_requests"),
        dedupe_key=f"introduction-request:{intro.id}",
    )

    flash("Introduction request submitted for review.", "success")
    return redirect(url_for("seller_dashboard"))




@app.route("/seller/buyers")
@login_required
@role_required("seller")
@require_subscription("seller", "premium")
def seller_buyers():
    """
    Seller-facing view of matching buyers.

    - Gated to Seller Premium via @require_subscription.
    - Uses SellerProfile + their live listings to infer target regions & care types.
    - Shows premium buyers whose preferences overlap with those signals.
    """
    # Seller business profile
    profile = SellerProfile.query.filter_by(user_id=current_user.id).first()

    # Seller's live listings
    listings = Listing.query.filter_by(
        seller_id=current_user.id,
        status="live",
    ).all()

    # If seller has literally no info at all, push them to set something up
    if not profile and not listings:
        flash(
            "Add a seller profile or at least one listing to see matching buyers.",
            "warning",
        )
        return redirect(url_for("seller_dashboard"))

    # --- Build seller "signal" sets: regions + care types ---
    seller_regions: set[str] = set()
    seller_care_types: set[str] = set()

    # From seller profile
    if profile:
        seller_regions |= parse_csv(profile.regions)
        if profile.care_type:
            seller_care_types.add(profile.care_type)

    # From their live listings
    for l in listings:
        if l.region:
            seller_regions.add(l.region)
        if l.care_type:
            seller_care_types.add(l.care_type)
        if l.sector_name:
            seller_care_types.add(l.sector_name)

    # If still totally empty, we can show all premium buyers, but it's noisy
    # We'll still compute matches, just with no extra filter.
    # --- Fetch premium buyers with profiles ---
    buyer_query = (
        BuyerProfile.query
        .join(User, BuyerProfile.user_id == User.id)
        .filter(User.role == "buyer")
    )

    # Restrict to premium buyers (Tier 2)
    SubscriptionModel = globals().get("Subscription")
    premium_buyer_ids = set()

    if SubscriptionModel is not None:
        active_premium_buyers = (
            SubscriptionModel.query
            .filter_by(role="buyer", tier="premium", is_active=True)
            .all()
        )
        premium_buyer_ids = {s.user_id for s in active_premium_buyers}

        buyer_query = buyer_query.filter(
            BuyerProfile.user_id.in_(premium_buyer_ids)
        )

    buyer_profiles = (
        buyer_query
        .order_by(BuyerProfile.created_at.desc())
        .all()
    )

    # --- Compute match signal per buyer ---
    matches = []

    for bp in buyer_profiles:
        buyer_regions = parse_csv(bp.preferred_regions)
        buyer_care_types = parse_csv(bp.care_types)

        region_match = bool(buyer_regions & seller_regions) if seller_regions else False
        care_match = bool(buyer_care_types & seller_care_types) if seller_care_types else False

        # Simple score: 0–2
        score = (1 if region_match else 0) + (1 if care_match else 0)

        # If seller has no signals, allow everyone through; otherwise drop zero-scores
        if (seller_regions or seller_care_types) and score == 0:
            continue

        matches.append(
            {
                "profile": bp,
                "user": bp.user,
                "region_match": region_match,
                "care_match": care_match,
                "score": score,
                "qualification": BuyerQualification.query.filter_by(user_id=bp.user_id).first(),
            }
        )

    # Sort best matches first
    matches.sort(key=lambda m: m["score"], reverse=True)

    return render_template(
        "seller/buyers.html",
        matches=matches,
        seller_regions=sorted(seller_regions),
        seller_care_types=sorted(seller_care_types),
        profile=profile,
        listings=listings,
    )





@app.route("/seller/listings/new", methods=["GET", "POST"])
@login_required
@role_required("seller")
def seller_new_listing():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        if not title:
            flash("Title is required.")
            return redirect(url_for("seller_new_listing"))

        try:
            sector = resolve_sector(
                request.form.get("sector") or request.form.get("care_type")
            )
            attributes = merge_legacy_listing_attributes(
                request.form, parse_listing_attributes(request.form, sector)
            )
            asking_price_minor = parse_major_units(request.form.get("asking_price"))
            revenue_minor = parse_major_units(request.form.get("annual_revenue"))
            ebitda_minor = parse_major_units(request.form.get("annual_ebitda"))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc))
            return redirect(url_for("seller_new_listing"))

        currency = (request.form.get("currency") or "GBP").upper()
        if currency not in {"GBP", "EUR", "USD"}:
            currency = "GBP"

        listing_code = generate_listing_code()
        listing = Listing(
            seller_id=current_user.id,
            listing_code=listing_code,
            title=title,
            region=request.form.get("region") or None,
            sector=sector,
            care_type=sector.name if sector else None,
            attributes=attributes,
            beds=attributes.get("unit_count"),
            occupancy_percent=attributes.get("capacity_utilisation"),
            cqc_rating=attributes.get("regulatory_rating"),
            tenure=request.form.get("tenure") or None,
            asking_price_minor=asking_price_minor,
            revenue_minor=revenue_minor,
            ebitda_minor=ebitda_minor,
            currency=currency,
            revenue_band=request.form.get("revenue_band") or None,
            ebitda_band=request.form.get("ebitda_band") or None,
            guide_price_band=request.form.get("guide_price_band") or None,
            short_description=request.form.get("short_description") or None,
            is_confidential=bool(request.form.get("is_confidential")),
            status="draft",
        )
        db.session.add(listing)
        db.session.flush()  # ensure listing.id available before adding photos

        # Handle multi-photo upload (field name: photos)
        files = request.files.getlist("photos")
        upload_folder = app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_folder, exist_ok=True)

        cover_set = False

        for file in files:
            if not file or not file.filename:
                continue
            if not allowed_file(file.filename):
                flash(f"Unsupported image type: {file.filename}")
                continue

            original = secure_filename(file.filename)
            unique_name = f"{listing.listing_code}_{uuid.uuid4().hex}_{original}"
            file_path = os.path.join(upload_folder, unique_name)
            file.save(file_path)

            photo = ListingPhoto(
                listing_id=listing.id,
                filename=unique_name,
                is_cover=False,
            )
            db.session.add(photo)

            # Set first uploaded photo as cover + legacy field
            if not cover_set:
                photo.is_cover = True
                listing.photo_filename = unique_name
                cover_set = True

        db.session.commit()
        flash("Listing created.")
        return redirect(url_for("seller_dashboard"))

    return render_template(
        "seller/new_listing.html",
        sector_options=get_sector_options(),
    )


@app.route("/seller/listings/<int:listing_id>/edit", methods=["GET", "POST"])
@login_required
def seller_edit_listing(listing_id):
    # Ensure seller only edits their own listing
    listing = Listing.query.get_or_404(listing_id)

    if current_user.role != "seller" or listing.seller_id != current_user.id:
        flash("You do not have permission to edit this listing.")
        return redirect(url_for("seller_dashboard"))

    if request.method == "POST":
        try:
            sector = resolve_sector(
                request.form.get("sector") or request.form.get("care_type")
            )
            attributes = merge_legacy_listing_attributes(
                request.form, parse_listing_attributes(request.form, sector)
            )
            asking_price_minor = parse_major_units(request.form.get("asking_price"))
            revenue_minor = parse_major_units(request.form.get("annual_revenue"))
            ebitda_minor = parse_major_units(request.form.get("annual_ebitda"))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc))
            return redirect(url_for("seller_edit_listing", listing_id=listing.id))

        # Core fields
        listing.title = request.form.get("title") or listing.title
        listing.short_description = request.form.get("short_description") or ""
        listing.region = request.form.get("region") or None
        listing.sector = sector
        listing.care_type = sector.name if sector else None
        listing.attributes = attributes
        listing.beds = attributes.get("unit_count")
        listing.occupancy_percent = attributes.get("capacity_utilisation")
        listing.cqc_rating = attributes.get("regulatory_rating")
        listing.asking_price_minor = asking_price_minor
        listing.revenue_minor = revenue_minor
        listing.ebitda_minor = ebitda_minor
        listing.currency = (request.form.get("currency") or "GBP").upper()
        if listing.currency not in {"GBP", "EUR", "USD"}:
            listing.currency = "GBP"
        listing.tenure = request.form.get("tenure") or None
        listing.guide_price_band = request.form.get("guide_price_band") or None
        listing.revenue_band = request.form.get("revenue_band") or None
        listing.ebitda_band = request.form.get("ebitda_band") or None
        listing.is_confidential = bool(request.form.get("is_confidential"))

        # New photos (optional)
        files = request.files.getlist("photos")
        upload_folder = app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_folder, exist_ok=True)

        for file in files:
            if not file or not file.filename:
                continue
            if not allowed_file(file.filename):
                flash(f"Unsupported image type: {file.filename}")
                continue

            original = secure_filename(file.filename)
            unique_name = f"{listing.listing_code}_{uuid.uuid4().hex}_{original}"
            file_path = os.path.join(upload_folder, unique_name)
            file.save(file_path)

            photo = ListingPhoto(
                listing_id=listing.id,
                filename=unique_name,
                is_cover=False,
            )
            db.session.add(photo)

            # If listing had no cover yet, set this one
            if not any(p.is_cover for p in listing.photos):
                photo.is_cover = True
                listing.photo_filename = unique_name

        db.session.commit()
        flash("Listing updated.")
        return redirect(url_for("seller_edit_listing", listing_id=listing.id))

    # GET → render the edit page
    return render_template(
        "seller/edit_listing.html",
        listing=listing,
        sector_options=get_sector_options(),
    )


@app.route("/seller/listings/<int:listing_id>/status", methods=["POST"])
@login_required
@role_required("seller")
def seller_update_listing_status(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    if listing.seller_id != current_user.id:
        flash("You can only update your own listings.")
        return redirect(url_for("seller_dashboard"))

    status = request.form.get("status")
    allowed = {"draft", "live", "under_offer", "sold"}
    if status not in allowed:
        flash("Invalid status.")
        return redirect(url_for("seller_dashboard"))

    # Only premium sellers can set listings live
    if status == "live" and not has_active_subscription(current_user, "seller", "premium"):
        flash(
            "Upgrade to Seller Premium to set listings live and be visible to buyers.",
            "warning",
        )
        return redirect(url_for("pricing"))

    previous_status = listing.status
    listing.status = status
    if not listing.listing_code:
        listing.listing_code = generate_listing_code()
    db.session.commit()
    if status == "live" and previous_status != "live":
        publish_listing_match_notifications(listing)
    flash(f"Listing marked as {status.replace('_', ' ')}.")
    return redirect(url_for("seller_dashboard"))

@app.route("/seller/listings/<int:listing_id>/request-valuation", methods=["GET", "POST"])
@login_required
@role_required("seller")
def request_valuation(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    if listing.seller_id != current_user.id:
        abort(404)

    # Basic valuer list (all valuers with a profile)
    valuers = (
        db.session.query(User, ValuerProfile)
        .join(ValuerProfile, ValuerProfile.user_id == User.id)
        .filter(User.role == "valuer")
        .order_by(ValuerProfile.company_name.asc())
        .all()
    )

    if request.method == "POST":
        # Optional valuer selection
        raw_valuer_id = (request.form.get("valuer_id") or "").strip()
        selected_valuer_id = None
        if raw_valuer_id:
            try:
                selected_valuer_id = int(raw_valuer_id)
            except ValueError:
                selected_valuer_id = None

        if selected_valuer_id:
            selected_valuer = User.query.filter_by(
                id=selected_valuer_id,
                role="valuer",
            ).first()
            if not selected_valuer:
                flash("Please choose a valid valuer.", "error")
                return redirect(request.url)

        notes = (request.form.get("notes") or "").strip() or None

        vr = ValuationRequest(
            listing_id=listing.id,
            seller_id=current_user.id,
            valuer_id=selected_valuer_id or None,
            status="pending",
            notes=notes,
        )
        db.session.add(vr)
        db.session.commit()

        if vr.valuer:
            publish_notification(
                vr.valuer,
                event_type="valuation_request",
                title="New valuation request",
                body=f"You have a valuation request for {listing.listing_code or 'a listing'}.",
                target_url=url_for("valuer_request_detail", request_id=vr.id),
                dedupe_key=f"valuation-request:{vr.id}",
            )

        # --- EMAIL NOTIFICATIONS (BROKER + OPTIONAL VALUER) ---
        try:
            admin_email = current_app.config.get("LEADS_NOTIFICATION_EMAIL")
            valuer_email = None
            if vr.valuer_id:
                valuer_user = User.query.get(vr.valuer_id)
                if valuer_user:
                    valuer_email = valuer_user.email

            to_addresses = [e for e in [admin_email] if e]

            if to_addresses:
                subject = f"New valuation request for {listing.listing_code or 'listing'}"

                safe_notes = (notes or "").replace("\n", "<br>")

                html_body = f"""
                    <h2>New valuation request</h2>
                    <p><strong>Listing:</strong> {listing.listing_code or ''} – {listing.title}</p>
                    <p><strong>Region:</strong> {listing.region or ''}</p>
                    <p><strong>Sector / industry:</strong> {listing.care_type or ''}</p>
                    <hr>
                    <p><strong>Seller:</strong> {current_user.email}</p>
                    <p><strong>Valuer assigned:</strong> {valuer_email or "Not yet"}</p>
                    <p><strong>Notes:</strong></p>
                    <p>{safe_notes or "No additional notes."}</p>
                    <p><small>Created at: {vr.created_at}</small></p>
                """

                send_email(
                    to_addresses=to_addresses,
                    subject=subject,
                    html_body=html_body,
                    reply_to=current_user.email,
                )
        except Exception as e:
            current_app.logger.error(f"Error sending valuation request email: {e}")

        flash("Valuation request submitted.", "success")
        return redirect(url_for("seller_dashboard"))

    # GET → render form
    return render_template(
        "seller/request_valuation.html",
        listing=listing,
        valuers=valuers,
    )


@app.route("/seller/enquiries")
@login_required
@role_required("seller")
def seller_enquiries():
    enquiries = (
        Enquiry.query.join(Listing, Enquiry.listing_id == Listing.id)
        .filter(Listing.seller_id == current_user.id)
        .order_by(Enquiry.created_at.desc())
        .all()
    )
    return render_template("seller/enquiries.html", enquiries=enquiries)


@app.route("/seller/enquiries/<int:enquiry_id>/status", methods=["POST"])
@login_required
@role_required("seller")
def seller_set_enquiry_status(enquiry_id):
    enquiry = Enquiry.query.get_or_404(enquiry_id)
    if enquiry.listing.seller_id != current_user.id:
        flash("You can only update enquiries on your own listings.")
        return redirect(url_for("seller_enquiries"))

    status = request.form.get("status")
    allowed = {"new", "read", "archived"}
    if status not in allowed:
        flash("Invalid status.")
        return redirect(url_for("seller_enquiries"))

    enquiry.status = status
    db.session.commit()
    flash("Enquiry status updated.")
    return redirect(url_for("seller_enquiries"))

# -------------------------------------------------------------------
# Seller Profile (Business-Level Information)
# -------------------------------------------------------------------

@app.route("/seller/profile", methods=["GET", "POST"])
@login_required
@role_required("seller")
def seller_profile():
    profile = SellerProfile.query.filter_by(user_id=current_user.id).first()

    if request.method == "POST":
        was_new = profile is None

        # Create profile if missing
        if profile is None:
            profile = SellerProfile(user_id=current_user.id)
            db.session.add(profile)
            db.session.flush()

        # Basic fields
        profile.business_name = request.form.get("business_name") or None
        profile.turnover = request.form.get("turnover") or None
        profile.ebitda = request.form.get("ebitda") or None
        profile.profit = request.form.get("profit") or None
        profile.loss = request.form.get("loss") or None
        profile.assets = request.form.get("assets") or None
        profile.debts = request.form.get("debts") or None
        profile.staff_count = request.form.get("staff_count") or None

        profile.regions = request.form.get("regions") or None
        profile.care_type = request.form.get("care_type") or None
        profile.summary = request.form.get("summary") or None

        profile.nda_accepted = bool(request.form.get("nda_accepted"))

        # Handle uploaded documents
        files = request.files.getlist("documents")
        uploaded_documents = []
        upload_folder = app.config["SELLER_DOCS_FOLDER"]
        os.makedirs(upload_folder, exist_ok=True)

        for file in files:
            if not file or not file.filename:
                continue
            if not allowed_document(file.filename):
                flash(f"Unsupported document type: {file.filename}", "error")
                continue

            original = secure_filename(file.filename)
            unique_name = f"{uuid.uuid4().hex}_{original}"
            file_path = os.path.join(upload_folder, unique_name)
            file.save(file_path)

            doc = SellerProfileDocument(
                profile_id=profile.id,
                filename=unique_name,
                original_filename=original,
            )
            db.session.add(doc)
            uploaded_documents.append(doc)

        db.session.commit()
        for doc in uploaded_documents:
            record_audit_event(
                "document.uploaded", "Seller profile document uploaded",
                subject_user_id=current_user.id,
                resource_type="seller_profile_document", resource_id=doc.id,
                details={"file_type": os.path.splitext(doc.original_filename or "")[1].lower()},
            )

        # --- EMAIL NOTIFICATION TO BROKER ---
        try:
            admin_email = current_app.config.get("LEADS_NOTIFICATION_EMAIL")
            if admin_email:
                mode = "New" if was_new else "Updated"
                subject = f"{mode} seller profile: {profile.business_name or current_user.email}"

                html_body = f"""
                    <h2>{mode} seller profile</h2>
                    <p><strong>User:</strong> {current_user.email}</p>
                    <p><strong>Business name:</strong> {profile.business_name or "n/a"}</p>
                    <p><strong>Turnover:</strong> {profile.turnover or "n/a"}</p>
                    <p><strong>EBITDA:</strong> {profile.ebitda or "n/a"}</p>
                    <p><strong>Region(s):</strong> {profile.regions or "n/a"}</p>
                    <p><strong>Sector / industry:</strong> {profile.care_type or "n/a"}</p>
                    <p><strong>NDA accepted:</strong> {"Yes" if profile.nda_accepted else "No"}</p>
                    <p><small>Updated at: {profile.updated_at or profile.created_at}</small></p>
                """

                send_email(
                    to_addresses=admin_email,
                    subject=subject,
                    html_body=html_body,
                    reply_to=current_user.email,
                )
        except Exception as e:
            current_app.logger.error(f"Error sending seller profile email: {e}")

        flash("Seller profile updated.", "success")
        return redirect(url_for("seller_dashboard"))

    return render_template(
        "seller/profile.html",
        profile=profile,
    )


@app.route("/seller/documents/<int:document_id>/download")
@login_required
def download_seller_document(document_id):
    document = SellerProfileDocument.query.get_or_404(document_id)
    owner_id = document.profile.user_id
    if current_user.role != "admin" and current_user.id != owner_id:
        abort(404)
    path = os.path.join(app.config["SELLER_DOCS_FOLDER"], document.filename)
    if not os.path.isfile(path):
        abort(404)
    record_audit_event(
        "document.downloaded", "Seller profile document downloaded",
        subject_user_id=owner_id,
        resource_type="seller_profile_document", resource_id=document.id,
        details={"access_role": current_user.role},
    )
    return send_from_directory(
        app.config["SELLER_DOCS_FOLDER"], document.filename,
        as_attachment=True,
        download_name=document.original_filename or "document",
    )


@app.route("/seller/listings/<int:listing_id>/data-room", methods=["GET", "POST"])
@login_required
def seller_listing_data_room(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    if not can_manage_data_room(current_user, listing):
        abort(404)

    if request.method == "POST":
        upload = request.files.get("document")
        category = (request.form.get("category") or "other").strip()
        stage = (request.form.get("disclosure_stage") or "nda").strip()
        title = (request.form.get("title") or "").strip()
        replacement_id = request.form.get("replacement_id", type=int)
        categories = {key for key, _label, _stage in DATA_ROOM_CATEGORIES}
        stages = {key for key, _label, _rank in DATA_ROOM_STAGES}
        if (
            not upload
            or not upload.filename
            or not allowed_document(upload.filename)
            or upload.mimetype not in app.config["ALLOWED_DOCUMENT_MIME_TYPES"]
        ):
            flash("Choose a PDF, Word or Excel document.", "error")
            return redirect(request.url)
        if category not in categories or stage not in stages:
            flash("Choose a valid document category and disclosure stage.", "error")
            return redirect(request.url)

        original = secure_filename(upload.filename)
        extension = os.path.splitext(original)[1].lower()
        filename = f"{uuid.uuid4().hex}{extension}"
        replacement = None
        if replacement_id:
            replacement = DataRoomDocument.query.filter_by(
                id=replacement_id, listing_id=listing.id, is_current=True
            ).first_or_404()
        document_key = replacement.document_key if replacement else uuid.uuid4().hex
        version = replacement.version + 1 if replacement else 1
        path = os.path.join(app.config["DATA_ROOM_FOLDER"], filename)
        upload.save(path)
        document = DataRoomDocument(
            listing_id=listing.id,
            uploaded_by_id=current_user.id,
            document_key=document_key,
            version=version,
            category=category,
            disclosure_stage=stage,
            title=(title or original)[:200],
            filename=filename,
            original_filename=original,
            mime_type=(upload.mimetype or "application/octet-stream")[:100],
            size_bytes=os.path.getsize(path),
        )
        if replacement:
            replacement.is_current = False
        db.session.add(document)
        db.session.commit()
        record_audit_event(
            "data_room.document_replaced" if replacement else "data_room.document_uploaded",
            "Data-room document replaced" if replacement else "Data-room document uploaded",
            subject_user_id=listing.seller_id,
            resource_type="data_room_document", resource_id=document.id,
            details={"listing_id": listing.id, "stage": stage, "version": version},
        )
        for intro in Introduction.query.filter_by(listing_id=listing.id).all():
            access = intro.data_room_access
            if (
                access and not access.revoked_at
                and data_room_stage_rank(stage) <= data_room_stage_rank(access.disclosure_stage)
            ):
                publish_notification(
                    intro.buyer,
                    event_type="data_room_document",
                    title="New data-room document",
                    body=f"A document was added for {listing.listing_code or 'an opportunity'}.",
                    target_url=url_for("introduction_data_room", intro_id=intro.id),
                    dedupe_key=f"data-room-document:{document.id}:{intro.id}",
                )
        flash("Document uploaded to the data room.", "success")
        return redirect(url_for("seller_listing_data_room", listing_id=listing.id))

    documents = DataRoomDocument.query.filter_by(listing_id=listing.id).order_by(
        DataRoomDocument.created_at.desc()
    ).all()
    introductions = Introduction.query.filter_by(listing_id=listing.id).order_by(
        Introduction.created_at.desc()
    ).all()
    return render_template(
        "data_room/manage.html", listing=listing, documents=documents,
        introductions=introductions, stages=DATA_ROOM_STAGES,
        categories=DATA_ROOM_CATEGORIES,
    )


@app.route("/introductions/<int:intro_id>/data-room")
@login_required
def introduction_data_room(intro_id):
    intro = Introduction.query.get_or_404(intro_id)
    is_party = current_user.id in {intro.buyer_id, intro.seller_id}
    if current_user.role != "admin" and not is_party:
        abort(404)
    access = intro.data_room_access
    can_manage = can_manage_data_room(current_user, intro.listing)
    query = DataRoomDocument.query.filter_by(
        listing_id=intro.listing_id, is_current=True, archived_at=None
    )
    if not can_manage:
        if not access or access.revoked_at:
            documents = []
        else:
            allowed_stages = [
                key for key, _label, rank in DATA_ROOM_STAGES
                if rank <= data_room_stage_rank(access.disclosure_stage)
            ]
            documents = query.filter(
                DataRoomDocument.disclosure_stage.in_(allowed_stages)
            ).order_by(DataRoomDocument.category, DataRoomDocument.title).all()
    else:
        documents = query.order_by(DataRoomDocument.category, DataRoomDocument.title).all()
    return render_template(
        "data_room/introduction.html", introduction=intro, access=access,
        documents=documents, can_manage=can_manage,
        stages=DATA_ROOM_STAGES,
    )


@app.route("/introductions/<int:intro_id>/data-room/access", methods=["POST"])
@login_required
def update_data_room_access(intro_id):
    intro = Introduction.query.get_or_404(intro_id)
    if not can_manage_data_room(current_user, intro.listing):
        abort(404)
    stage = (request.form.get("disclosure_stage") or "").strip()
    valid_stages = {key for key, _label, _rank in DATA_ROOM_STAGES}
    access = intro.data_room_access
    if stage == "revoked":
        if access and not access.revoked_at:
            access.revoked_at = utcnow()
            access.updated_at = utcnow()
            db.session.commit()
            record_audit_event(
                "data_room.access_revoked", "Data-room access revoked",
                subject_user_id=intro.buyer_id, resource_type="introduction",
                resource_id=intro.id,
            )
            publish_notification(
                intro.buyer, event_type="data_room_access",
                title="Data-room access changed",
                body=f"Your data-room access for {intro.listing.listing_code or 'an opportunity'} was revoked.",
                target_url=url_for("buyer_dashboard"),
                dedupe_key=f"data-room-access:{intro.id}:revoked:{int(utcnow().timestamp())}",
            )
        flash("Data-room access revoked.", "success")
        return redirect(url_for("introduction_data_room", intro_id=intro.id))
    if intro.status in {"pending_seller_request", "declined", "failed"}:
        flash("Access can only be granted after an introduction is approved.", "error")
        return redirect(url_for("introduction_data_room", intro_id=intro.id))
    if stage not in valid_stages:
        flash("Choose a valid disclosure stage.", "error")
        return redirect(url_for("introduction_data_room", intro_id=intro.id))
    if access:
        previous_stage = access.disclosure_stage
        access.disclosure_stage = stage
        access.granted_by_id = current_user.id
        access.granted_at = utcnow()
        access.revoked_at = None
        access.updated_at = utcnow()
    else:
        previous_stage = None
        access = DataRoomAccess(
            introduction_id=intro.id, disclosure_stage=stage,
            granted_by_id=current_user.id,
        )
        db.session.add(access)
    db.session.commit()
    record_audit_event(
        "data_room.access_granted", "Data-room access granted or updated",
        subject_user_id=intro.buyer_id, resource_type="introduction",
        resource_id=intro.id,
        details={"previous_stage": previous_stage, "stage": stage},
    )
    publish_notification(
        intro.buyer, event_type="data_room_access",
        title="Data-room access granted",
        body=f"You can now access documents up to {data_room_stage_label(stage)} for {intro.listing.listing_code or 'an opportunity'}.",
        target_url=url_for("introduction_data_room", intro_id=intro.id),
        dedupe_key=f"data-room-access:{intro.id}:{stage}:{int(utcnow().timestamp())}",
    )
    flash("Data-room access updated.", "success")
    return redirect(url_for("introduction_data_room", intro_id=intro.id))


@app.route("/data-room/documents/<int:document_id>/archive", methods=["POST"])
@login_required
def archive_data_room_document(document_id):
    document = DataRoomDocument.query.get_or_404(document_id)
    if not can_manage_data_room(current_user, document.listing):
        abort(404)
    document.archived_at = utcnow()
    document.is_current = False
    db.session.commit()
    record_audit_event(
        "data_room.document_archived", "Data-room document archived",
        subject_user_id=document.listing.seller_id,
        resource_type="data_room_document", resource_id=document.id,
        details={"listing_id": document.listing_id},
    )
    flash("Document archived. Its audit and version history were retained.", "success")
    return redirect(url_for("seller_listing_data_room", listing_id=document.listing_id))


@app.route("/data-room/documents/<int:document_id>/download")
@login_required
def download_data_room_document(document_id):
    document = DataRoomDocument.query.get_or_404(document_id)
    if not can_download_data_room_document(current_user, document):
        abort(404)
    path = os.path.join(app.config["DATA_ROOM_FOLDER"], document.filename)
    if not os.path.isfile(path):
        abort(404)
    access = buyer_data_room_access(current_user, document.listing)
    record_audit_event(
        "data_room.document_downloaded", "Data-room document downloaded",
        subject_user_id=document.listing.seller_id,
        resource_type="data_room_document", resource_id=document.id,
        details={
            "listing_id": document.listing_id,
            "introduction_id": access.introduction_id if access else None,
            "version": document.version,
        },
    )
    return send_from_directory(
        app.config["DATA_ROOM_FOLDER"], document.filename,
        as_attachment=True, download_name=document.original_filename,
    )


@app.route("/introductions/<int:intro_id>/workspace")
@login_required
def deal_workspace(intro_id):
    intro = Introduction.query.get_or_404(intro_id)
    if not can_access_deal_workspace(current_user, intro):
        abort(404)
    expire_structured_offers(intro.id)
    messages = WorkspaceMessage.query.filter_by(introduction_id=intro.id).order_by(
        WorkspaceMessage.created_at.asc()
    ).all()
    tasks = WorkspaceTask.query.filter_by(introduction_id=intro.id).order_by(
        WorkspaceTask.status.asc(), WorkspaceTask.due_date.asc(), WorkspaceTask.created_at.asc()
    ).all()
    milestones = WorkspaceMilestone.query.filter_by(introduction_id=intro.id).order_by(
        WorkspaceMilestone.sort_order.asc(), WorkspaceMilestone.due_date.asc()
    ).all()
    offers = StructuredOffer.query.filter_by(introduction_id=intro.id).order_by(
        StructuredOffer.sequence.desc()
    ).all()
    return render_template(
        "workspace/index.html", introduction=intro, messages=messages,
        tasks=tasks, milestones=milestones, offers=offers,
        participants=(intro.buyer, intro.seller),
        can_negotiate=can_negotiate_offer(current_user, intro),
        has_accepted_offer=any(offer.status == "accepted" for offer in offers),
    )


@app.route("/introductions/<int:intro_id>/workspace/offers", methods=["POST"])
@login_required
def submit_structured_offer(intro_id):
    intro = Introduction.query.get_or_404(intro_id)
    if not can_negotiate_offer(current_user, intro):
        abort(404)
    expire_structured_offers(intro.id)
    intro = Introduction.query.filter_by(id=intro.id).with_for_update().one()
    if StructuredOffer.query.filter_by(
        introduction_id=intro.id, status="accepted"
    ).first():
        flash("An offer has already been accepted for this introduction.", "error")
        return redirect(url_for("deal_workspace", intro_id=intro.id))
    try:
        values = _parse_offer_form()
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("deal_workspace", intro_id=intro.id))

    offer = StructuredOffer(
        introduction_id=intro.id,
        sequence=_next_offer_sequence(intro.id),
        created_by_id=current_user.id,
        recipient_id=_offer_recipient(intro, current_user.id).id,
        **values,
    )
    db.session.add(offer)
    old_status = intro.status
    if intro.status in {"initiated", "nda_signed", "viewing"}:
        intro.status = "offer_made"
        db.session.add(IntroductionStatusHistory(
            introduction_id=intro.id, old_status=old_status, new_status="offer_made",
            changed_by_user_id=current_user.id, note="Structured offer submitted",
        ))
    intro.updated_at = utcnow()
    db.session.commit()
    record_audit_event(
        "offer.submitted", "Structured offer submitted",
        subject_user_id=offer.recipient_id, resource_type="structured_offer",
        resource_id=offer.id,
        details={"introduction_id": intro.id, "sequence": offer.sequence, "currency": offer.currency},
    )
    publish_notification(
        offer.recipient, event_type="offer_submitted", title="New structured offer",
        body=f"Offer #{offer.sequence} was submitted for {intro.listing.listing_code or 'an introduction'}.",
        target_url=url_for("deal_workspace", intro_id=intro.id),
        dedupe_key=f"offer:{offer.id}:submitted",
    )
    flash("Offer submitted and added to the permanent history.", "success")
    return redirect(url_for("deal_workspace", intro_id=intro.id))


@app.route("/workspace/offers/<int:offer_id>/respond", methods=["POST"])
@login_required
def respond_to_structured_offer(offer_id):
    offer = StructuredOffer.query.get_or_404(offer_id)
    intro = offer.introduction
    if not can_negotiate_offer(current_user, intro):
        abort(404)
    expire_structured_offers(intro.id)
    intro = Introduction.query.filter_by(id=intro.id).with_for_update().one()
    db.session.refresh(offer)
    action = (request.form.get("action") or "").strip()
    if offer.status != "submitted":
        flash("This offer is no longer open.", "error")
        return redirect(url_for("deal_workspace", intro_id=intro.id))

    if action == "withdraw":
        if current_user.id != offer.created_by_id:
            abort(404)
        offer.status = "withdrawn"
        offer.responded_at = utcnow()
        recipient = offer.recipient
        event_type, title = "offer_withdrawn", "Offer withdrawn"
    elif action in {"accept", "reject", "counter"}:
        if current_user.id != offer.recipient_id:
            abort(404)
        if action == "counter":
            try:
                values = _parse_offer_form()
            except ValueError as exc:
                flash(str(exc), "error")
                return redirect(url_for("deal_workspace", intro_id=intro.id))
            offer.status = "countered"
            offer.responded_at = utcnow()
            counter = StructuredOffer(
                introduction_id=intro.id, parent_offer_id=offer.id,
                sequence=_next_offer_sequence(intro.id), created_by_id=current_user.id,
                recipient_id=offer.created_by_id, **values,
            )
            db.session.add(counter)
            intro.updated_at = utcnow()
            db.session.commit()
            record_audit_event(
                "offer.countered", "Structured offer countered",
                subject_user_id=counter.recipient_id, resource_type="structured_offer",
                resource_id=counter.id,
                details={"introduction_id": intro.id, "sequence": counter.sequence, "parent_offer_id": offer.id},
            )
            publish_notification(
                counter.recipient, event_type="offer_countered", title="Counter-offer received",
                body=f"Counter-offer #{counter.sequence} was submitted for {intro.listing.listing_code or 'an introduction'}.",
                target_url=url_for("deal_workspace", intro_id=intro.id),
                dedupe_key=f"offer:{counter.id}:countered",
            )
            flash("Counter-offer submitted.", "success")
            return redirect(url_for("deal_workspace", intro_id=intro.id))
        if action == "reject":
            offer.status = "rejected"
            offer.responded_at = utcnow()
            recipient = offer.creator
            event_type, title = "offer_rejected", "Offer declined"
        else:
            now = utcnow()
            offer.status = "accepted"
            offer.responded_at = now
            for other in StructuredOffer.query.filter(
                StructuredOffer.introduction_id == intro.id,
                StructuredOffer.id != offer.id,
                StructuredOffer.status == "submitted",
            ).all():
                other.status = "superseded"
                other.responded_at = now
            old_status = intro.status
            intro.status = "offer_accepted"
            intro.offer_amount = offer.display_amount
            intro.offer_date = offer.created_at
            intro.offer_terms = offer.terms
            intro.updated_at = now
            if old_status != "offer_accepted":
                db.session.add(IntroductionStatusHistory(
                    introduction_id=intro.id, old_status=old_status,
                    new_status="offer_accepted", changed_by_user_id=current_user.id,
                    note=f"Structured offer #{offer.sequence} accepted",
                ))
            deal = Deal.query.filter_by(introduction_id=intro.id).first()
            if deal is None:
                deal = Deal(introduction_id=intro.id, broker_commission_percent=2.0)
                db.session.add(deal)
            deal.agreed_price = offer.display_amount
            if deal.status != "completed":
                deal.status = "in_progress"
            commission_percent = deal.broker_commission_percent
            if commission_percent is not None:
                deal.broker_commission_amount = int(round(
                    offer.amount_minor * commission_percent / 100
                ))
            recipient = offer.creator
            event_type, title = "offer_accepted", "Offer accepted"
    else:
        flash("Choose a valid offer action.", "error")
        return redirect(url_for("deal_workspace", intro_id=intro.id))

    intro.updated_at = utcnow()
    db.session.commit()
    record_audit_event(
        f"offer.{offer.status}", f"Structured offer {offer.status}",
        subject_user_id=recipient.id, resource_type="structured_offer", resource_id=offer.id,
        details={"introduction_id": intro.id, "sequence": offer.sequence},
    )
    publish_notification(
        recipient, event_type=event_type, title=title,
        body=f"Offer #{offer.sequence} for {intro.listing.listing_code or 'an introduction'} was {offer.status}.",
        target_url=url_for("deal_workspace", intro_id=intro.id),
        dedupe_key=f"offer:{offer.id}:{offer.status}",
    )
    flash(f"Offer {offer.status}.", "success")
    return redirect(url_for("deal_workspace", intro_id=intro.id))


@app.route("/introductions/<int:intro_id>/workspace/messages", methods=["POST"])
@login_required
def add_workspace_message(intro_id):
    intro = Introduction.query.get_or_404(intro_id)
    if not can_access_deal_workspace(current_user, intro):
        abort(404)
    body = (request.form.get("body") or "").strip()
    message_type = (request.form.get("message_type") or "message").strip()
    if not body or message_type not in {"message", "question"}:
        flash("Enter a message or question.", "error")
        return redirect(url_for("deal_workspace", intro_id=intro.id))
    message = WorkspaceMessage(
        introduction_id=intro.id, author_id=current_user.id,
        message_type=message_type, body=body[:5000],
    )
    db.session.add(message)
    intro.updated_at = utcnow()
    db.session.commit()
    record_audit_event(
        "workspace.question_added" if message_type == "question" else "workspace.message_added",
        "Deal-workspace question added" if message_type == "question" else "Deal-workspace message added",
        subject_user_id=intro.seller_id, resource_type="workspace_message",
        resource_id=message.id, details={"introduction_id": intro.id},
    )
    if message.author_id != current_user.id:
        publish_notification(
            message.author, event_type="workspace_question",
            title="Deal question resolved" if resolved else "Deal question reopened",
            body=f"Your question for {intro.listing.listing_code or 'an introduction'} was {'resolved' if resolved else 'reopened'}.",
            target_url=url_for("deal_workspace", intro_id=intro.id),
            dedupe_key=f"workspace-question:{message.id}:{'resolved' if resolved else 'reopened'}",
        )
    for recipient in workspace_recipients(intro, current_user.id):
        publish_notification(
            recipient, event_type="workspace_message",
            title="New deal-workspace question" if message_type == "question" else "New deal-workspace message",
            body=f"A new update was posted for {intro.listing.listing_code or 'an introduction'}.",
            target_url=url_for("deal_workspace", intro_id=intro.id),
            dedupe_key=f"workspace-message:{message.id}:{recipient.id}",
        )
    flash("Question added." if message_type == "question" else "Message posted.", "success")
    return redirect(url_for("deal_workspace", intro_id=intro.id))


@app.route("/workspace/messages/<int:message_id>/resolve", methods=["POST"])
@login_required
def resolve_workspace_question(message_id):
    message = WorkspaceMessage.query.get_or_404(message_id)
    intro = message.introduction
    if not can_access_deal_workspace(current_user, intro) or message.message_type != "question":
        abort(404)
    resolved = (request.form.get("resolved") or "1") == "1"
    message.resolved_at = utcnow() if resolved else None
    message.resolved_by_id = current_user.id if resolved else None
    db.session.commit()
    record_audit_event(
        "workspace.question_resolved" if resolved else "workspace.question_reopened",
        "Deal-workspace question resolved" if resolved else "Deal-workspace question reopened",
        subject_user_id=intro.seller_id, resource_type="workspace_message",
        resource_id=message.id, details={"introduction_id": intro.id},
    )
    return redirect(url_for("deal_workspace", intro_id=intro.id))


@app.route("/introductions/<int:intro_id>/workspace/tasks", methods=["POST"])
@login_required
def add_workspace_task(intro_id):
    intro = Introduction.query.get_or_404(intro_id)
    if not can_access_deal_workspace(current_user, intro):
        abort(404)
    title = (request.form.get("title") or "").strip()
    owner_id = request.form.get("owner_id", type=int)
    if not title or owner_id not in {intro.buyer_id, intro.seller_id}:
        flash("Enter a task and choose a deal participant.", "error")
        return redirect(url_for("deal_workspace", intro_id=intro.id))
    due_date = None
    due_raw = (request.form.get("due_date") or "").strip()
    if due_raw:
        try:
            due_date = datetime.strptime(due_raw, "%Y-%m-%d").date()
        except ValueError:
            flash("Choose a valid due date.", "error")
            return redirect(url_for("deal_workspace", intro_id=intro.id))
    task = WorkspaceTask(
        introduction_id=intro.id, title=title[:200],
        description=((request.form.get("description") or "").strip()[:3000] or None),
        owner_id=owner_id, created_by_id=current_user.id, due_date=due_date,
    )
    db.session.add(task)
    intro.updated_at = utcnow()
    db.session.commit()
    record_audit_event(
        "workspace.task_created", "Deal-workspace task created",
        subject_user_id=owner_id, resource_type="workspace_task", resource_id=task.id,
        details={"introduction_id": intro.id, "due_date": str(due_date) if due_date else None},
    )
    publish_notification(
        task.owner, event_type="workspace_task", title="New deal task assigned",
        body=f"{task.title} was assigned for {intro.listing.listing_code or 'an introduction'}.",
        target_url=url_for("deal_workspace", intro_id=intro.id),
        dedupe_key=f"workspace-task:{task.id}:created",
    )
    flash("Task added.", "success")
    return redirect(url_for("deal_workspace", intro_id=intro.id))


@app.route("/workspace/tasks/<int:task_id>/status", methods=["POST"])
@login_required
def update_workspace_task(task_id):
    task = WorkspaceTask.query.get_or_404(task_id)
    intro = task.introduction
    if not can_access_deal_workspace(current_user, intro):
        abort(404)
    status = (request.form.get("status") or "").strip()
    if status not in {"todo", "in_progress", "completed"}:
        flash("Choose a valid task status.", "error")
        return redirect(url_for("deal_workspace", intro_id=intro.id))
    task.status = status
    task.completed_at = utcnow() if status == "completed" else None
    task.updated_at = utcnow()
    db.session.commit()
    record_audit_event(
        "workspace.task_status_changed", "Deal-workspace task status changed",
        subject_user_id=task.owner_id, resource_type="workspace_task", resource_id=task.id,
        details={"introduction_id": intro.id, "status": status},
    )
    if task.owner_id != current_user.id:
        publish_notification(
            task.owner, event_type="workspace_task",
            title="Deal task updated", body=f"{task.title} is now {status.replace('_', ' ')}.",
            target_url=url_for("deal_workspace", intro_id=intro.id),
            dedupe_key=f"workspace-task:{task.id}:{status}",
        )
    flash("Task updated.", "success")
    return redirect(url_for("deal_workspace", intro_id=intro.id))


@app.route("/introductions/<int:intro_id>/workspace/milestones", methods=["POST"])
@login_required
def add_workspace_milestone(intro_id):
    intro = Introduction.query.get_or_404(intro_id)
    if not can_access_deal_workspace(current_user, intro):
        abort(404)
    title = (request.form.get("title") or "").strip()
    if not title:
        flash("Enter a milestone title.", "error")
        return redirect(url_for("deal_workspace", intro_id=intro.id))
    due_date = None
    due_raw = (request.form.get("due_date") or "").strip()
    if due_raw:
        try:
            due_date = datetime.strptime(due_raw, "%Y-%m-%d").date()
        except ValueError:
            flash("Choose a valid milestone date.", "error")
            return redirect(url_for("deal_workspace", intro_id=intro.id))
    milestone = WorkspaceMilestone(
        introduction_id=intro.id, title=title[:200], due_date=due_date,
        sort_order=WorkspaceMilestone.query.filter_by(introduction_id=intro.id).count(),
        created_by_id=current_user.id,
    )
    db.session.add(milestone)
    intro.updated_at = utcnow()
    db.session.commit()
    record_audit_event(
        "workspace.milestone_created", "Deal-workspace milestone created",
        subject_user_id=intro.seller_id, resource_type="workspace_milestone",
        resource_id=milestone.id, details={"introduction_id": intro.id},
    )
    for recipient in workspace_recipients(intro, current_user.id):
        publish_notification(
            recipient, event_type="workspace_milestone", title="New deal milestone",
            body=f"{milestone.title} was added for {intro.listing.listing_code or 'an introduction'}.",
            target_url=url_for("deal_workspace", intro_id=intro.id),
            dedupe_key=f"workspace-milestone:{milestone.id}:{recipient.id}",
        )
    flash("Milestone added.", "success")
    return redirect(url_for("deal_workspace", intro_id=intro.id))


@app.route("/workspace/milestones/<int:milestone_id>/status", methods=["POST"])
@login_required
def update_workspace_milestone(milestone_id):
    milestone = WorkspaceMilestone.query.get_or_404(milestone_id)
    intro = milestone.introduction
    if not can_access_deal_workspace(current_user, intro):
        abort(404)
    status = (request.form.get("status") or "").strip()
    if status not in {"planned", "completed"}:
        flash("Choose a valid milestone status.", "error")
        return redirect(url_for("deal_workspace", intro_id=intro.id))
    milestone.status = status
    milestone.completed_at = utcnow() if status == "completed" else None
    db.session.commit()
    record_audit_event(
        "workspace.milestone_status_changed", "Deal-workspace milestone status changed",
        subject_user_id=intro.seller_id, resource_type="workspace_milestone",
        resource_id=milestone.id, details={"introduction_id": intro.id, "status": status},
    )
    for recipient in workspace_recipients(intro, current_user.id):
        publish_notification(
            recipient, event_type="workspace_milestone",
            title="Deal milestone updated",
            body=f"{milestone.title} is now {status}.",
            target_url=url_for("deal_workspace", intro_id=intro.id),
            dedupe_key=f"workspace-milestone:{milestone.id}:{status}:{recipient.id}",
        )
    flash("Milestone updated.", "success")
    return redirect(url_for("deal_workspace", intro_id=intro.id))


@app.route("/buyer/profile", methods=["GET", "POST"])
@login_required
@role_required("buyer")
def buyer_profile():
    profile = BuyerProfile.query.filter_by(user_id=current_user.id).first()

    # Choices for checkboxes / selects
    region_choices = sorted(REGION_COORDS.keys())
    # Kept on the legacy care_types field until the generic sector migration.
    care_type_choices = [
        "Healthcare & Social Care",
        "Hospitality & Leisure",
        "Professional Services",
        "Retail & E-commerce",
        "Technology & Software",
        "Manufacturing",
        "Construction & Property",
        "Recruitment",
        "Residential",
        "Nursing",
        "Dementia / EMI",
        "Learning disability",
        "Mental health",
        "Supported living",
        "Other",
    ]
    dd_choices = [
        "Financial due diligence",
        "Operational due diligence",
        "Clinical quality review",
        "Property / estates review",
        "Regulatory / compliance review",
    ]

    if request.method == "POST":
        was_new = profile is None

        # Basic details
        business_name = (request.form.get("business_name") or "").strip() or None
        contact_person = (request.form.get("contact_person") or "").strip() or None
        phone = (request.form.get("phone") or "").strip() or None

        # Deal appetite
        investment_type = (request.form.get("investment_type") or "").strip() or None
        deal_structure = (request.form.get("deal_structure") or "").strip() or None

        # Financials
        min_budget = (request.form.get("min_budget") or "").strip() or None
        max_budget = (request.form.get("max_budget") or "").strip() or None
        proof_of_funds = (request.form.get("proof_of_funds") or "").strip() or None
        preferred_multiple = (request.form.get("preferred_multiple") or "").strip() or None
        funding_source = (request.form.get("funding_source") or "").strip() or None

        # Target criteria (checkbox groups)
        preferred_regions_list = request.form.getlist("preferred_regions")
        care_types_list = request.form.getlist("care_types")

        preferred_regions = ",".join(preferred_regions_list) if preferred_regions_list else None
        care_types = ",".join(care_types_list) if care_types_list else None

        beds_min = request.form.get("beds_min") or None
        beds_max = request.form.get("beds_max") or None
        beds_min = int(beds_min) if beds_min else None
        beds_max = int(beds_max) if beds_max else None

        quality_preference = (request.form.get("quality_preference") or "").strip() or None
        turnaround_interest = (request.form.get("turnaround_interest") or "").strip() or None

        # Timing & strategy
        transaction_timeline = (request.form.get("transaction_timeline") or "").strip() or None
        expansion_strategy = (request.form.get("expansion_strategy") or "").strip() or None

        # Advisors & DD
        has_buy_side_advisor = bool(request.form.get("has_buy_side_advisor"))
        advisor_details = (request.form.get("advisor_details") or "").strip() or None

        requirements_dd_list = request.form.getlist("requirements_dd")
        requirements_dd = ",".join(requirements_dd_list) if requirements_dd_list else None

        # NDA
        nda_signed = bool(request.form.get("nda_signed"))

        # Create or update
        if profile is None:
            profile = BuyerProfile(
                user_id=current_user.id,
                business_name=business_name,
                contact_person=contact_person,
                phone=phone,
                investment_type=investment_type,
                deal_structure=deal_structure,
                min_budget=min_budget,
                max_budget=max_budget,
                proof_of_funds=proof_of_funds,
                preferred_multiple=preferred_multiple,
                funding_source=funding_source,
                preferred_regions=preferred_regions,
                care_types=care_types,
                beds_min=beds_min,
                beds_max=beds_max,
                quality_preference=quality_preference,
                turnaround_interest=turnaround_interest,
                transaction_timeline=transaction_timeline,
                expansion_strategy=expansion_strategy,
                has_buy_side_advisor=has_buy_side_advisor,
                advisor_details=advisor_details,
                requirements_dd=requirements_dd,
                nda_signed=nda_signed,
            )
            db.session.add(profile)
        else:
            profile.business_name = business_name
            profile.contact_person = contact_person
            profile.phone = phone
            profile.investment_type = investment_type
            profile.deal_structure = deal_structure
            profile.min_budget = min_budget
            profile.max_budget = max_budget
            profile.proof_of_funds = proof_of_funds
            profile.preferred_multiple = preferred_multiple
            profile.funding_source = funding_source
            profile.preferred_regions = preferred_regions
            profile.care_types = care_types
            profile.beds_min = beds_min
            profile.beds_max = beds_max
            profile.quality_preference = quality_preference
            profile.turnaround_interest = turnaround_interest
            profile.transaction_timeline = transaction_timeline
            profile.expansion_strategy = expansion_strategy
            profile.has_buy_side_advisor = has_buy_side_advisor
            profile.advisor_details = advisor_details
            profile.requirements_dd = requirements_dd
            profile.nda_signed = nda_signed

        db.session.commit()

        # --- EMAIL NOTIFICATION TO BROKER ---
        try:
            admin_email = current_app.config.get("LEADS_NOTIFICATION_EMAIL")
            if admin_email:
                mode = "New" if was_new else "Updated"

                # Work out current subscription tier, if any
                tier = "Basic / None"
                try:
                    sub = (
                        Subscription.query
                        .filter_by(user_id=current_user.id, role="buyer", is_active=True)
                        .order_by(Subscription.started_at.desc())
                        .first()
                    )
                    if sub:
                        tier = f"{sub.tier.capitalize()} ({sub.role})"
                except Exception:
                    pass

                subject = f"{mode} buyer profile: {business_name or current_user.email}"

                html_body = f"""
                    <h2>{mode} buyer profile</h2>
                    <p><strong>User:</strong> {current_user.email}</p>
                    <p><strong>Business name:</strong> {business_name or "n/a"}</p>
                    <p><strong>Investment type:</strong> {investment_type or "n/a"}</p>
                    <p><strong>Budget range:</strong> {min_budget or "?"} – {max_budget or "?"}</p>
                    <p><strong>Preferred regions:</strong> {preferred_regions or "n/a"}</p>
                    <p><strong>Care types:</strong> {care_types or "n/a"}</p>
                    <p><strong>Timeline:</strong> {transaction_timeline or "n/a"}</p>
                    <p><strong>NDA signed:</strong> {"Yes" if nda_signed else "No"}</p>
                    <p><strong>Current tier:</strong> {tier}</p>
                """

                send_email(
                    to_addresses=admin_email,
                    subject=subject,
                    html_body=html_body,
                    reply_to=current_user.email,
                )
        except Exception as e:
            current_app.logger.error(f"Error sending buyer profile email: {e}")

        flash("Buyer profile saved.", "success")
        return redirect(url_for("buyer_dashboard"))

    # GET → decode CSV fields for checkbox pre-selection
    selected_regions = []
    selected_care_types = []
    selected_dd = []

    if profile:
        if profile.preferred_regions:
            selected_regions = [r.strip() for r in profile.preferred_regions.split(",") if r.strip()]
        if profile.care_types:
            selected_care_types = [c.strip() for c in profile.care_types.split(",") if c.strip()]
        if profile.requirements_dd:
            selected_dd = [d.strip() for d in profile.requirements_dd.split(",") if d.strip()]

    return render_template(
        "buyer/profile.html",
        profile=profile,
        region_choices=region_choices,
        care_type_choices=care_type_choices,
        dd_choices=dd_choices,
        selected_regions=selected_regions,
        selected_care_types=selected_care_types,
        selected_dd=selected_dd,
    )


@app.route("/buyer/qualification", methods=["GET", "POST"])
@login_required
@role_required("buyer")
def buyer_qualification():
    qualification = BuyerQualification.query.filter_by(user_id=current_user.id).first()
    if request.method == "POST":
        if not qualification:
            qualification = BuyerQualification(user_id=current_user.id)
            db.session.add(qualification)
        legal_name = (request.form.get("legal_name") or "").strip()
        if not legal_name:
            flash("Enter your legal name or the legal name of the acquiring entity.", "error")
            return redirect(request.url)
        try:
            acquisitions_completed = max(
                0, int(request.form.get("acquisitions_completed") or 0)
            )
        except ValueError:
            flash("Completed acquisitions must be a whole number.", "error")
            return redirect(request.url)
        qualification.legal_name = legal_name[:255]
        qualification.company_number = (
            (request.form.get("company_number") or "").strip()[:50] or None
        )
        qualification.website = (
            (request.form.get("website") or "").strip()[:255] or None
        )
        qualification.acquisitions_completed = acquisitions_completed
        qualification.track_record_summary = (
            (request.form.get("track_record_summary") or "").strip()[:3000] or None
        )
        qualification.identity_status = "pending"
        qualification.business_status = (
            "pending" if qualification.company_number or qualification.website else "not_submitted"
        )
        evidence = request.files.get("funds_evidence")
        if evidence and evidence.filename:
            if (
                not allowed_document(evidence.filename)
                or evidence.mimetype not in app.config["ALLOWED_DOCUMENT_MIME_TYPES"]
            ):
                flash("Proof of funds must be a PDF, Word or Excel document.", "error")
                return redirect(request.url)
            original = secure_filename(evidence.filename)
            extension = os.path.splitext(original)[1].lower()
            filename = f"{uuid.uuid4().hex}{extension}"
            path = os.path.join(app.config["BUYER_EVIDENCE_FOLDER"], filename)
            evidence.save(path)
            qualification.funds_filename = filename
            qualification.funds_original_filename = original
            qualification.funds_mime_type = evidence.mimetype[:100]
            qualification.funds_size_bytes = os.path.getsize(path)
            qualification.funds_status = "pending"
        elif qualification.funds_filename:
            # A resubmission can change the acquiring entity, so prior funding
            # approval must be reviewed again even when the file is unchanged.
            qualification.funds_status = "pending"
        qualification.submitted_at = utcnow()
        qualification.updated_at = utcnow()
        qualification.reviewed_at = None
        qualification.reviewed_by_id = None
        db.session.commit()
        record_audit_event(
            "buyer.qualification_submitted", "Buyer qualification submitted for review",
            subject_user_id=current_user.id, resource_type="buyer_qualification",
            resource_id=qualification.id,
            details={"has_funds_evidence": bool(qualification.funds_filename)},
        )
        publish_role_notification(
            "admin", event_type="buyer_qualification",
            title="Buyer qualification awaiting review",
            body=f"Buyer {current_user.id} submitted qualification evidence.",
            target_url=url_for("admin_buyer_qualification", buyer_id=current_user.id),
            dedupe_key=f"buyer-qualification:{qualification.id}:{int(qualification.submitted_at.timestamp())}",
        )
        flash("Qualification submitted for review.", "success")
        return redirect(url_for("buyer_qualification"))
    return render_template("buyer/qualification.html", qualification=qualification)


@app.route("/buyer/qualification/evidence")
@login_required
@role_required("buyer")
def buyer_qualification_evidence():
    qualification = BuyerQualification.query.filter_by(user_id=current_user.id).first_or_404()
    return _send_buyer_evidence(qualification)


def _send_buyer_evidence(qualification):
    if not qualification.funds_filename:
        abort(404)
    path = os.path.join(app.config["BUYER_EVIDENCE_FOLDER"], qualification.funds_filename)
    if not os.path.isfile(path):
        abort(404)
    record_audit_event(
        "buyer.qualification_evidence_downloaded",
        "Private proof-of-funds evidence downloaded",
        subject_user_id=qualification.user_id,
        resource_type="buyer_qualification", resource_id=qualification.id,
        details={"access_role": current_user.role},
    )
    return send_from_directory(
        app.config["BUYER_EVIDENCE_FOLDER"], qualification.funds_filename,
        as_attachment=True,
        download_name=qualification.funds_original_filename or "proof-of-funds",
    )

@app.route("/buyer/dashboard")
@login_required
@role_required("buyer")
def buyer_dashboard():
    """
    Buyer dashboard:
    - Shows recent enquiries
    - Shows recommended live listings based on buyer profile
    - Shows a persistent shortlist and saved searches
    """
    # Recent enquiries for this buyer
    enquiries = (
        Enquiry.query
        .join(Listing, Enquiry.listing_id == Listing.id)
        .filter(Enquiry.buyer_id == current_user.id)
        .order_by(Enquiry.created_at.desc())
        .limit(10)
        .all()
    )

    # Base query: live listings only
    recommendations_query = Listing.query.filter_by(status="live")

    # Exclude listings already enquired about
    enquired_ids = [e.listing_id for e in enquiries]
    if enquired_ids:
        recommendations_query = recommendations_query.filter(
            ~Listing.id.in_(enquired_ids)
        )

    # Apply buyer profile filters if present
    profile = BuyerProfile.query.filter_by(user_id=current_user.id).first()
    qualification = BuyerQualification.query.filter_by(user_id=current_user.id).first()
    is_premium = is_premium_buyer(current_user)
    active_sub = get_active_subscription_for_role(current_user, "buyer")
    current_plan_label = None
    if active_sub:
        current_plan_label = f"{active_sub.role.capitalize()} {active_sub.tier.capitalize()}"
    profile_complete = bool(profile and profile.is_complete())

    if profile:
        # Legacy simple filters (keep for now so it "just works")
        if profile.region:
            recommendations_query = recommendations_query.filter(
                Listing.region == profile.region
            )
        if profile.care_type:
            recommendations_query = recommendations_query.filter(
                Listing.care_type == profile.care_type
            )

        if profile.min_price_band:
            recommendations_query = recommendations_query.filter(
                (Listing.guide_price_band == profile.min_price_band)
                | (Listing.guide_price_band == profile.max_price_band)
                | (Listing.guide_price_band == "On request")
            )

    recommendations = (
        recommendations_query
        .order_by(Listing.created_at.desc())
        .limit(6)
        .all()
    )
    match_results = compute_matches_for_buyer(current_user, limit=6)
    top_matches = [listing for listing, _score, _reasons in match_results]

    # Persistent buyer tools
    shortlist_ids = get_shortlist_ids()
    shortlist_listings = []
    if shortlist_ids:
        shortlist_listings = (
            Listing.query
            .filter(
                Listing.id.in_(shortlist_ids),
                Listing.status == "live",
            )
            .order_by(Listing.created_at.desc())
            .all()
        )
    saved_searches = (
        SavedSearch.query.filter_by(buyer_id=current_user.id)
        .order_by(SavedSearch.created_at.desc())
        .limit(5)
        .all()
    )
    data_room_introductions = (
        Introduction.query.filter_by(buyer_id=current_user.id)
        .order_by(Introduction.updated_at.desc())
        .all()
    )

    return render_template(
        "buyer/dashboard.html",   # <-- key fix vs buyer_dashboard.html
        enquiries=enquiries,
        recommendations=recommendations,
        shortlist_listings=shortlist_listings,
        profile=profile,
        top_matches=top_matches,
        is_premium_buyer=is_premium,
        active_sub=active_sub,
        current_plan_label=current_plan_label,
        profile_complete=profile_complete,
        qualification=qualification,
        saved_searches=saved_searches,
        data_room_introductions=data_room_introductions,
    )



@app.route("/valuers/<int:valuer_id>")
def valuer_detail(valuer_id):
    """
    Public valuer profile detail page.
    Shows more information; contact details are still gated.
    """
    profile = ValuerProfile.query.get_or_404(valuer_id)
    owner = profile.user

    # Premium flag for future highlighting
    is_premium_valuer = False
    SubscriptionModel = globals().get("Subscription")
    if SubscriptionModel is not None:
        sub = (
            SubscriptionModel.query
            .filter_by(user_id=owner.id, role="valuer", tier="premium", is_active=True)
            .first()
        )
        is_premium_valuer = sub is not None

    # Contact visibility (same rule as directory)
    can_view_contact = False
    if current_user.is_authenticated:
        if current_user.role in ("seller", "admin"):
            can_view_contact = True
        elif current_user.role == "buyer" and has_active_subscription(current_user, "buyer", "premium"):
            can_view_contact = True

    # Pre-split regions for chips
    region_list = []
    if profile.regions:
        region_list = [r.strip() for r in profile.regions.split(",") if r.strip()]

    return render_template(
        "valuer_detail.html",
        profile=profile,
        owner=owner,
        is_premium_valuer=is_premium_valuer,
        can_view_contact=can_view_contact,
        region_list=region_list,
    )

@app.route("/valuer/requests/<int:req_id>/accept", methods=["POST"])
@login_required
@role_required("valuer")
def valuer_accept_request(req_id):
    vr = ValuationRequest.query.get_or_404(req_id)

    if vr.valuer_id != current_user.id:
        flash("You cannot update this valuation request.", "error")
        return redirect(url_for("valuer_requests"))

    vr.status = "accepted"
    vr.updated_at = datetime.utcnow()
    db.session.commit()

    listing = vr.listing
    publish_notification(
        vr.seller,
        event_type="valuation_status",
        title="Valuation request accepted",
        body=f"Your valuer accepted the request for {listing.listing_code or 'your listing'}.",
        target_url=url_for("seller_dashboard"),
        dedupe_key=f"valuation:{vr.id}:accepted",
    )

    flash("Request accepted and seller notified.", "success")
    return redirect(url_for("valuer_requests"))

@app.route("/valuer/requests/<int:req_id>/decline", methods=["POST"])
@login_required
@role_required("valuer")
def valuer_decline_request(req_id):
    vr = ValuationRequest.query.get_or_404(req_id)

    if vr.valuer_id != current_user.id:
        flash("You cannot update this valuation request.", "error")
        return redirect(url_for("valuer_requests"))

    vr.status = "declined"
    vr.updated_at = datetime.utcnow()
    db.session.commit()

    listing = vr.listing
    publish_notification(
        vr.seller,
        event_type="valuation_status",
        title="Valuation request declined",
        body=f"The valuer declined the request for {listing.listing_code or 'your listing'}.",
        target_url=url_for("seller_dashboard"),
        dedupe_key=f"valuation:{vr.id}:declined",
    )

    flash("Request declined and seller notified.", "success")
    return redirect(url_for("valuer_requests"))


@app.route("/valuer/requests/<int:req_id>/complete", methods=["POST"])
@login_required
@role_required("valuer")
def valuer_complete_request(req_id):
    vr = ValuationRequest.query.get_or_404(req_id)

    if vr.valuer_id != current_user.id:
        flash("You cannot update this valuation request.", "error")
        return redirect(url_for("valuer_requests"))

    vr.status = "completed"
    vr.updated_at = datetime.utcnow()
    db.session.commit()

    listing = vr.listing
    publish_notification(
        vr.seller,
        event_type="valuation_status",
        title="Valuation completed",
        body=f"The valuation for {listing.listing_code or 'your listing'} was marked complete.",
        target_url=url_for("seller_dashboard"),
        dedupe_key=f"valuation:{vr.id}:completed",
    )

    flash("Request marked as complete and seller notified.", "success")
    return redirect(url_for("valuer_requests"))



# -------------------------------------------------------------------
# Valuer Public Directory + Detail Views
# -------------------------------------------------------------------

def buyer_can_view_valuer_contact() -> bool:
    """
    Buyers only get full contact access if premium.
    Sellers and admins always get access.
    Guests never do.
    """
    if not current_user.is_authenticated:
        return False

    if current_user.role in ("seller", "admin"):
        return True

    if current_user.role == "buyer":
        return has_active_subscription(current_user, "buyer", "premium")

    return False

@app.route("/buyer/shortlist")
@login_required
@role_required("buyer")
def buyer_shortlist():
    ids = get_shortlist_ids()
    listings = []
    if ids:
        listings = (
            Listing.query.filter(Listing.id.in_(ids), Listing.status == "live")
            .order_by(Listing.created_at.desc())
            .all()
        )
    return render_template("buyer/shortlist.html", listings=listings)

@app.route("/listings/<int:listing_id>/toggle-shortlist", methods=["POST"])
@login_required
@role_required("buyer")
def toggle_shortlist(listing_id):
    """
    Add/remove a listing from the buyer's persistent shortlist.
    Expects a POST from listing_detail or listings views.
    """
    listing = Listing.query.get_or_404(listing_id)
    item = ShortlistItem.query.filter_by(
        buyer_id=current_user.id, listing_id=listing.id
    ).first()

    if item:
        db.session.delete(item)
        flash("Listing removed from your shortlist.", "info")
    else:
        db.session.add(
            ShortlistItem(buyer_id=current_user.id, listing_id=listing.id)
        )
        flash("Listing added to your shortlist.", "success")
    db.session.commit()

    # Go back to where the user came from, or fallback to shortlist page
    requested_next = request.form.get("next") or request.referrer
    next_url = requested_next if is_safe_redirect_target(requested_next) else url_for("buyer_shortlist")
    return redirect(next_url)


@app.route("/buyer/saved-searches")
@login_required
@role_required("buyer")
def buyer_saved_searches():
    searches = (
        SavedSearch.query.filter_by(buyer_id=current_user.id)
        .order_by(SavedSearch.created_at.desc())
        .all()
    )
    return render_template("buyer/saved_searches.html", searches=searches)


@app.route("/buyer/saved-searches", methods=["POST"])
@login_required
@role_required("buyer")
def save_buyer_search():
    search_term = (request.form.get("search_q") or "").strip()[:120] or None
    region = (request.form.get("region") or "").strip()[:100] or None
    care_type = (request.form.get("care_type") or "").strip()[:100] or None
    supplied_name = (request.form.get("name") or "").strip()[:120]
    parts = [part for part in (search_term, region, care_type) if part]
    name = supplied_name or (" · ".join(parts) if parts else "All live opportunities")

    existing = SavedSearch.query.filter_by(
        buyer_id=current_user.id, name=name
    ).first()
    if existing:
        flash("You already have a saved search with that name.", "info")
    else:
        db.session.add(
            SavedSearch(
                buyer_id=current_user.id,
                name=name,
                search_term=search_term,
                region=region,
                care_type=care_type,
                email_alerts=bool(request.form.get("email_alerts")),
            )
        )
        db.session.commit()
        flash("Search saved. You can manage it from your buyer dashboard.", "success")

    return redirect(url_for("buyer_saved_searches"))


@app.route("/buyer/saved-searches/<int:search_id>/alerts", methods=["POST"])
@login_required
@role_required("buyer")
def toggle_saved_search_alerts(search_id):
    saved_search = SavedSearch.query.filter_by(
        id=search_id, buyer_id=current_user.id
    ).first_or_404()
    saved_search.email_alerts = not saved_search.email_alerts
    db.session.commit()
    state = "on" if saved_search.email_alerts else "off"
    flash(f"Email alerts turned {state} for {saved_search.name}.", "success")
    return redirect(url_for("buyer_saved_searches"))


@app.route("/buyer/saved-searches/<int:search_id>/delete", methods=["POST"])
@login_required
@role_required("buyer")
def delete_saved_search(search_id):
    saved_search = SavedSearch.query.filter_by(
        id=search_id, buyer_id=current_user.id
    ).first_or_404()
    db.session.delete(saved_search)
    db.session.commit()
    flash("Saved search deleted.", "info")
    return redirect(url_for("buyer_saved_searches"))


@app.route("/valuers/<int:profile_id>")
def valuer_public_profile(profile_id):
    """
    Public view of a single valuer profile.
    Used from the Valuer Framework directory.
    """
    profile = ValuerProfile.query.get_or_404(profile_id)
    user = profile.user

    # Check if this valuer is on a premium tier
    is_premium_valuer = has_active_subscription(user, "valuer", "premium")

    return render_template(
        "valuer_detail_public.html",
        profile=profile,
        is_premium_valuer=is_premium_valuer,
    )


@app.route("/my/dashboard")
@login_required
def my_dashboard():
    """
    Role-aware dashboard router:
    - buyers -> buyer_dashboard
    - sellers -> seller_dashboard
    - valuers -> valuer_dashboard
    - admins -> admin_dashboard
    """
    role = getattr(current_user, "role", None)

    if role == "buyer":
        return redirect(url_for("buyer_dashboard"))
    elif role == "seller":
        return redirect(url_for("seller_dashboard"))
    elif role == "valuer":
        return redirect(url_for("valuer_dashboard"))
    elif role == "admin":
        return redirect(url_for("admin_dashboard"))

    # Fallback: treat as buyer if somehow unknown
    return redirect(url_for("buyer_dashboard"))



# -------------------------------------------------------------------
# Valuer routes
# -------------------------------------------------------------------

@app.route("/valuer/dashboard")
@login_required
@role_required("valuer")
def valuer_dashboard():
    profile = ValuerProfile.query.filter_by(user_id=current_user.id).first()
    # In future: show valuation requests, stats, etc.
    profile_complete = bool(
        profile
        and profile.company_name
        and profile.regions
        and profile.accreditation
    )

    # Get active subscription for valuer role
    active_sub = get_active_subscription_for_role(current_user, "valuer")

    current_plan_label = None
    if active_sub:
        current_plan_label = f"{active_sub.role.capitalize()} {active_sub.tier.capitalize()}"

    return render_template(
        "valuer/dashboard.html",
        profile=profile,
        profile_complete=profile_complete,
        current_plan_label=current_plan_label,
        active_sub=active_sub,
    )





# -------------------------------------------------------------------
# Valuer routes
# -------------------------------------------------------------------

@app.route("/valuer/profile", methods=["GET", "POST"])
@login_required
def valuer_profile():
    if current_user.role != "valuer":
        flash("Valuer access only.")
        return redirect(url_for("index"))

    profile = ValuerProfile.query.filter_by(user_id=current_user.id).first()

    if request.method == "POST":
        company_name = (request.form.get("company_name") or "").strip() or None
        accreditation = (request.form.get("accreditation") or "").strip() or None
        regions = (request.form.get("regions") or "").strip() or None
        pricing_notes = (request.form.get("pricing_notes") or "").strip() or None
        bio = (request.form.get("bio") or "").strip() or None

        if profile is None:
            profile = ValuerProfile(
                user_id=current_user.id,
                company_name=company_name,
                accreditation=accreditation,
                regions=regions,
                pricing_notes=pricing_notes,
                bio=bio,
            )
            db.session.add(profile)
        else:
            profile.company_name = company_name
            profile.accreditation = accreditation
            profile.regions = regions
            profile.pricing_notes = pricing_notes
            profile.bio = bio

        db.session.commit()
        flash("Valuer profile saved.")
        return redirect(url_for("valuer_profile"))

    return render_template("valuer/profile.html", profile=profile)

# -------------------------------------------------------------------
# Admin routes
# -------------------------------------------------------------------

@app.route("/admin")
@login_required
@role_required("admin")
def admin_dashboard():
    # Listing stats
    listing_counts = {
        "live": Listing.query.filter_by(status="live").count(),
        "draft": Listing.query.filter_by(status="draft").count(),
        "under_offer": Listing.query.filter_by(status="under_offer").count(),
        "sold": Listing.query.filter_by(status="sold").count(),
    }

    # User counts by role
    total_users = User.query.count()
    buyers_total = User.query.filter_by(role="buyer").count()
    sellers_total = User.query.filter_by(role="seller").count()
    valuers_total = User.query.filter_by(role="valuer").count()
    admins_total = User.query.filter_by(role="admin").count()

    # Enquiries
    enquiry_count = Enquiry.query.count()

    # Subscription breakdown (basic / premium) per role
    subscription_breakdown = {
        "buyer": {"basic": 0, "premium": 0},
        "seller": {"basic": 0, "premium": 0},
        "valuer": {"basic": 0, "premium": 0},
    }

    if "Subscription" in globals():
        active_subs = Subscription.query.filter_by(is_active=True).all()
        for s in active_subs:
            role_key = s.role
            tier_key = s.tier
            if role_key in subscription_breakdown and tier_key in subscription_breakdown[role_key]:
                subscription_breakdown[role_key][tier_key] += 1

    # Valuation requests
    valuation_total = ValuationRequest.query.count()
    valuation_open = ValuationRequest.query.filter(
        ValuationRequest.status.in_(["pending", "accepted"])
    ).count()

    # Deals / pipeline
    deals_total = Deal.query.count()
    deals_completed = Deal.query.filter_by(status="completed").count()
    deals_in_progress = Deal.query.filter(Deal.status != "completed").count()

    # Recent activity
    recent_listings = (
        Listing.query.order_by(Listing.created_at.desc()).limit(5).all()
    )
    recent_valuations = (
        ValuationRequest.query.order_by(ValuationRequest.created_at.desc()).limit(5).all()
    )
    recent_deals = (
        Deal.query
        .join(Introduction, Deal.introduction_id == Introduction.id)
        .join(Listing, Introduction.listing_id == Listing.id)
        .order_by(Deal.id.desc())
        .limit(5)
        .all()
    )

    return render_template(
        "admin/dashboard.html",
        listing_counts=listing_counts,
        total_users=total_users,
        buyers_total=buyers_total,
        sellers_total=sellers_total,
        valuers_total=valuers_total,
        admins_total=admins_total,
        enquiry_count=enquiry_count,
        subscription_breakdown=subscription_breakdown,
        valuation_total=valuation_total,
        valuation_open=valuation_open,
        deals_total=deals_total,
        deals_completed=deals_completed,
        deals_in_progress=deals_in_progress,
        recent_listings=recent_listings,
        recent_valuations=recent_valuations,
        recent_deals=recent_deals,
    )





@app.route("/admin/listings")
@login_required
@role_required("admin")
def admin_listings():
    listings = Listing.query.order_by(Listing.created_at.desc()).all()

    # Optional: admin map data – show full info
    map_data = []
    for l in listings:
        lat, lng = REGION_COORDS.get(l.region or "", DEFAULT_COORD)
        map_data.append(
            {
                "id": l.id,
                "title": l.title or "Untitled listing",
                "lat": lat,
                "lng": lng,
                "region": l.region or "",
                "care_type": l.care_type or "",
                "beds": l.beds or "",
                "guide_price": l.guide_price_band or "On request",
                "code": l.listing_code or "",
            }
        )

    return render_template(
        "admin/listings.html",
        listings=listings,
        map_data=map_data,
    )


@app.route("/admin/listings/<int:listing_id>/approve", methods=["POST"])
@login_required
@role_required("admin")
def admin_approve_listing(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    previous_status = listing.status
    listing.status = "live"
    if not listing.listing_code:
        listing.listing_code = generate_listing_code()
    db.session.commit()
    record_audit_event(
        "admin.listing_approved", "Listing approved and published",
        subject_user_id=listing.seller_id, resource_type="listing",
        resource_id=listing.id, details={"previous_status": previous_status},
    )
    if previous_status != "live":
        publish_listing_match_notifications(listing)
    flash("Listing approved and set live.")
    return redirect(url_for("admin_listings"))


@app.route("/admin/listings/<int:listing_id>/archive", methods=["POST"])
@login_required
@role_required("admin")
def admin_archive_listing(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    listing.status = "archived"
    db.session.commit()
    record_audit_event(
        "admin.listing_archived", "Listing archived",
        subject_user_id=listing.seller_id, resource_type="listing",
        resource_id=listing.id,
    )
    flash("Listing archived.")
    return redirect(url_for("admin_listings"))


@app.route("/admin/test-email")
@login_required
@role_required("admin")
def test_email():
    ok = send_email(
        to_addresses="YOUR_REAL_ADDRESS@gmail.com",
        subject="Ownerlane SMTP test",
        html_body="""
            <h2>SMTP is live ✅</h2>
            <p>This is a test email from Ownerlane.</p>
        """,
    )
    if ok:
        return "Test email sent. Check your inbox."
    else:
        return "Failed to send test email – check logs and SMTP settings.", 500


@app.route("/admin/leads")
@login_required
@role_required("admin")
def admin_leads():
    leads = Lead.query.order_by(desc(Lead.created_at)).limit(200).all()
    return render_template("admin_leads.html", leads=leads)

@app.route("/admin/introduction_requests")
@login_required
@role_required("admin")
def admin_introduction_requests():
    pending = (
        Introduction.query
        .filter(Introduction.status == "pending_seller_request")
        .order_by(Introduction.created_at.desc())
        .all()
    )
    return render_template("admin/introduction_requests.html", pending=pending)

@app.route("/admin/introduction_requests/<int:intro_id>/approve", methods=["POST"])
@login_required
@role_required("admin")
def admin_approve_intro_request(intro_id):
    intro = Introduction.query.get_or_404(intro_id)
    intro.status = "initiated"
    intro.updated_at = datetime.utcnow()
    db.session.commit()
    record_audit_event(
        "admin.introduction_approved", "Introduction request approved",
        subject_user_id=intro.seller_id, resource_type="introduction",
        resource_id=intro.id, details={"buyer_id": intro.buyer_id},
    )

    for recipient in (intro.buyer, intro.seller):
        publish_notification(
            recipient,
            event_type="introduction_status",
            title="Introduction approved",
            body=f"The introduction for {intro.listing.listing_code or 'the listing'} is now initiated.",
            target_url=url_for("my_dashboard"),
            dedupe_key=f"introduction:{intro.id}:initiated",
        )

    flash("Introduction approved and marked as initiated.", "success")
    return redirect(url_for("admin_introduction_requests"))


@app.route("/admin/introduction_requests/<int:intro_id>/decline", methods=["POST"])
@login_required
@role_required("admin")
def admin_decline_intro_request(intro_id):
    intro = Introduction.query.get_or_404(intro_id)
    intro.status = "declined"
    db.session.commit()
    record_audit_event(
        "admin.introduction_declined", "Introduction request declined",
        subject_user_id=intro.seller_id, resource_type="introduction",
        resource_id=intro.id, details={"buyer_id": intro.buyer_id},
    )

    for recipient in (intro.buyer, intro.seller):
        publish_notification(
            recipient,
            event_type="introduction_status",
            title="Introduction request declined",
            body=f"The introduction request for {intro.listing.listing_code or 'the listing'} was declined.",
            target_url=url_for("my_dashboard"),
            dedupe_key=f"introduction:{intro.id}:declined",
        )

    flash("Introduction request declined.", "success")
    return redirect(url_for("admin_introduction_requests"))

@app.route("/admin/buyers")
@login_required
@role_required("admin")
def admin_buyers():
    """
    Admin view: all buyers with profile + subscription info.
    """
    buyers = (
        User.query
        .filter_by(role="buyer")
        .order_by(User.created_at.desc())
        .all()
    )

    # Work out which buyers have an active premium subscription
    premium_ids = set()
    basic_ids = set()

    if "Subscription" in globals():
        subs = (
            Subscription.query
            .filter_by(role="buyer", is_active=True)
            .all()
        )
        for s in subs:
            if s.tier == "premium":
                premium_ids.add(s.user_id)
            else:
                basic_ids.add(s.user_id)

    return render_template(
        "admin/buyers.html",
        buyers=buyers,
        profile_map={p.user_id: p for p in BuyerProfile.query.all()},
        qualification_map={q.user_id: q for q in BuyerQualification.query.all()},
        premium_ids=premium_ids,
        basic_ids=basic_ids,
    )


@app.route("/admin/buyer-verifications")
@login_required
@role_required("admin")
def admin_buyer_verifications():
    qualifications = BuyerQualification.query.order_by(
        BuyerQualification.submitted_at.desc()
    ).all()
    return render_template(
        "admin/buyer_verifications.html", qualifications=qualifications
    )


@app.route("/admin/buyer-verifications/<int:buyer_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_buyer_qualification(buyer_id):
    buyer = User.query.filter_by(id=buyer_id, role="buyer").first_or_404()
    qualification = BuyerQualification.query.filter_by(user_id=buyer.id).first_or_404()
    if request.method == "POST":
        allowed = {"not_submitted", "pending", "verified", "rejected"}
        identity_status = (request.form.get("identity_status") or "").strip()
        business_status = (request.form.get("business_status") or "").strip()
        funds_status = (request.form.get("funds_status") or "").strip()
        if {identity_status, business_status, funds_status} - allowed:
            flash("Choose valid review decisions.", "error")
            return redirect(request.url)
        if funds_status == "verified" and not qualification.funds_filename:
            flash("Proof of funds cannot be verified without private evidence.", "error")
            return redirect(request.url)
        previous = qualification.overall_status
        qualification.identity_status = identity_status
        qualification.business_status = business_status
        qualification.funds_status = funds_status
        qualification.review_notes = (
            (request.form.get("review_notes") or "").strip()[:3000] or None
        )
        qualification.reviewed_at = utcnow()
        qualification.reviewed_by_id = current_user.id
        qualification.updated_at = utcnow()
        db.session.commit()
        record_audit_event(
            "admin.buyer_qualification_reviewed", "Buyer qualification reviewed",
            subject_user_id=buyer.id, resource_type="buyer_qualification",
            resource_id=qualification.id,
            details={"previous_status": previous, "status": qualification.overall_status},
        )
        publish_notification(
            buyer, event_type="buyer_qualification",
            title="Buyer verification updated",
            body=f"Your qualification review is now {qualification.overall_status.replace('_', ' ')}.",
            target_url=url_for("buyer_qualification"),
            dedupe_key=f"buyer-qualification-review:{qualification.id}:{int(qualification.reviewed_at.timestamp())}",
        )
        flash("Buyer qualification review saved.", "success")
        return redirect(url_for("admin_buyer_qualification", buyer_id=buyer.id))
    profile = BuyerProfile.query.filter_by(user_id=buyer.id).first()
    return render_template(
        "admin/buyer_qualification.html", buyer=buyer,
        qualification=qualification, profile=profile,
    )


@app.route("/admin/buyer-verifications/<int:buyer_id>/evidence")
@login_required
@role_required("admin")
def admin_buyer_qualification_evidence(buyer_id):
    qualification = BuyerQualification.query.filter_by(user_id=buyer_id).first_or_404()
    return _send_buyer_evidence(qualification)


@app.route("/admin/sellers")
@login_required
@role_required("admin")
def admin_sellers():
    """
    Admin view: all sellers with business profile + subscription info.
    """
    sellers = (
        User.query
        .filter_by(role="seller")
        .order_by(User.created_at.desc())
        .all()
    )

    premium_ids = set()
    basic_ids = set()

    if "Subscription" in globals():
        subs = (
            Subscription.query
            .filter_by(role="seller", is_active=True)
            .all()
        )
        for s in subs:
            if s.tier == "premium":
                premium_ids.add(s.user_id)
            else:
                basic_ids.add(s.user_id)

    return render_template(
        "admin/sellers.html",
        sellers=sellers,
        profile_map={p.user_id: p for p in SellerProfile.query.all()},
        premium_ids=premium_ids,
        basic_ids=basic_ids,
    )

@app.route("/admin/valuers")
@login_required
@role_required("admin")
def admin_valuers():
    """
    Admin view: all valuers + whether they are premium.
    """
    valuers = (
        User.query
        .filter_by(role="valuer")
        .order_by(User.created_at.desc())
        .all()
    )

    premium_ids = set()
    basic_ids = set()

    if "Subscription" in globals():
        subs = (
            Subscription.query
            .filter_by(role="valuer", is_active=True)
            .all()
        )
        for s in subs:
            if s.tier == "premium":
                premium_ids.add(s.user_id)
            else:
                basic_ids.add(s.user_id)

    return render_template(
        "admin/valuers.html",
        valuers=valuers,
        profile_map={p.user_id: p for p in ValuerProfile.query.all()},
        premium_ids=premium_ids,
        basic_ids=basic_ids,
    )


@app.route("/admin/valuation-requests")
@login_required
@role_required("admin")
def admin_valuation_requests():
    """
    Admin view: all valuation requests across the platform.
    """
    requests_q = (
        ValuationRequest.query
        .order_by(ValuationRequest.created_at.desc())
        .all()
    )
    return render_template(
        "admin/valuation_requests.html",
        requests=requests_q,
    )




# -------- Introductions from enquiries --------


@app.route("/admin/enquiries/<int:enquiry_id>/introduce", methods=["POST"])
@login_required
@role_required("admin")
def admin_create_introduction_from_enquiry(enquiry_id):
    enquiry = Enquiry.query.get_or_404(enquiry_id)
    listing = enquiry.listing
    buyer = enquiry.buyer
    seller = listing.seller

    existing = Introduction.query.filter_by(
        buyer_id=buyer.id,
        seller_id=seller.id,
        listing_id=listing.id,
    ).first()
    if existing:
        flash("An introduction already exists for this buyer and listing.")
        return redirect(url_for("admin_leads"))

    intro = Introduction(
        buyer_id=buyer.id,
        seller_id=seller.id,
        listing_id=listing.id,
        status="initiated",
    )
    db.session.add(intro)
    db.session.commit()
    record_audit_event(
        "admin.introduction_created", "Introduction created from enquiry",
        subject_user_id=seller.id, resource_type="introduction", resource_id=intro.id,
        details={"buyer_id": buyer.id, "enquiry_id": enquiry.id},
    )
    for recipient in (intro.buyer, intro.seller):
        publish_notification(
            recipient,
            event_type="introduction_status",
            title="Introduction created",
            body=f"An introduction was created for {intro.listing.listing_code or 'a listing'}.",
            target_url=url_for("my_dashboard"),
            dedupe_key=f"introduction:{intro.id}:initiated",
        )
    flash("Introduction created from enquiry.")
    return redirect(url_for("admin_introductions"))

@app.route("/admin/introductions")
@login_required
@role_required("admin")
def admin_introductions():
    """
    Kanban-style board of all introductions, grouped by status.
    """
    introductions = (
        Introduction.query
        .join(Listing, Introduction.listing_id == Listing.id)
        .join(User, Introduction.buyer_id == User.id)
        .order_by(Introduction.created_at.desc())
        .all()
    )

    # Group into columns
    status_columns = {key: [] for key, _ in INTRO_STATUSES}
    for intro in introductions:
        key = intro.status or "initiated"
        if key not in status_columns:
            key = "initiated"
        status_columns[key].append(intro)

    return render_template(
        "admin/introductions.html",
        status_columns=status_columns,
        statuses=INTRO_STATUSES,
        buyer_profile_map={p.user_id: p for p in BuyerProfile.query.all()},
        deal_map={d.introduction_id: d for d in Deal.query.all()},
    )






@app.route("/admin/introductions/<int:intro_id>")
@login_required
@role_required("admin")
def admin_introduction_detail(intro_id):
    """
    Detailed view of a single introduction: buyer, seller, listing, pipeline status,
    and associated deal if present.
    """
    intro = Introduction.query.get_or_404(intro_id)

    # Existing deal (if any)
    deal = Deal.query.filter_by(introduction_id=intro.id).first()
    buyer_profile = BuyerProfile.query.filter_by(user_id=intro.buyer_id).first()
    seller_profile = SellerProfile.query.filter_by(user_id=intro.seller_id).first()
    buyer_qualification = BuyerQualification.query.filter_by(
        user_id=intro.buyer_id
    ).first()

    return render_template(
        "admin/introduction_detail.html",
        introduction=intro,
        deal=deal,
        buyer_profile=buyer_profile,
        seller_profile=seller_profile,
        buyer_qualification=buyer_qualification,
        statuses=INTRO_STATUSES,
    )


@app.route("/admin/introductions/<int:intro_id>/status", methods=["POST"])
@login_required
@role_required("admin")
def admin_update_introduction_status(intro_id):
    """
    Move an introduction along the pipeline (initiated → nda_signed → …),
    log a history row, and trigger email notifications.
    """
    intro = Introduction.query.get_or_404(intro_id)
    new_status = (request.form.get("status") or "").strip()

    valid_keys = {k for k, _ in INTRO_STATUSES}
    if new_status not in valid_keys:
        flash("Invalid status.", "error")
        return redirect(request.referrer or url_for("admin_introductions"))

    old_status = intro.status or "initiated"
    if new_status == old_status:
        # No actual change; nothing to log
        flash("Status unchanged.", "info")
        return redirect(request.referrer or url_for("admin_introductions"))

    intro.status = new_status
    intro.updated_at = datetime.utcnow()

    # Mirror onto deal if present
    deal = Deal.query.filter_by(introduction_id=intro.id).first()
    if deal:
        if new_status == "completed":
            deal.status = "completed"
        elif new_status == "failed":
            deal.status = "aborted"

    # History row
    history = IntroductionStatusHistory(
        introduction_id=intro.id,
        old_status=old_status,
        new_status=new_status,
        changed_by_user_id=current_user.id if current_user.is_authenticated else None,
    )
    db.session.add(history)

    db.session.commit()
    record_audit_event(
        "admin.introduction_status_changed", "Introduction status changed",
        subject_user_id=intro.seller_id, resource_type="introduction",
        resource_id=intro.id,
        details={"old_status": old_status, "new_status": new_status},
    )

    new_label = _label_for_intro_status(new_status)
    for recipient in (intro.buyer, intro.seller):
        publish_notification(
            recipient,
            event_type="introduction_status",
            title=f"Introduction moved to {new_label}",
            body=f"The introduction for {intro.listing.listing_code or 'the listing'} is now {new_label}.",
            target_url=url_for("my_dashboard"),
            dedupe_key=f"introduction:{intro.id}:{new_status}",
        )

    # Email notifications
    try:
        notify_introduction_status_change(intro, old_status, new_status)
    except Exception:
        current_app.logger.exception("Failed to send intro status notifications")

    flash("Introduction status updated.", "success")
    return redirect(request.referrer or url_for("admin_introductions"))




@app.route("/admin/introductions/<int:intro_id>/deal", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_introduction_deal(intro_id):
    """
    Attach or edit a deal for a given introduction.
    """
    intro = Introduction.query.get_or_404(intro_id)

    deal = Deal.query.filter_by(introduction_id=intro.id).first()
    creating = deal is None
    if creating:
        deal = Deal(introduction_id=intro.id)

    if request.method == "POST":
        agreed_price = (request.form.get("agreed_price") or "").strip() or None
        commission_percent_raw = (request.form.get("broker_commission_percent") or "").strip()
        completion_date_raw = (request.form.get("completion_date") or "").strip()

        # Basic parse of commission %
        broker_commission_percent = None
        if commission_percent_raw:
            try:
                broker_commission_percent = float(commission_percent_raw)
            except ValueError:
                broker_commission_percent = None

        # Parse completion date (optional)
        completion_date = None
        if completion_date_raw:
            try:
                completion_date = datetime.strptime(completion_date_raw, "%Y-%m-%d")
            except ValueError:
                completion_date = None

        # Attempt to auto-calc commission_amount if parseable
        broker_commission_amount = deal.broker_commission_amount
        if agreed_price and broker_commission_percent is not None:
            try:
                # Strip £ and commas, convert to float pounds → pence int
                price_clean = agreed_price.replace("£", "").replace(",", "").strip()
                price_float = float(price_clean)
                commission_pounds = price_float * (broker_commission_percent / 100.0)
                broker_commission_amount = int(round(commission_pounds * 100))
            except Exception:
                # If parsing fails, leave as existing / None
                pass

        deal.agreed_price = agreed_price
        if broker_commission_percent is not None:
            deal.broker_commission_percent = broker_commission_percent
        if completion_date is not None:
            deal.completion_date = completion_date
        if broker_commission_amount is not None:
            deal.broker_commission_amount = broker_commission_amount

        # If we have a completion date, assume completed status
        if completion_date:
            deal.status = "completed"

        if creating:
            db.session.add(deal)

        db.session.commit()
        flash("Deal details saved.", "success")
        return redirect(url_for("admin_introduction_detail", intro_id=intro.id))

    # GET – render form
    return render_template(
        "admin/deal_edit.html",
        introduction=intro,
        deal=deal,
    )



# -------- Deals & commission --------


@app.route("/admin/deals")
@login_required
@role_required("admin")
def admin_deals():
    deals = (
        Deal.query
        .join(Introduction, Deal.introduction_id == Introduction.id)
        .join(Listing, Introduction.listing_id == Listing.id)
        .order_by(Deal.id.desc())
        .all()
    )
    return render_template("admin/deals.html", deals=deals)

@app.route("/admin/matches")
@login_required
@role_required("admin")
def admin_matches():
    """
    Admin 'control room' – see buyers and their top matches.
    Lets you quickly see who to nudge for which listings.
    """
    buyers = (
        User.query
        .filter_by(role="buyer")
        .order_by(User.created_at.desc())
        .all()
    )

    rows = []
    for buyer in buyers:
        profile = BuyerProfile.query.filter_by(user_id=buyer.id).first()
        is_premium = has_active_subscription(buyer, "buyer", "premium")
        matches = compute_matches_for_buyer(buyer, limit=5)  # list of (listing, score, reasons)

        rows.append({
            "buyer": buyer,
            "profile": profile,
            "is_premium": is_premium,
            "matches": matches,
        })

    return render_template("admin/matches.html", rows=rows)


@app.route("/admin/deals/<int:deal_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_deal_detail(deal_id):
    deal = Deal.query.get_or_404(deal_id)
    intro = deal.introduction
    listing = intro.listing
    buyer = intro.buyer
    seller = intro.seller

    if request.method == "POST":
        # Editable fields
        agreed_price = (request.form.get("agreed_price") or "").strip() or None
        commission_percent_str = (request.form.get("commission_percent") or "").strip()
        status = (request.form.get("status") or "").strip() or "in_progress"
        completion_date_str = (request.form.get("completion_date") or "").strip()

        # Update agreed_price
        deal.agreed_price = agreed_price

        # Commission percent
        try:
            deal.broker_commission_percent = float(commission_percent_str)
        except ValueError:
            flash("Commission percent must be a number.", "error")

        # Completion date
        if completion_date_str:
            try:
                deal.completion_date = datetime.strptime(
                    completion_date_str, "%Y-%m-%d"
                )
            except ValueError:
                flash("Completion date must be in YYYY-MM-DD format.", "error")
        else:
            deal.completion_date = None

        # Status
        allowed_statuses = {"in_progress", "completed", "aborted"}
        if status not in allowed_statuses:
            flash("Invalid deal status selected.", "error")
        else:
            deal.status = status

        # Recalculate commission amount if we have a price
        pence = parse_amount_to_pence(deal.agreed_price)
        if pence is not None and deal.broker_commission_percent is not None:
            deal.broker_commission_amount = int(
                pence * (deal.broker_commission_percent / 100.0)
            )

        db.session.commit()
        record_audit_event(
            "admin.deal_updated", "Deal details updated",
            subject_user_id=seller.id, resource_type="deal", resource_id=deal.id,
            details={"status": deal.status},
        )
        flash("Deal updated.", "success")
        return redirect(url_for("admin_deal_detail", deal_id=deal.id))

    # GET → render template
    return render_template(
        "admin/deal_detail.html",
        deal=deal,
        intro=deal.introduction,
        listing=listing,
        buyer=buyer,
        seller=seller,
    )

@app.route("/admin/deals/<int:deal_id>/export")
@login_required
@role_required("admin")
def admin_deal_export(deal_id):
    deal = Deal.query.get_or_404(deal_id)
    intro = deal.introduction
    listing = intro.listing
    buyer = intro.buyer
    seller = intro.seller

    html = render_template(
        "admin/deal_sheet.html",
        deal=deal,
        intro=intro,
        listing=listing,
        buyer=buyer,
        seller=seller,
    )

    response = make_response(html)
    filename = f"deal_{deal.id}_{listing.listing_code or 'ref'}.html"
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@app.route("/admin/subscriptions")
@login_required
@role_required("admin")
def admin_subscriptions():
    users = User.query.order_by(User.id.asc()).all()

    # Gather user subscriptions (latest first per user)
    subs = (
        Subscription.query
        .order_by(
            Subscription.user_id.asc(),
            Subscription.started_at.desc()
        )
        .all()
    )

    # Map: user_id -> currently active subscription
    sub_map = {}
    for s in subs:
        if s.is_active:
            sub_map[s.user_id] = s

    return render_template(
        "admin/subscriptions.html",
        users=users,
        sub_map=sub_map
    )

@app.route("/admin/enquiries")
@login_required
@role_required("admin")
def admin_enquiries():
    """
    Show all enquiries (new/read/archived) for admin oversight.
    """
    enquiries = (
        Enquiry.query
        .order_by(Enquiry.created_at.desc())
        .all()
    )

    return render_template(
        "admin/enquiries.html",
        enquiries=enquiries
    )


@app.route("/admin/subscriptions/grant", methods=["POST"])
@login_required
@role_required("admin")
def admin_grant_subscription():
    """
    Grant or refresh a subscription for a given user/role/tier.
    Used from the admin/subscriptions screen.
    """
    user_id = request.form.get("user_id")
    role = (request.form.get("role") or "").strip().lower()
    tier = (request.form.get("tier") or "").strip().lower() or "premium"

    if not user_id or not role:
        flash("Missing user or role.", "error")
        return redirect(url_for("admin_subscriptions"))

    try:
        user_id_int = int(user_id)
    except ValueError:
        flash("Invalid user id.", "error")
        return redirect(url_for("admin_subscriptions"))

    user = User.query.get(user_id_int)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("admin_subscriptions"))

    # Basic sanity: role must match user's role
    if user.role != role:
        flash("User role mismatch for that subscription type.", "error")
        return redirect(url_for("admin_subscriptions"))

    upsert_subscription(user.id, role=role, tier=tier, months=1)
    record_audit_event(
        "admin.subscription_granted", "Subscription granted or refreshed",
        subject_user_id=user.id, resource_type="user", resource_id=user.id,
        details={"role": role, "tier": tier},
    )
    flash(f"{tier.capitalize()} subscription granted for {user.email} ({role}).", "success")
    return redirect(url_for("admin_subscriptions"))


@app.route("/admin/subscriptions/cancel", methods=["POST"])
@login_required
@role_required("admin")
def admin_cancel_subscription():
    """
    Soft-cancel a subscription (mark inactive).
    """
    sub_id = request.form.get("sub_id")
    if not sub_id:
        flash("Missing subscription id.", "error")
        return redirect(url_for("admin_subscriptions"))

    try:
        sub_id_int = int(sub_id)
    except ValueError:
        flash("Invalid subscription id.", "error")
        return redirect(url_for("admin_subscriptions"))

    sub = Subscription.query.get(sub_id_int)
    if not sub:
        flash("Subscription not found.", "error")
        return redirect(url_for("admin_subscriptions"))

    sub.is_active = False
    db.session.commit()
    record_audit_event(
        "admin.subscription_cancelled", "Subscription cancelled",
        subject_user_id=sub.user_id, resource_type="subscription", resource_id=sub.id,
        details={"role": sub.role, "tier": sub.tier},
    )
    flash("Subscription cancelled.", "success")
    return redirect(url_for("admin_subscriptions"))

@app.route("/admin/subscriptions/<int:user_id>/clear", methods=["POST"])
@login_required
@role_required("admin")
def admin_clear_subscription(user_id):
    """Clear/deactivate the current active subscription for a user."""
    user = User.query.get_or_404(user_id)

    # Find their active subscription
    sub = Subscription.query.filter_by(user_id=user.id, is_active=True).first()

    if not sub:
        flash("No active subscription to clear for this user.", "info")
        return redirect(url_for("admin_subscriptions"))

    # Deactivate it (adjust these lines if your model uses different fields)
    sub.is_active = False
    # Optional: mark an end date if you have such a column
    # sub.ends_at = datetime.utcnow()

    db.session.commit()
    record_audit_event(
        "admin.subscription_cleared", "Active subscription cleared",
        subject_user_id=user.id, resource_type="subscription", resource_id=sub.id,
        details={"role": sub.role, "tier": sub.tier},
    )
    flash(f"Active subscription cleared for {user.email}.", "success")
    return redirect(url_for("admin_subscriptions"))

@app.route("/admin/content/<slug>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_edit_content(slug):
    """
    Edit a single content block (page copy) identified by slug.
    Optional ?next=/some/url to return user back to the page they came from.
    """
    from urllib.parse import urlparse

    default = request.args.get("default", "")
    next_url = request.args.get("next") or url_for("admin_dashboard")

    block = PageContent.query.filter_by(slug=slug).first()
    if not block:
        block = PageContent(slug=slug, content=default)
        db.session.add(block)
        db.session.commit()

    if request.method == "POST":
        content = request.form.get("content") or ""
        block.content = content
        block.updated_by = current_user
        db.session.commit()
        record_audit_event(
            "admin.content_updated", "Marketplace content updated",
            resource_type="page_content", resource_id=block.id,
            details={"slug": block.slug},
        )

        flash("Content updated.", "success")

        # Basic safety: only redirect to internal paths
        parsed = urlparse(next_url)
        if parsed.netloc:
            return redirect(url_for("admin_dashboard"))
        return redirect(next_url)

    return render_template("admin/edit_content.html", block=block, next_url=next_url)




# -------- Admin user management / impersonation --------


@app.route("/admin/users")
@login_required
@role_required("admin")
def admin_users():
    users = User.query.order_by(User.id.desc()).all()
    return render_template("admin/users.html", users=users)


@app.route("/admin/audit-log")
@login_required
@role_required("admin")
def admin_audit_log():
    query = AuditEvent.query
    event_type = (request.args.get("event_type") or "").strip()
    resource_type = (request.args.get("resource_type") or "").strip()
    user_id = request.args.get("user_id", type=int)
    search = (request.args.get("q") or "").strip()
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    if resource_type:
        query = query.filter(AuditEvent.resource_type == resource_type)
    if user_id:
        query = query.filter(
            or_(AuditEvent.actor_id == user_id, AuditEvent.subject_user_id == user_id)
        )
    if search:
        like = f"%{search[:100]}%"
        query = query.filter(
            or_(AuditEvent.summary.ilike(like), AuditEvent.event_type.ilike(like))
        )
    page = max(request.args.get("page", 1, type=int), 1)
    pagination = query.order_by(AuditEvent.created_at.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    event_types = [
        row[0] for row in db.session.query(AuditEvent.event_type)
        .distinct().order_by(AuditEvent.event_type).all()
    ]
    resource_types = [
        row[0] for row in db.session.query(AuditEvent.resource_type)
        .filter(AuditEvent.resource_type.isnot(None))
        .distinct().order_by(AuditEvent.resource_type).all()
    ]
    return render_template(
        "admin/audit_log.html", pagination=pagination,
        event_types=event_types, resource_types=resource_types,
    )


@app.route("/admin/impersonate/<int:user_id>", methods=["POST"])
@login_required
@role_required("admin")
def admin_impersonate(user_id):
    target = User.query.get_or_404(user_id)

    if target.id == current_user.id:
        flash("You are already logged in as this user.")
        return redirect(url_for("admin_users"))

    if not session.get("impersonator_id"):
        session["impersonator_id"] = current_user.id

    record_audit_event(
        "admin.impersonation_started", "Administrator started impersonating a user",
        subject_user_id=target.id, resource_type="user", resource_id=target.id,
    )

    login_user(target)
    flash(f"You are now impersonating {target.email}")
    return redirect(url_for("index"))


@app.route("/admin/stop-impersonating", methods=["POST"])
@login_required
def stop_impersonating():
    impersonator_id = session.get("impersonator_id")
    if not impersonator_id:
        flash("You are not impersonating another user.")
        return redirect(url_for("index"))

    admin = User.query.get(impersonator_id)
    if not admin or admin.role != "admin":
        session.pop("impersonator_id", None)
        flash("Original admin account could not be found.")
        return redirect(url_for("index"))

    impersonated_user_id = current_user.id
    record_audit_event(
        "admin.impersonation_stopped", "Administrator stopped impersonating a user",
        subject_user_id=impersonated_user_id, resource_type="user",
        resource_id=impersonated_user_id, actor_id=admin.id,
    )
    session.pop("impersonator_id", None)
    login_user(admin)
    flash("Stopped impersonating and returned to your admin account.")
    return redirect(url_for("admin_dashboard"))


# -------------------------------------------------------------------
# Weekly digest task
# -------------------------------------------------------------------

@app.route("/tasks/send_weekly_digest")
def send_weekly_digest():
    token = request.args.get("token")
    configured_token = app.config.get("DIGEST_TASK_TOKEN")
    if not configured_token:
        return "Digest task is not configured", 503
    if token != configured_token:
        return "Forbidden", 403

    since = utcnow() - timedelta(days=7)
    for listing in Listing.query.filter(
        Listing.status == "live", Listing.created_at >= since
    ).all():
        publish_listing_match_notifications(listing)

    today = utcnow().date()
    reminder_horizon = today + timedelta(days=7)
    due_tasks = (
        WorkspaceTask.query.join(Introduction)
        .filter(
            WorkspaceTask.status != "completed",
            WorkspaceTask.due_date.isnot(None),
            WorkspaceTask.due_date <= reminder_horizon,
            ~Introduction.status.in_(["pending_seller_request", "declined", "failed"]),
        )
        .all()
    )
    for task in due_tasks:
        timing = "overdue" if task.due_date < today else f"due {task.due_date.strftime('%d %b')}"
        publish_notification(
            task.owner, event_type="workspace_task_reminder",
            title="Deal task reminder",
            body=f"{task.title} is {timing} for {task.introduction.listing.listing_code or 'an introduction'}.",
            target_url=url_for("deal_workspace", intro_id=task.introduction_id),
            dedupe_key=f"workspace-task-reminder:{task.id}:{task.due_date.isoformat()}",
        )

    expire_structured_offers()

    # Retry immediate deliveries that previously failed.
    for notification in Notification.query.filter_by(
        email_eligible=True, email_sent_at=None
    ).all():
        if notification_email_mode(notification.user_id) == "immediate":
            deliver_notification_email(notification)

    total_emails = 0
    total_notifications = 0
    for user in User.query.order_by(User.id.asc()).all():
        if notification_email_mode(user.id) != "weekly":
            continue
        queued = (
            Notification.query.filter_by(
                user_id=user.id,
                email_eligible=True,
                digest_sent_at=None,
                read_at=None,
            )
            .order_by(Notification.created_at.asc())
            .limit(100)
            .all()
        )
        if not queued:
            continue

        lines = ["Your weekly Ownerlane notifications:\n"]
        for notification in queued:
            lines.append(f"- {notification.title}")
            lines.append(f"  {notification.body}")
            target = _notification_absolute_url(notification.target_url)
            if target:
                lines.append(f"  {target}")
            lines.append("")
        lines.append("Open Ownerlane to review and manage all notifications.")
        sent = send_email(
            user.email,
            "Your weekly Ownerlane notifications",
            "\n".join(lines),
        )
        if not sent:
            continue
        sent_at = utcnow()
        for notification in queued:
            notification.digest_sent_at = sent_at
        db.session.commit()
        record_audit_event(
            "notification.digest_delivered", "Weekly notification digest delivered",
            subject_user_id=user.id, resource_type="user", resource_id=user.id,
            details={"notification_count": len(queued), "delivery": "weekly"},
        )
        total_emails += 1
        total_notifications += len(queued)

    if not total_emails:
        return "No queued notifications for this week.", 200
    return (
        f"Weekly digest sent: {total_emails} users, {total_notifications} notifications.",
        200,
    )

@app.route("/admin/subscriptions/set", methods=["POST"])
@login_required
@role_required("admin")
def admin_set_subscription():
    user_id = int(request.form.get("user_id"))
    role = request.form.get("role")
    tier = request.form.get("tier")

    user = User.query.get_or_404(user_id)

    # Clear existing active subs
    Subscription.query.filter_by(user_id=user.id, is_active=True).update(
        {"is_active": False}
    )

    # Create new subscription
    new_sub = Subscription(
        user_id=user.id,
        role=role,
        tier=tier,
        is_active=True,
        renews_at=datetime.utcnow() + timedelta(days=30)
    )
    db.session.add(new_sub)
    db.session.commit()
    record_audit_event(
        "admin.subscription_set", "Subscription replaced",
        subject_user_id=user.id, resource_type="subscription", resource_id=new_sub.id,
        details={"role": role, "tier": tier},
    )

    flash(f"{user.email} is now {role.capitalize()} {tier.capitalize()}.", "success")
    return redirect(url_for("admin_subscriptions"))

@app.route("/webhooks/stripe", methods=["POST"])
@csrf.exempt
def stripe_webhook():
    """
    Handle Stripe webhooks:
      - checkout.session.completed → create/activate Subscription row
      - customer.subscription.deleted → deactivate
    """
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    webhook_secret = app.config.get("STRIPE_WEBHOOK_SECRET")

    if not webhook_secret:
        # If no secret configured, ignore for safety
        return "Webhook not configured", 200

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=webhook_secret,
        )
    except ValueError:
        # Invalid payload
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        # Invalid signature
        return "Invalid signature", 400

    event_type = event["type"]
    data_obj = event["data"]["object"]

    # 1) Checkout completed → create/update Subscription row
    if event_type == "checkout.session.completed":
        session_obj = data_obj
        subscription_id = session_obj.get("subscription")
        customer_id = session_obj.get("customer")

        meta = session_obj.get("metadata") or {}
        user_id = meta.get("user_id")
        role = meta.get("role")
        tier = meta.get("tier")

        if not user_id or not role or not tier or not subscription_id:
            app.logger.warning("Stripe webhook missing metadata for checkout.session.completed")
            return "Missing metadata", 200

        try:
            user = User.query.get(int(user_id))
        except Exception:
            user = None

        if not user:
            app.logger.warning(f"Stripe webhook: user {user_id} not found")
            return "User not found", 200

        # Deactivate existing active subs for this user/role
        Subscription.query.filter_by(
            user_id=user.id,
            role=role,
            is_active=True,
        ).update({"is_active": False})

        # Create a new active subscription
        new_sub = Subscription(
            user_id=user.id,
            role=role,
            tier=tier,
            stripe_subscription_id=subscription_id,
            stripe_customer_id=customer_id,
            is_active=True,
            started_at=datetime.utcnow(),
            renews_at=None,  # could be updated from invoice / subscription events
        )
        db.session.add(new_sub)
        db.session.commit()

        app.logger.info(f"Activated {role} {tier} subscription for user {user.email}")
        return "ok", 200

    # 2) Subscription deleted/canceled → deactivate
    if event_type in {"customer.subscription.deleted", "customer.subscription.updated"}:
        sub = data_obj
        stripe_sub_id = sub.get("id")
        status = sub.get("status")

        db_sub = Subscription.query.filter_by(
            stripe_subscription_id=stripe_sub_id
        ).first()

        if db_sub:
            if status in {"canceled", "unpaid", "past_due"}:
                db_sub.is_active = False
                db.session.commit()
                app.logger.info(f"Deactivated subscription {stripe_sub_id} due to status {status}")

        return "ok", 200

    # For everything else, just acknowledge
    return "ignored", 200

# -------------------------------------------------------------------
# Auto-run migrations on startup (for Railway)
# -------------------------------------------------------------------
if os.getenv("RUN_MIGRATIONS_ON_START", "0") == "1":
    from flask_migrate import upgrade as alembic_upgrade

    with app.app_context():
        alembic_upgrade()

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

if __name__ == "__main__":
    # Only do seeding inside an app context, and only if explicitly enabled
    with app.app_context():
        if os.environ.get("AUTO_SEED_ADMIN", "0") == "1":
            seed_admin_user()

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
