import os
import re
import uuid
import smtplib
import math
from email.message import EmailMessage
from datetime import datetime, timedelta
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
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
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
from sqlalchemy import func, desc

from flask import current_app

# -------------------------------------------------------------------
# App & config
# -------------------------------------------------------------------

app = Flask(__name__)

# Secret key
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-production")

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



login_manager = LoginManager(app)
login_manager.login_view = "login"

# Task token & email config
app.config["DIGEST_TASK_TOKEN"] = os.getenv("DIGEST_TASK_TOKEN", "super-secret-token")

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

# Seller document upload folder
SELLER_DOCS_FOLDER = os.path.join(app.root_path, "static", "seller_docs")
os.makedirs(SELLER_DOCS_FOLDER, exist_ok=True)
app.config["SELLER_DOCS_FOLDER"] = SELLER_DOCS_FOLDER

# Heads of Terms / deal docs upload folder
OFFER_DOCS_FOLDER = os.path.join(app.root_path, "static", "offer_docs")
os.makedirs(OFFER_DOCS_FOLDER, exist_ok=True)
app.config["OFFER_DOCS_FOLDER"] = OFFER_DOCS_FOLDER

# -------------------------------------------------------------------
# Deal / introduction status pipeline
# -------------------------------------------------------------------

INTRO_STATUSES = [
    ("initiated", "Initiated"),
    ("nda_signed", "NDA signed"),
    ("viewing", "Viewing"),
    ("offer_made", "Offer made"),
    ("offer_accepted", "Offer accepted"),
    ("completed", "Completed"),
    ("failed", "Failed"),
]




# -------------------------------------------------------------------
# Models
# -------------------------------------------------------------------


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'seller','buyer','admin','valuer'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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


class Listing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    listing_code = db.Column(db.String(20), unique=True)
    title = db.Column(db.String(255), nullable=False)
    region = db.Column(db.String(100))
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
        db.String(20), default="draft"
    )  # 'draft','live','under_offer','sold','archived'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # legacy single photo (keep so older code still works)
    photo_filename = db.Column(db.String(255))

    seller = db.relationship("User", backref="listings", lazy=True)

    photos = db.relationship(
        "ListingPhoto",
        backref="listing",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="ListingPhoto.created_at",
    )


class ListingPhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    listing_id = db.Column(db.Integer, db.ForeignKey("listing.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    is_cover = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Enquiry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    listing_id = db.Column(db.Integer, db.ForeignKey("listing.id"), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
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

    user = db.relationship("User", backref="buyer_profile", uselist=False)

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



class Lead(db.Model):
    __tablename__ = "leads"

    id = db.Column(db.Integer, primary_key=True)
    listing_id = db.Column(
        db.Integer,
        db.ForeignKey("listing.id"),
        nullable=False,
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

    user = db.relationship("User", backref="valuer_profile", uselist=False)

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

    user = db.relationship("User", backref="seller_profile", uselist=False)


class SellerProfileDocument(db.Model):
    __tablename__ = "seller_profile_documents"

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("seller_profiles.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    profile = db.relationship("SellerProfile", backref="documents")


class Subscription(db.Model):
    __tablename__ = "subscriptions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # "basic" or "premium"
    tier = db.Column(db.String(20), nullable=False)

    # "buyer", "seller", "valuer"
    role = db.Column(db.String(20), nullable=False)

    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    renews_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    # Stripe integration
    stripe_subscription_id = db.Column(db.String(255))
    stripe_customer_id = db.Column(db.String(255))

    user = db.relationship("User", backref="subscriptions")


class Payment(db.Model):
    __tablename__ = "payments"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    amount = db.Column(db.Integer)  # pence
    currency = db.Column(db.String(10), default="GBP")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    stripe_payment_id = db.Column(db.String(255))
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
    listing_id = db.Column(db.Integer, db.ForeignKey("listing.id"), nullable=False)

    turnover = db.Column(db.String(100))
    ebitda = db.Column(db.String(100))
    profit = db.Column(db.String(100))
    loss = db.Column(db.String(100))
    assets = db.Column(db.String(255))
    debts = db.Column(db.String(255))
    staff_count = db.Column(db.Integer)

    year_end = db.Column(db.String(50))  # e.g. "YE Mar 2024"

    listing = db.relationship("Listing", backref="financials", uselist=False)


class BuyerCriteria(db.Model):
    __tablename__ = "buyer_criteria"

    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    regions = db.Column(db.String(255))  # comma-separated
    care_types = db.Column(db.String(255))  # comma-separated

    min_turnover = db.Column(db.String(50))
    max_turnover = db.Column(db.String(50))
    min_beds = db.Column(db.Integer)
    max_beds = db.Column(db.Integer)

    funding_ready = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)

    buyer = db.relationship("User", backref="criteria", uselist=False)


class Introduction(db.Model):
    __tablename__ = "introductions"

    id = db.Column(db.Integer, primary_key=True)

    buyer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    listing_id = db.Column(db.Integer, db.ForeignKey("listing.id"), nullable=False)

    # Deal status pipeline
    status = db.Column(
        db.String(20),
        default="initiated"
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


class IntroductionStatusHistory(db.Model):
    __tablename__ = "introduction_status_history"

    id = db.Column(db.Integer, primary_key=True)
    introduction_id = db.Column(
        db.Integer, db.ForeignKey("introductions.id"), nullable=False
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

    listing_id = db.Column(db.Integer, db.ForeignKey("listing.id"), nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    valuer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    status = db.Column(
        db.String(20),
        default="pending"
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
        db.Integer, db.ForeignKey("introductions.id"), nullable=False
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

    introduction = db.relationship("Introduction", backref="deal")


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

    sub = (
        SubscriptionModel.query
        .filter_by(user_id=user.id, role=role, tier=tier, is_active=True)
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
    Send emails when an introduction moves through the pipeline.
    - Always notifies the internal broker email (LEADS_NOTIFICATION_EMAIL).
    - Optionally notifies buyer/seller on key milestones.
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
          View in admin: (log into the Care Home Broker admin and open Introductions).
        </p>
    """

    # 1) Internal broker notification
    send_email(
        to_addresses=internal_email,
        subject=subject,
        html_body=html_body,
    )

    # 2) Optional buyer / seller notifications on key milestones
    #    (tweak this set if you want different behaviour)
    external_notify_statuses = {"nda_signed", "viewing", "offer_made", "offer_accepted", "completed"}

    if new_status in external_notify_statuses:
        buyer_subject = f"Your introduction for {code} is now '{new_label}'"
        seller_subject = f"Introduction for {code} is now '{new_label}'"

        buyer_html = f"""
            <p>Hi,</p>
            <p>
              The introduction for listing <strong>{code} – {title}</strong> has moved to:
              <strong>{new_label}</strong>.
            </p>
            <p>
              Please log into the platform or contact Kaijo North Consulting for the next steps.
            </p>
        """

        seller_html = f"""
            <p>Hi,</p>
            <p>
              The introduction for your listing <strong>{code} – {title}</strong> has moved to:
              <strong>{new_label}</strong>.
            </p>
            <p>
              Please log into the platform or contact Kaijo North Consulting for the next steps.
            </p>
        """

        try:
            send_email(buyer.email, buyer_subject, buyer_html)
        except Exception:
            current_app.logger.exception("Failed to send buyer intro status email")

        try:
            send_email(seller.email, seller_subject, seller_html)
        except Exception:
            current_app.logger.exception("Failed to send seller intro status email")



def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in app.config["ALLOWED_EXTENSIONS"]


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


# Shortlist stored in session for buyers
def get_shortlist_ids():
    ids = session.get("shortlist", [])
    if not isinstance(ids, list):
        ids = []
    try:
        return {int(i) for i in ids}
    except Exception:
        return set()

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
            reasons.append("Care type match")

        # Beds range
        if profile.beds_min is not None and l.beds is not None:
            if l.beds >= profile.beds_min:
                score += 10
                reasons.append("Meets min beds")
        if profile.beds_max is not None and l.beds is not None:
            if l.beds <= profile.beds_max:
                score += 10
                reasons.append("Within beds range")

        # Rough quality match
        if profile.quality_preference and l.cqc_rating:
            if profile.quality_preference.lower() in l.cqc_rating.lower():
                score += 10
                reasons.append("Quality/CQC match")

        # If no specific matches triggered, still include with a low base score
        if score == 0:
            score = 5
            reasons.append("General match (live & within broad filters)")

        results.append((l, score, reasons))

    results.sort(key=lambda t: t[1], reverse=True)

    if limit is not None:
        results = results[:limit]

    return results



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
            <p>This introduction is being managed by Kaijo North Consulting via the Care Home Broker platform.</p>
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


# -------- Admin seeding helpers --------


def seed_admin_user(email: str | None = None, password: str | None = None):
    """
    Seed an admin user.
    Email/password can be passed in or taken from env:
      ADMIN_EMAIL, ADMIN_PASSWORD
    """
    email = (
        email or os.environ.get("ADMIN_EMAIL") or "admin@carebroker.local"
    ).strip().lower()
    password = password or os.environ.get("ADMIN_PASSWORD") or "Admin123!"

    existing = User.query.filter_by(email=email).first()
    if existing:
        print(f"[seed-admin] Admin user already exists: {email}")
        return existing

    ok, msg = validate_password_strength(password)
    if not ok:
        print(f"[seed-admin] Weak admin password: {msg}")
        print("[seed-admin] WARNING: Using a weak admin password. Change ADMIN_PASSWORD!")

    admin = User(
        email=email,
        password_hash=generate_password_hash(password),
        role="admin",
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



@app.route("/listings")
def listings():
    # Base query: live listings only
    query = Listing.query.filter_by(status="live")

    search_q = (request.args.get("q") or "").strip()
    selected_region = request.args.get("region") or ""
    selected_care_type = request.args.get("care_type") or ""
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
    if selected_care_type:
        query = query.filter(Listing.care_type == selected_care_type)

    total = query.count()
    pages = max(1, math.ceil(total / per_page)) if total else 1
    if page > pages:
        page = pages

    listings_data = (
        query.order_by(Listing.created_at.desc())
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
    care_types = sorted(
        {
            c[0]
            for c in base_live.with_entities(Listing.care_type).distinct()
            if c[0] is not None and c[0] != ""
        }
    )

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
            map_data.append(
                {
                    "id": l.id,
                    "title": l.title,
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
        "listings.html",
        listings=listings_data,
        search_q=search_q,
        selected_region=selected_region,
        selected_care_type=selected_care_type,
        view_mode=view_mode,
        page=page,
        pages=pages,
        total=total,
        regions=regions,
        care_types=care_types,
        shortlist_ids=shortlist_ids,
        map_data=map_data,
        is_premium_buyer=is_premium_buyer,   # <-- ADDED
    )



@app.route("/listings/<int:listing_id>", methods=["GET", "POST"])
def listing_detail(listing_id):
    listing = Listing.query.get_or_404(listing_id)

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
            flash("Your enquiry has been sent.")
            return redirect(url_for("buyer_dashboard"))

    # ---- GET (or POST with validation errors) → render template ----
    return render_template(
        "listing_detail.html",
        listing=listing,
        is_premium_buyer=is_premium_buyer,
        is_shortlisted=is_shortlisted,
        can_enquire=can_enquire,
    )


@app.route("/listing/<int:listing_id>/enquire", methods=["GET", "POST"])
def enquire(listing_id):
    listing = Listing.query.get_or_404(listing_id)

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

        # Send notification email
        to_email = app.config["LEADS_NOTIFICATION_EMAIL"]
        if to_email:
            subject = (
                f"New enquiry for listing #{listing.id}: "
                f"{getattr(listing, 'name', 'Care Home')}"
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

        if not email:
            flash("Email is required.")
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
        )
        db.session.add(user)
        db.session.commit()
        flash("Buyer account created. You can now log in.")
        return redirect(url_for("login"))

    return render_template("auth/register_buyer.html")


@app.route("/register/seller", methods=["GET", "POST"])
def register_seller():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email:
            flash("Email is required.")
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
        )
        db.session.add(user)
        db.session.commit()
        flash("Seller account created. You can now log in.")
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

        if not email:
            flash("Email is required.")
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

        flash("Valuer account created. You can now log in.")
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

        vr.status = new_status
        vr.created_at = vr.created_at  # unchanged; SQLAlchemy will track
        db.session.commit()
        flash("Valuation request updated.", "success")
        return redirect(url_for("valuer_request_detail", request_id=vr.id))

    return render_template(
        "valuer/request_detail.html",
        vr=vr,
        allowed_statuses=allowed_statuses,
    )

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

        user = User.query.filter_by(email=email).first()

        if user is None or not user.check_password(password):
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html")

        if not getattr(user, "is_active", True):
            flash("Your account is inactive. Please contact support.", "warning")
            return render_template("auth/login.html")

        # Log the user in
        login_user(user, remember=True)

        # Honour ?next=... if present
        next_page = request.args.get("next")
        if next_page:
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
    logout_user()
    flash("Logged out.")
    return redirect(url_for("index"))


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

    return render_template(
        "seller/dashboard.html",
        listings=listings,
        profile=profile,
        profile_incomplete=profile_incomplete,
        current_plan_label=current_plan_label,
        active_sub=active_sub,
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

        if premium_buyer_ids:
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
            }
        )

    # Sort best matches first
    matches.sort(key=lambda m: m["score"], reverse=True)

    return render_template(
        "seller/buyers.html",
        matches=matches,
        seller_regions=sorted(seller_regions),
        seller_care_types=sorted(seller_care_types),
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

        listing = Listing(
            seller_id=current_user.id,
            title=title,
            region=request.form.get("region") or None,
            care_type=request.form.get("care_type") or None,
            beds=request.form.get("beds") or None,
            occupancy_percent=request.form.get("occupancy_percent") or None,
            cqc_rating=request.form.get("cqc_rating") or None,
            tenure=request.form.get("tenure") or None,
            revenue_band=request.form.get("revenue_band") or None,
            ebitda_band=request.form.get("ebitda_band") or None,
            guide_price_band=request.form.get("guide_price_band") or None,
            short_description=request.form.get("short_description") or None,
            is_confidential=bool(request.form.get("is_confidential")),
            status="draft",
        )
        listing.listing_code = generate_listing_code()

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

    return render_template("seller/new_listing.html")


@app.route("/seller/listings/<int:listing_id>/edit", methods=["GET", "POST"])
@login_required
def seller_edit_listing(listing_id):
    # Ensure seller only edits their own listing
    listing = Listing.query.get_or_404(listing_id)

    if current_user.role != "seller" or listing.seller_id != current_user.id:
        flash("You do not have permission to edit this listing.")
        return redirect(url_for("seller_dashboard"))

    if request.method == "POST":
        # Core fields
        listing.title = request.form.get("title") or listing.title
        listing.short_description = request.form.get("short_description") or ""
        listing.region = request.form.get("region") or None
        listing.care_type = request.form.get("care_type") or None
        listing.beds = request.form.get("beds") or None
        listing.occupancy_percent = request.form.get("occupancy_percent") or None
        listing.cqc_rating = request.form.get("cqc_rating") or None
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
    return render_template("seller/edit_listing.html", listing=listing)


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

    listing.status = status
    if not listing.listing_code:
        listing.listing_code = generate_listing_code()
    db.session.commit()
    flash(f"Listing marked as {status.replace('_', ' ')}.")
    return redirect(url_for("seller_dashboard"))

@app.route("/seller/listings/<int:listing_id>/request-valuation", methods=["GET", "POST"])
@login_required
@role_required("seller")
def request_valuation(listing_id):
    listing = Listing.query.get_or_404(listing_id)

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

        # --- EMAIL NOTIFICATIONS (BROKER + OPTIONAL VALUER) ---
        try:
            admin_email = current_app.config.get("LEADS_NOTIFICATION_EMAIL")
            valuer_email = None
            if vr.valuer_id:
                valuer_user = User.query.get(vr.valuer_id)
                if valuer_user:
                    valuer_email = valuer_user.email

            to_addresses = [e for e in [admin_email, valuer_email] if e]

            if to_addresses:
                subject = f"New valuation request for {listing.listing_code or 'listing'}"

                safe_notes = (notes or "").replace("\n", "<br>")

                html_body = f"""
                    <h2>New valuation request</h2>
                    <p><strong>Listing:</strong> {listing.listing_code or ''} – {listing.title}</p>
                    <p><strong>Region:</strong> {listing.region or ''}</p>
                    <p><strong>Care type:</strong> {listing.care_type or ''}</p>
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
        upload_folder = app.config["SELLER_DOCS_FOLDER"]
        os.makedirs(upload_folder, exist_ok=True)

        for file in files:
            if not file or not file.filename:
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

        db.session.commit()

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
                    <p><strong>Care type:</strong> {profile.care_type or "n/a"}</p>
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


@app.route("/buyer/profile", methods=["GET", "POST"])
@login_required
@role_required("buyer")
def buyer_profile():
    profile = BuyerProfile.query.filter_by(user_id=current_user.id).first()

    # Choices for checkboxes / selects
    region_choices = sorted(REGION_COORDS.keys())
    care_type_choices = [
        "Residential",
        "Nursing",
        "Dementia / EMI",
        "Learning disability",
        "Mental health",
        "Supported living",
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

@app.route("/buyer/dashboard")
@login_required
@role_required("buyer")
def buyer_dashboard():
    """
    Buyer dashboard:
    - Shows recent enquiries
    - Shows recommended live listings based on buyer profile
    - Shows shortlist listings from session
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

    # Shortlist listings (session-based)
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

    return render_template(
        "buyer/dashboard.html",   # <-- key fix vs buyer_dashboard.html
        enquiries=enquiries,
        recommendations=recommendations,
        shortlist_listings=shortlist_listings,
        profile=profile,
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

    # Notify the seller
    seller_email = vr.seller.email
    listing = vr.listing

    subject = f"Valuer accepted your valuation request – {listing.listing_code or ''}"

    html_body = f"""
        <h2>Your valuation request has been accepted</h2>
        <p><strong>Listing:</strong> {listing.listing_code or ''} – {listing.title}</p>
        <p>Your chosen valuer ({current_user.email}) has accepted your request.</p>

        <p>You can now wait for them to contact you or follow up via your dashboard.</p>

        <p><a href="{url_for('seller_dashboard', _external=True)}">Open seller dashboard</a></p>
    """

    send_email(
        to_addresses=seller_email,
        subject=subject,
        html_body=html_body,
        reply_to=current_user.email,
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

    seller_email = vr.seller.email
    listing = vr.listing

    subject = f"Valuation request declined – {listing.listing_code or ''}"

    html_body = f"""
        <h2>Your valuation request was declined</h2>
        <p><strong>Listing:</strong> {listing.listing_code or ''} – {listing.title}</p>
        <p>Your chosen valuer ({current_user.email}) has declined the valuation request.</p>

        <p>You may send the request to another valuer.</p>
        <p><a href="{url_for('valuers_directory', _external=True)}">Browse valuers</a></p>
    """

    send_email(
        to_addresses=seller_email,
        subject=subject,
        html_body=html_body,
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

    seller_email = vr.seller.email
    listing = vr.listing

    subject = f"Valuation completed – {listing.listing_code or ''}"

    html_body = f"""
        <h2>Your valuation has been completed</h2>
        <p><strong>Listing:</strong> {listing.listing_code or ''} – {listing.title}</p>
        <p>The valuation has now been marked as complete by {current_user.email}.</p>

        <p>Please check your inbox or contact the valuer for the final report.</p>

        <p><a href="{url_for('seller_dashboard', _external=True)}">Go to seller dashboard</a></p>
    """

    send_email(
        to_addresses=seller_email,
        subject=subject,
        html_body=html_body,
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
    Add/remove a listing from the buyer's shortlist (stored in session).
    Expects a POST from listing_detail or listings views.
    """
    listing = Listing.query.get_or_404(listing_id)

    # Get current shortlist from session (list of IDs)
    shortlist = session.get("shortlist", [])
    try:
        listing_id_int = int(listing_id)
    except (TypeError, ValueError):
        listing_id_int = listing_id

    if listing_id_int in shortlist:
        shortlist.remove(listing_id_int)
        flash("Listing removed from your shortlist.", "info")
    else:
        shortlist.append(listing_id_int)
        flash("Listing added to your shortlist.", "success")

    session["shortlist"] = shortlist

    # Go back to where the user came from, or fallback to shortlist page
    next_url = request.form.get("next") or request.referrer or url_for("buyer_shortlist")
    return redirect(next_url)


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
    listing.status = "live"
    if not listing.listing_code:
        listing.listing_code = generate_listing_code()
    db.session.commit()
    flash("Listing approved and set live.")
    return redirect(url_for("admin_listings"))


@app.route("/admin/listings/<int:listing_id>/archive", methods=["POST"])
@login_required
@role_required("admin")
def admin_archive_listing(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    listing.status = "archived"
    db.session.commit()
    flash("Listing archived.")
    return redirect(url_for("admin_listings"))


@app.route("/admin/test-email")
def test_email():
    ok = send_email(
        to_addresses="YOUR_REAL_ADDRESS@gmail.com",
        subject="Care Home Broker SMTP test",
        html_body="""
            <h2>SMTP is live ✅</h2>
            <p>This is a test email from the Care Home Broker app.</p>
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

    flash("Introduction approved and marked as initiated.", "success")
    return redirect(url_for("admin_introduction_requests"))


@app.route("/admin/introduction_requests/<int:intro_id>/decline", methods=["POST"])
@login_required
@role_required("admin")
def admin_decline_intro_request(intro_id):
    intro = Introduction.query.get_or_404(intro_id)
    intro.status = "declined"
    db.session.commit()

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
        premium_ids=premium_ids,
        basic_ids=basic_ids,
    )


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
    deal = getattr(intro, "deal", None)

    return render_template(
        "admin/introduction_detail.html",
        introduction=intro,
        deal=deal,
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
    if intro.deal:
        if new_status == "completed":
            intro.deal.status = "completed"
        elif new_status == "failed":
            intro.deal.status = "aborted"

    # History row
    history = IntroductionStatusHistory(
        introduction_id=intro.id,
        old_status=old_status,
        new_status=new_status,
        changed_by_user_id=current_user.id if current_user.is_authenticated else None,
    )
    db.session.add(history)

    db.session.commit()

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

    deal = getattr(intro, "deal", None)
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
    if token != app.config["DIGEST_TASK_TOKEN"]:
        return "Forbidden", 403

    now = datetime.utcnow()
    since = now - timedelta(days=7)

    # New live listings in the last 7 days
    new_listings = (
        Listing.query.filter(
            Listing.status == "live",
            Listing.created_at >= since,
        ).all()
    )

    if not new_listings:
        return "No new listings in last 7 days.", 200

    buyer_matches = {}  # User -> list[Listing with match attrs]

    # Buyers that actually have a BuyerProfile
    buyers_with_profile = (
        User.query.filter_by(role="buyer")
        .join(BuyerProfile, BuyerProfile.user_id == User.id)
        .all()
    )

    for buyer in buyers_with_profile:
        profile = BuyerProfile.query.filter_by(user_id=buyer.id).first()
        if not profile:
            continue

        # Score all new listings for this buyer
        scored = []
        for listing in new_listings:
            if listing.status != "live":
                continue

            score, label, reasons = compute_buyer_listing_match(listing, profile)
            if score <= 0:
                continue

            # attach temp attrs for this digest only
            listing._match_score = score
            listing._match_label = label
            listing._match_reasons = reasons
            scored.append(listing)

        if not scored:
            continue

        # Sort by score (desc) then newest first
        scored.sort(
            key=lambda l: (getattr(l, "_match_score", 0), l.created_at or datetime.min),
            reverse=True,
        )

        # Limit per-buyer list for the email
        buyer_matches[buyer] = scored[:10]

    if not buyer_matches:
        return "No profile matches for buyers this week.", 200

    total_emails = 0
    total_matches = 0

    for buyer, matches in buyer_matches.items():
        lines = []
        lines.append(
            "Here are new care home opportunities from the last 7 days that match your profile:\n"
        )

        for l in matches:
            code = l.listing_code or "Ref pending"
            title = l.title or "Confidential care home"
            region = l.region or "Region"
            care_type = l.care_type or "Care type"
            beds = l.beds or "?"
            price = l.guide_price_band or "On request"
            label = getattr(l, "_match_label", "Match")
            reasons = getattr(l, "_match_reasons", []) or []

            lines.append(f"- {code} – {title}")
            lines.append(
                f"  {label} • {region} • {care_type} • {beds} beds • Guide price: {price}"
            )
            if reasons:
                # Include only the first couple of reasons to keep it readable
                for r in reasons[:2]:
                    lines.append(f"    · {r}")
            lines.append("")

        # Premium vs basic CTA
        is_premium = has_active_subscription(buyer, "buyer", "premium")
        if is_premium:
            lines.append(
                "You have Buyer Premium access – log in to view full details and send enquiries directly."
            )
        else:
            lines.append(
                "You currently have Buyer Basic access. Upgrade to Buyer Premium to see full listing details and send enquiries directly through the platform."
            )

        lines.append("")
        lines.append("Log in to your buyer dashboard to view and manage these opportunities.")
        lines.append("")

        body = "\n".join(lines)
        subject = "Your weekly matched care home opportunities"

        # Use simple text body; send_email will wrap it as text/html combo
        send_email(buyer.email, subject, body)

        total_emails += 1
        total_matches += len(matches)

    return (
        f"Weekly digest sent: {total_emails} buyers, {total_matches} total matches.",
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

    flash(f"{user.email} is now {role.capitalize()} {tier.capitalize()}.", "success")
    return redirect(url_for("admin_subscriptions"))

@app.route("/webhooks/stripe", methods=["POST"])
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


