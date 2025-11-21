import os
import re
import uuid
import smtplib
import math
from email.message import EmailMessage
from datetime import datetime, timedelta

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
)
from flask_sqlalchemy import SQLAlchemy
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

from flask import current_app  # if not already imported
# -------------------------------------------------------------------
# App & config
# -------------------------------------------------------------------

app = Flask(__name__)

# Secret key & DB
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///care_broker.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# Task token & email config
app.config["DIGEST_TASK_TOKEN"] = os.getenv("DIGEST_TASK_TOKEN", "super-secret-token")

# after app = Flask(__name__) and config stuff:
app.config['SMTP_SERVER'] = os.getenv('SMTP_SERVER', 'localhost')
app.config['SMTP_PORT'] = int(os.getenv('SMTP_PORT', '25'))
app.config['SMTP_USERNAME'] = os.getenv('SMTP_USERNAME')
app.config['SMTP_PASSWORD'] = os.getenv('SMTP_PASSWORD')
app.config['SMTP_USE_TLS'] = os.getenv('SMTP_USE_TLS', '0') == '1'
app.config['SMTP_DEFAULT_FROM'] = os.getenv('SMTP_DEFAULT_FROM', 'no-reply@example.com')

# Upload config
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ALLOWED_EXTENSIONS"] = {"png", "jpg", "jpeg", "gif", "webp"}

app.config["LEADS_NOTIFICATION_EMAIL"] = os.getenv(
    "LEADS_NOTIFICATION_EMAIL",
    app.config.get("SMTP_USERNAME")  # fallback to Gmail sender
)





# -------------------------------------------------------------------
# Models
# -------------------------------------------------------------------


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'seller','buyer','admin'
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
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False
    )
    region = db.Column(db.String(100))  # main region of interest
    care_type = db.Column(db.String(100))  # main care type of interest
    min_price_band = db.Column(db.String(50))  # e.g. "<£500k"
    max_price_band = db.Column(db.String(50))  # e.g. "£3m+"
    experience_level = db.Column(db.String(50))  # e.g. "First-time buyer"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="buyer_profile", uselist=False)

from datetime import datetime
# ... your other imports ...

class Lead(db.Model):
    __tablename__ = "leads"

    id = db.Column(db.Integer, primary_key=True)
    listing_id = db.Column(
        db.Integer,
        db.ForeignKey("listing.id"),  # 👈 change this
        nullable=False
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


def generate_listing_code():
    """Generate codes like CH-0001, CH-0002, etc."""
    last = Listing.query.order_by(Listing.id.desc()).first()
    next_num = (last.id + 1) if last else 1
    return f"CH-{next_num:04d}"


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
    msg['Subject'] = subject
    msg['From'] = app.config['SMTP_DEFAULT_FROM']
    msg['To'] = ', '.join(to_addresses)

    if reply_to:
        msg['Reply-To'] = reply_to

    if not text_body:
        text_body = html_body.replace('<br>', '\n').replace('<br/>', '\n').replace('<br />', '\n')

    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype='html')

    try:
        with smtplib.SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT']) as smtp:
            if app.config['SMTP_USE_TLS']:
                smtp.starttls()

            if app.config['SMTP_USERNAME'] and app.config['SMTP_PASSWORD']:
                smtp.login(app.config['SMTP_USERNAME'], app.config['SMTP_PASSWORD'])

            smtp.send_message(msg)

        return True
    except Exception as e:
        app.logger.error(f"Error sending email: {e}")
        return False


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
    return render_template("index.html", listings=listings)


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
    )


@app.route("/listings/<int:listing_id>/shortlist", methods=["POST"])
@login_required
@role_required("buyer")
def toggle_shortlist(listing_id):
    listing = Listing.query.get_or_404(listing_id)

    ids = get_shortlist_ids()
    if listing_id in ids:
        ids.remove(listing_id)
        flash("Removed from your shortlist.")
    else:
        ids.add(listing_id)
        flash("Added to your shortlist.")

    session["shortlist"] = list(ids)
    session.modified = True

    next_url = request.form.get("next") or url_for("listings")
    return redirect(next_url)


@app.route("/listings/<int:listing_id>", methods=["GET", "POST"])
def listing_detail(listing_id):
    listing = Listing.query.get_or_404(listing_id)

    # Handle enquiry POST
    if request.method == "POST":
        if not current_user.is_authenticated or current_user.role != "buyer":
            flash("Log in as a buyer to send an enquiry.")
            return redirect(url_for("login"))

        message = request.form.get("message", "").strip()
        nda_accepted = bool(request.form.get("nda_accepted"))

        if not message:
            flash("Please include a message.")
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
        return redirect(url_for("listing_detail", listing_id=listing.id))

    # Check if current buyer already accepted NDA for this listing
    nda_already_accepted = False
    if current_user.is_authenticated and current_user.role == "buyer":
        nda_already_accepted = (
            Enquiry.query.filter_by(
                listing_id=listing.id, buyer_id=current_user.id, nda_accepted=True
            ).first()
            is not None
        )

    return render_template(
        "listing_detail.html",
        listing=listing,
        nda_already_accepted=nda_already_accepted,
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
            subject = f"New enquiry for listing #{listing.id}: {getattr(listing, 'name', 'Care Home')}"
            html_body = f"""
                <h2>New enquiry for listing #{listing.id}</h2>
                <p><strong>Listing:</strong> {getattr(listing, 'name', '')}</p>
                <p><strong>Region:</strong> {getattr(listing, 'region', '')}</p>
                <p><strong>Buyer name:</strong> {buyer_name}</p>
                <p><strong>Email:</strong> {buyer_email}</p>
                <p><strong>Phone:</strong> {buyer_phone}</p>
                <p><strong>Company:</strong> {buyer_company}</p>
                <p><strong>Message:</strong></p>
                <p>{message.replace('\n', '<br>')}</p>
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


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Invalid email or password.")
            return redirect(url_for("login"))

        login_user(user)
        flash("Logged in successfully.")

        next_page = request.args.get("next")
        if next_page:
            return redirect(next_page)

        if user.role == "seller":
            return redirect(url_for("seller_dashboard"))
        if user.role == "buyer":
            return redirect(url_for("buyer_dashboard"))
        if user.role == "admin":
            return redirect(url_for("admin_dashboard"))

        return redirect(url_for("index"))

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

    return render_template("seller/dashboard.html", listings=listings)


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

    listing.status = status
    if not listing.listing_code:
        listing.listing_code = generate_listing_code()
    db.session.commit()
    flash(f"Listing marked as {status.replace('_', ' ')}.")
    return redirect(url_for("seller_dashboard"))


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
# Buyer routes
# -------------------------------------------------------------------


@app.route("/buyer/dashboard")
@login_required
@role_required("buyer")
def buyer_dashboard():
    # Recent enquiries for this buyer
    enquiries = (
        Enquiry.query.join(Listing, Enquiry.listing_id == Listing.id)
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
        recommendations_query.order_by(Listing.created_at.desc()).limit(6).all()
    )

    # Shortlist listings
    shortlist_ids = get_shortlist_ids()
    shortlist_listings = []
    if shortlist_ids:
        shortlist_listings = (
            Listing.query.filter(
                Listing.id.in_(shortlist_ids), Listing.status == "live"
            )
            .order_by(Listing.created_at.desc())
            .all()
        )

    return render_template(
        "buyer/dashboard.html",
        enquiries=enquiries,
        recommendations=recommendations,
        shortlist_listings=shortlist_listings,
    )


@app.route("/buyer/profile", methods=["GET", "POST"])
@login_required
@role_required("buyer")
def buyer_profile():
    profile = BuyerProfile.query.filter_by(user_id=current_user.id).first()

    if request.method == "POST":
        region = request.form.get("region") or None
        care_type = request.form.get("care_type") or None
        min_price_band = request.form.get("min_price_band") or None
        max_price_band = request.form.get("max_price_band") or None
        experience_level = request.form.get("experience_level") or None

        if profile is None:
            profile = BuyerProfile(
                user_id=current_user.id,
                region=region,
                care_type=care_type,
                min_price_band=min_price_band,
                max_price_band=max_price_band,
                experience_level=experience_level,
            )
            db.session.add(profile)
        else:
            profile.region = region
            profile.care_type = care_type
            profile.min_price_band = min_price_band
            profile.max_price_band = max_price_band
            profile.experience_level = experience_level

        db.session.commit()
        flash("Buyer profile saved.")
        return redirect(url_for("buyer_dashboard"))

    return render_template("buyer/profile.html", profile=profile)


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


# -------------------------------------------------------------------
# Admin routes
# -------------------------------------------------------------------


@app.route("/admin")
@login_required
@role_required("admin")
def admin_dashboard():
    listing_counts = {
        "live": Listing.query.filter_by(status="live").count(),
        "draft": Listing.query.filter_by(status="draft").count(),
        "under_offer": Listing.query.filter_by(status="under_offer").count(),
        "sold": Listing.query.filter_by(status="sold").count(),
    }
    user_count = User.query.count()
    enquiry_count = Enquiry.query.count()
    return render_template(
        "admin/dashboard.html",
        listing_counts=listing_counts,
        user_count=user_count,
        enquiry_count=enquiry_count,
    )


@app.route("/admin/listings")
@login_required
@role_required("admin")
def admin_listings():
    listings = Listing.query.order_by(Listing.created_at.desc()).all()
    return render_template("admin/listings.html", listings=listings)


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


@app.route('/test-email')
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
# decorate with your existing admin/superuser decorator if you have one
def admin_leads():
    leads = Lead.query.order_by(desc(Lead.created_at)).limit(200).all()
    return render_template("admin_leads.html", leads=leads)

# -------- Admin user management / impersonation --------


@app.route("/admin/users")
@login_required
def admin_users():
    if current_user.role != "admin":
        flash("Admin access required.")
        return redirect(url_for("index"))

    users = User.query.order_by(User.id.desc()).all()
    return render_template("admin/users.html", users=users)


@app.route("/admin/impersonate/<int:user_id>", methods=["POST"])
@login_required
def admin_impersonate(user_id):
    if current_user.role != "admin":
        flash("Admin access required.")
        return redirect(url_for("index"))

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

    new_listings = (
        Listing.query.filter(
            Listing.status == "live",
            Listing.created_at >= since,
        ).all()
    )

    if not new_listings:
        return "No new listings in last 7 days.", 200

    buyer_matches = {}  # User -> list[Listing]

    buyers_with_profile = (
        User.query.filter_by(role="buyer")
        .join(BuyerProfile, BuyerProfile.user_id == User.id)
        .all()
    )

    for buyer in buyers_with_profile:
        profile = BuyerProfile.query.filter_by(user_id=buyer.id).first()
        if not profile:
            continue

        matches = []
        for listing in new_listings:
            if listing.status != "live":
                continue

            if profile.region and listing.region and listing.region != profile.region:
                continue
            if (
                profile.care_type
                and listing.care_type
                and listing.care_type != profile.care_type
            ):
                continue

            matches.append(listing)

        if matches:
            buyer_matches[buyer] = matches

    total_emails = 0
    total_matches = 0

    for buyer, matches in buyer_matches.items():
        lines = []
        lines.append(
            "Here are new care home opportunities from the last 7 days that match your profile:\n"
        )

        for l in matches:
            code = l.listing_code or "Ref pending"
            title = l.title
            region = l.region or "Region"
            care_type = l.care_type or "Care type"
            beds = l.beds or "?"
            price = l.guide_price_band or "On request"

            lines.append(f"- {code} – {title}")
            lines.append(
                f"  {region} • {care_type} • {beds} beds • Guide price: {price}"
            )
            lines.append("")

        lines.append(
            "To view details and send an enquiry, log in to your buyer dashboard."
        )
        lines.append("")

        body = "\n".join(lines)
        subject = "Your weekly care home opportunities digest"

        send_email(buyer.email, subject, body)

        total_emails += 1
        total_matches += len(matches)

    return f"Weekly digest sent: {total_emails} buyers, {total_matches} total matches.", 200


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if os.environ.get("AUTO_SEED_ADMIN", "0") == "1":
            seed_admin_user()
    app.run(debug=True)
