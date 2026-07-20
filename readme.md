# Ownerlane

**Where businesses find their next owner.**

Ownerlane is a modern, confidential marketplace where owners can explore a sale and verified buyers can discover, enquire about, and track established UK business opportunities.

Visit [ownerlane.uk](https://ownerlane.uk).

Built with Flask + Tailwind + SQLite and deployable via Waitress, Heroku/Railway, or Docker.

# Features
## Authentication

Buyer accounts

Seller accounts

Admin dashboard

Verified-email registration

Expiring, single-use password reset links

Persistent login throttling

Idle and absolute session limits for administrators

Login/Logout with Flask-Login

## Seller portal

Create, edit, and manage listings

Upload multiple photos per listing

Choose automatic cover image

Track enquiries

Update status (Draft, Live, Under Offer, Sold)

Manage staged data rooms with retained document versions

Grant or revoke buyer access per introduction and disclosure stage

## Buyer portal

Browse listings

View full details + gallery

Submit enquiries (NDA-gated)

Personalised recommendations

Buyer profile preferences

Private qualification and proof-of-funds submission

Reviewed identity, business and funding trust badges

## Marketplace tools

Weekly digest task endpoint

Persistent in-app notification centre with unread counts

Immediate, weekly or disabled notification-email preferences

Deduplicated saved-search and transaction-event delivery

Private introduction workspaces with messaging, Q&A, tasks and milestones

Due-date reminders through immediate or weekly notification delivery

Structured monetary offers with conditions, expiry, counter-offers and permanent history

Accepted-offer synchronisation into introduction and deal records

Privacy-safe seller analytics for listing views, unique visitors and shortlist activity

Seller conversion funnels, buyer-quality summaries, stage timing and listing comparisons

Multi-discipline adviser marketplace with verification, coverage and availability filters

Private scoped requests, versioned quotes, engagement tracking and completed-work reviews

Two-party consent for anonymous use of completed transaction data

Administrator-controlled benchmark publication with a hard minimum cohort of five

Aggregate market insights and private, reproducible seller valuation reports

Listing matching logic

Explainable assisted matching with published criterion weights, fit/gap evidence and separate data-coverage scores

Human-controlled matching outcomes: scores never approve, reject or prevent marketplace actions

Buyer, seller and Ownerlane teams with expiring email invitations and owner/manager/contributor/viewer permissions

Active team workspaces with shared buyer shortlists/searches and permissioned seller listing/data-room collaboration

Scoped read-only API tokens with versioned profile, listing and introduction endpoints

HTTPS webhooks with HMAC-SHA256 signatures, delivery history and bounded retries

Role-scoped, spreadsheet-safe CRM CSV export

Confidential multi-listing portfolios marketed as a whole, by configurable lot, or either way

Seller portfolio builder with lot pricing, availability, publication safeguards and targeted premium-buyer enquiries

Portfolio-aware governed introductions that retain the selected whole-portfolio or lot context

Transaction completion workspace with assigned checklists, conditions and automatic blocker calculation

Private SHA-256 checksummed signature-ready documents with separate buyer and seller acknowledgements

Two-party controlled handover that synchronises introductions, deals, listings and portfolio lots

Confidential listing handling

Privacy-safe activity and audit log

Audited data-room document access

Clean, mobile-first UI

## Data

SQLite by default

Can switch to Postgres easily using DATABASE_URL

## Project structure
project/
│ app.py
│ run_prod.py
│ requirements.txt
│ Procfile
│ Dockerfile
│ runtime.txt
│ .env.example
│ care_broker.db
│
├── static/
│   └── uploads/   (listing photo uploads)
│
└── templates/
    ├── base.html
    ├── listings.html
    ├── listing_detail.html
    ├── ...
    ├── seller/
    └── buyer/

## Getting started
1. Clone the project
git clone https://github.com/Dolman17/Carehomebroker.git
cd Carehomebroker

2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # macOS/Linux
.venv\Scripts\activate      # Windows

3. Install dependencies
pip install -r requirements.txt

4. Set up environment variables

Copy .env.example → .env:

cp .env.example .env


At minimum set:

SECRET_KEY=change-this
PUBLIC_BASE_URL=http://localhost:5000

The application now fails closed in production if `SECRET_KEY` or
`PUBLIC_BASE_URL` is missing. Railway's `RAILWAY_PUBLIC_DOMAIN` is accepted as
the public URL automatically. Configure working SMTP credentials so email
verification and password resets can be delivered.

5. Create the database from the committed migration

```bash
flask --app app.py db upgrade
```

Do not use `db.create_all()` for application setup. Alembic migrations are the
source of truth for both SQLite and PostgreSQL.

6. Create the first administrator

```bash
ADMIN_EMAIL=admin@example.com \
ADMIN_PASSWORD='choose-a-strong-password' \
flask --app app.py seed-admin
```

Both values are required, and weak passwords are rejected.

7. Run the app in development mode
flask --app app.py run --debug


Then visit:

http://127.0.0.1:5000

## Running in production

We use Waitress as the production server.

Run with:

python run_prod.py


Waitress will default to:

http://0.0.0.0:8000


Production environments overwrite PORT.

## Deployment options

### Heroku / Railway

A simple Procfile is included:

web: python run_prod.py


Push your repository and both platforms will auto-detect Python + install requirements.

Run `flask --app app.py db upgrade` as a release/deployment step before starting
the web process. `RUN_MIGRATIONS_ON_START=1` is available for a single-instance
deployment, but a dedicated release step is safer when multiple instances may start.

### Docker
Build image
docker build -t ownerlane .

Run container with mounted uploads
docker run -p 8000:8000 \
  -v $(pwd)/static/uploads:/app/static/uploads \
  -v $(pwd)/instance/private_uploads:/app/instance/private_uploads \
  --env-file .env \
  ownerlane

Stop the container
docker ps
docker stop <container-id>

## Environment variables

.env.example shows everything required:

Before public launch, configure the legal identity used by the footer and legal
notices:

```env
LEGAL_ENTITY_NAME=Your Legal Company Name Ltd
LEGAL_COMPANY_NUMBER=12345678
LEGAL_REGISTERED_ADDRESS=Your registered geographic address
LEGAL_ICO_NUMBER=ZA123456
LEGAL_CONTACT_EMAIL=hello@ownerlane.uk
LEGAL_LAST_UPDATED=17 July 2026
```

`LEGAL_COMPANY_NUMBER`, `LEGAL_REGISTERED_ADDRESS`, and `LEGAL_ICO_NUMBER` are
optional at runtime so local development remains simple, but the applicable
company and data-protection details should be completed before public launch.

SECRET_KEY=your-secret
PUBLIC_BASE_URL=https://ownerlane.uk
DATABASE_URL=sqlite:///care_broker.db
PRIVATE_UPLOAD_ROOT=/path/to/persistent/private-storage
DIGEST_TASK_TOKEN=your-token
WEBHOOK_TASK_TOKEN=a-different-strong-random-token

SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@example.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=1
SMTP_DEFAULT_FROM=your-email@example.com

Production Deployment Tips

Always use a strong SECRET_KEY

If running multiple containers, use Postgres instead of SQLite

Use a secrets manager (Railway/Render/Heroku env vars)

## Integrations

Signed-in users can manage API tokens, webhooks and exports at `/integrations`.
API tokens are displayed only once, stored as keyed hashes and restricted to the
scopes selected at creation. The initial API surface is read-only:

```text
GET /api/v1/me
GET /api/v1/listings
GET /api/v1/listings/<id>
GET /api/v1/introductions
```

Send tokens as `Authorization: Bearer <token>`. Listing responses use the same
confidentiality rules as the marketplace; API access does not bypass disclosure
or subscription controls.

Webhook deliveries include `X-Ownerlane-Event`, `X-Ownerlane-Delivery`,
`X-Ownerlane-Timestamp` and `X-Ownerlane-Signature`. Verify the signature as
HMAC-SHA256 of `<timestamp>.<raw request body>` using the one-time signing secret,
reject stale timestamps and compare signatures in constant time. A protected
worker should regularly call:

```text
POST /tasks/deliver-webhooks
Authorization: Bearer <WEBHOOK_TASK_TOKEN>
```

The worker attempts up to 50 due deliveries per call, does not follow redirects
and retries unsuccessful deliveries up to five total attempts.

📸 File Uploads

Listing photos are stored in:

static/uploads/


Cover image = first uploaded file or any is_cover=True.

If you deploy using Docker, remember to mount this folder or you’ll lose uploads on redeploy.

Seller and data-room documents are never served from the public static folder.
They are stored beneath `PRIVATE_UPLOAD_ROOT` (default:
`instance/private_uploads`). In Railway or another ephemeral environment, mount
a persistent volume and set `PRIVATE_UPLOAD_ROOT` to that mount path before
accepting production documents.

Completion and signature-ready documents are stored under the same private
root in `completion_docs`. Ownerlane records file integrity and party
acknowledgements; this workflow is not itself a qualified electronic-signature
service. Configure a native e-sign provider before presenting it as one.

🧪 Future Enhancements (ready when you are)

Photo delete + reorder

AI-powered listing summaries

Real-time buyer–seller messaging

Seller analytics dashboard

Data export for admin

Multi-file NDA documents

Per-region search filters

Paging and sorting on listings

🤝 Support

If you want:

Full frontend redesign (EllipseHR style)

Admin super dashboard

AI valuation engine

CRM-level tracking

Just ask and I’ll generate the full code, templates, and routes.
