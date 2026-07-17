Care Home Broker – Buy & Sell UK Care Homes

A lightweight, mobile-friendly marketplace where care home providers can privately advertise interest to sell and verified buyers can enquire, track opportunities, and receive smart personalised recommendations.

Built with Flask + Tailwind + SQLite and deployable via Waitress, Heroku/Railway, or Docker.

✨ Features
🔐 Authentication

Buyer accounts

Seller accounts

Admin dashboard

Login/Logout with Flask-Login

🏡 Seller Portal

Create, edit, and manage listings

Upload multiple photos per listing

Choose automatic cover image

Track enquiries

Update status (Draft, Live, Under Offer, Sold)

📌 Buyer Portal

Browse listings

View full details + gallery

Submit enquiries (NDA-gated)

Personalised recommendations

Buyer profile preferences

🧠 Smart Extras

Weekly digest task endpoint

Listing matching logic

Confidential listing handling

Clean, mobile-first UI

🗂 Data

SQLite by default

Can switch to Postgres easily using DATABASE_URL

🏗 Project Structure
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

🚀 Getting Started (Development)
1. Clone the project
git clone your-repo-url-here
cd your-project-folder

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

The application now fails closed in production if `SECRET_KEY` is missing.

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

🏭 Running in Production

We use Waitress as the production server.

Run with:

python run_prod.py


Waitress will default to:

http://0.0.0.0:8000


Production environments overwrite PORT.

☸ Deployment Options
🔹 Heroku / Railway (Procfile)

A simple Procfile is included:

web: python run_prod.py


Push your repository and both platforms will auto-detect Python + install requirements.

Run `flask --app app.py db upgrade` as a release/deployment step before starting
the web process. `RUN_MIGRATIONS_ON_START=1` is available for a single-instance
deployment, but a dedicated release step is safer when multiple instances may start.

🔹 Docker Deployment
Build image
docker build -t care-broker .

Run container with mounted uploads
docker run -p 8000:8000 \
  -v $(pwd)/static/uploads:/app/static/uploads \
  -v $(pwd)/instance/private_uploads:/app/instance/private_uploads \
  --env-file .env \
  care-broker

Stop the container
docker ps
docker stop <container-id>

⚙ Environment Variables

.env.example shows everything required:

SECRET_KEY=your-secret
DATABASE_URL=sqlite:///care_broker.db
DIGEST_TASK_TOKEN=your-token

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

📸 File Uploads

Listing photos are stored in:

static/uploads/


Cover image = first uploaded file or any is_cover=True.

If you deploy using Docker, remember to mount this folder or you’ll lose uploads on redeploy.

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
