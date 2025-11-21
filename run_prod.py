import os
from waitress import serve
from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    # You can tweak threads if needed, but this is a sane default
    serve(app, host="0.0.0.0", port=port)
