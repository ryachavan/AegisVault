"""Entry point — loads .env then starts the app factory.

Usage:
    python run.py            (dev server on http://localhost:5000)
    flask run                (after: set FLASK_APP=run.py)
"""

from dotenv import load_dotenv

load_dotenv()  # reads .env into os.environ before config is loaded

from app import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
