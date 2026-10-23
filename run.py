"""Start the dashboard: python run.py, then open http://127.0.0.1:5000"""
import os

from soc.app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")))
