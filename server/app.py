from flask import Flask
from .config import Config
from .database import db
from .auth import auth

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    with app.app_context():
        db.create_all()

    app.register_blueprint(auth, url_prefix="/auth")

    @app.get("/")
    def index():
        return {"status": "lackson auth running"}

    return app

app = create_app()

