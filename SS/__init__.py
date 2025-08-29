import os
from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate
import stripe

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
migrate = Migrate()

def create_app(config_class=None):
    app = Flask(__name__, instance_relative_config=True)

    # Inject cart total into templates
    @app.context_processor
    def inject_cart_total():
        cart = session.get('cart', {})
        total_quantity = sum(cart.values())
        return dict(cart_total=total_quantity)

    # Load base configuration
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY'),
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL'),  # ✅ Use Supabase PostgreSQL
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        STRIPE_SECRET_KEY=os.environ.get('STRIPE_SECRET_KEY'),
        STRIPE_PUBLIC_KEY=os.environ.get('STRIPE_PUBLIC_KEY'),
    )

    # Optional: Load additional config if passed
    if config_class:
        app.config.from_object(config_class)

    # ✅ Initialize Stripe
    stripe.api_key = app.config['STRIPE_SECRET_KEY']

    # Initialize extensions with the app
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    # Setup user loader
    @login_manager.user_loader
    def load_user(user_id):
        from .models import User
        return User.query.get(int(user_id))

    login_manager.login_view = 'main.login'

    # Add Python min function to Jinja templates
    app.jinja_env.globals.update(min=min)

    # Ensure instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Register blueprints
    from .routes import main
    app.register_blueprint(main)

    return app
