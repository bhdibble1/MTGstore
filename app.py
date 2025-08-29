from SS.app import create_app
from flask_migrate import Migrate
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from SS.models import db, Product, User, Order, OrderItem
from flask_login import current_user

app = create_app()

# Custom AdminModelView that restricts access to admin users only
class AdminModelView(ModelView):
    def is_accessible(self):
        # Allow access only if user is authenticated and is an admin
        return current_user.is_authenticated and current_user.email == 'Bhdibble@gmail.com'

# Initialize Flask-Admin
admin = Admin(app, name='Admin Panel', template_mode='bootstrap4')

# Add views to Flask-Admin using the custom AdminModelView for each model
admin.add_view(AdminModelView(User, db.session))
admin.add_view(AdminModelView(Product, db.session))
admin.add_view(AdminModelView(Order, db.session))
admin.add_view(AdminModelView(OrderItem, db.session))

# Start the app
if __name__ == '__main__':
    app.run(debug=True)
