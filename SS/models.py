from SS import db, bcrypt
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    
    # One-to-many relationship with Order
    orders = db.relationship('Order', backref='user', lazy=True)

    def set_password(self, raw_password):
        self.password = bcrypt.generate_password_hash(raw_password).decode('utf-8')

    def check_password(self, raw_password):
        return bcrypt.check_password_hash(self.password, raw_password)

    def __repr__(self):
        return f"<User {self.email}>"

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100), nullable=False)
    product_description = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    product_image = db.Column(db.String(), nullable=False)
    featured = db.Column(db.Boolean, default=False, nullable=False)
    price = db.Column(db.Float, nullable=False, default=0.00)
    category = db.Column(db.String, nullable=True, default='Sealed')

    def __repr__(self):
        return f"Product('{self.product_name}', '{self.product_image}', '{self.quantity}', '{self.price}')"

# Order model
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    total = db.Column(db.Float, nullable=False, default=0.00)

    # Foreign Key linking to the User model
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    # One-to-many relationship with OrderItem
    items = db.relationship('OrderItem', backref='order', lazy=True)

    # Optional tracking information
    tracking_number = db.Column(db.String(100), nullable=True)
    tracking_status = db.Column(db.String(100), nullable=True)
    tracking_carrier = db.Column(db.String(100), nullable=True)
    tracking_url = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f"Order('{self.id}', '{self.order_date}', '{self.total}', '{self.user_id}')"

# OrderItem model (many-to-many relationship between Product and Order)
class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Foreign Key to Order
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)

    # Foreign Key to Product
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)

    quantity = db.Column(db.Integer, nullable=False)
    subtotal = db.Column(db.Float, nullable=False)

    # Relationship to Product
    product = db.relationship('Product', backref='order_items', lazy=True)

    def __repr__(self):
        return f"OrderItem('{self.id}', '{self.order_id}', '{self.product_id}', '{self.quantity}', '{self.subtotal}')"
