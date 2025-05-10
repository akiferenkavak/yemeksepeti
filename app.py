from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Restaurant, Order, OrderItem
from flask_migrate import Migrate


app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # some security process not much important in our case


# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yemeksepeti.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Flask-Migrate'i başlat
migrate = Migrate(app, db)

# Create tables within app context
with app.app_context():
    db.create_all()




# Kullanıcı tipi kontrol fonksiyonları //// kimin hangi sayfaya girip giremeyeceğini kontrol eden decoratorlar
# bizim 3 kullanıcı tipimiz var admin, restaurant ve user
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Bu sayfaya erişmek için giriş yapmalısınız', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_type' not in session or session['user_type'] != 'admin':
            flash('Bu sayfaya erişmek için admin yetkisi gereklidir', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def restaurant_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_type' not in session or session['user_type'] != 'restaurant':
            flash('Bu sayfaya erişmek için restoran yetkisi gereklidir', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function


# Admin dashboard page
@app.route("/admin/dashboard")
@login_required
@admin_required
def admin_dashboard():
    # Count pending restaurant approvals
    pending_count = Restaurant.query.filter_by(is_approved=False).count()
    return render_template("admin_dashboard.html", pending_count=pending_count)

# Restaurant dashboard page
@app.route("/restaurant/dashboard")
@login_required
@restaurant_required
def restaurant_dashboard():
    # Giriş yapmış restoranın bilgilerini getir
    restaurant = Restaurant.query.filter_by(user_id=session['user_id']).first()
    return render_template("restaurant_dashboard.html", restaurant=restaurant)



@app.route("/")
def home():
    return render_template("index.html")


# Giriş sayfası
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        # Check if user exists in database
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['user_type'] = user.user_type
            session['user_id'] = user.id
            session['email'] = user.email
            session['name'] = user.name
            
            flash(f'Hoş geldiniz, {user.name}!', 'success')
            
            if user.user_type == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.user_type == 'restaurant':
                return redirect(url_for('restaurant_dashboard'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Geçersiz email veya şifre!', 'danger')
    
    return render_template("login.html")


# Çıkış yap
@app.route("/logout")
def logout():
    session.clear()
    flash('Başarıyla çıkış yaptınız', 'success')
    return redirect(url_for('home'))


 #Kullanıcı kaydı
@app.route("/register/user", methods=["GET", "POST"])
def register_user():
    if request.method == "POST":
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        phone = request.form.get('phone')
        address = request.form.get('address')
        
        # Check if passwords match
        if password != confirm_password:
            flash('Şifreler eşleşmiyor!', 'danger')
            return redirect(url_for('register_user'))
        
        # Check if email is already registered
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Bu email adresi zaten kayıtlı!', 'danger')
            return redirect(url_for('register_user'))
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            phone=phone,
            address=address,
            user_type='user'
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Kullanıcı hesabınız başarıyla oluşturuldu!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Kayıt sırasında bir hata oluştu: {str(e)}', 'danger')
            return redirect(url_for('register_user'))
    
    return render_template("register_user.html")

# Restoran kaydı
@app.route("/register/restaurant", methods=["GET", "POST"])
def register_restaurant():
    if request.method == "POST":
        owner_name = request.form.get('owner_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        phone = request.form.get('phone')
        address = request.form.get('address')
        restaurant_name = request.form.get('restaurant_name')
        cuisine_type = request.form.get('cuisine_type')
        tax_id = request.form.get('tax_id')
        
        # Check if passwords match
        if password != confirm_password:
            flash('Şifreler eşleşmiyor!', 'danger')
            return redirect(url_for('register_restaurant'))
        
        # Check if email is already registered
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Bu email adresi zaten kayıtlı!', 'danger')
            return redirect(url_for('register_restaurant'))
        
        # Check if tax_id is already registered
        existing_restaurant = Restaurant.query.filter_by(tax_id=tax_id).first()
        if existing_restaurant:
            flash('Bu vergi numarası zaten kayıtlı!', 'danger')
            return redirect(url_for('register_restaurant'))
        
        try:
            # Create new user with restaurant type
            hashed_password = generate_password_hash(password)
            new_user = User(
                name=owner_name,
                email=email,
                password=hashed_password,
                phone=phone,
                address=address,
                user_type='restaurant'
            )
            
            db.session.add(new_user)
            db.session.flush()  # Get the user ID before committing
            
            # Create new restaurant linked to this user
            new_restaurant = Restaurant(
                user_id=new_user.id,
                restaurant_name=restaurant_name,
                cuisine_type=cuisine_type,
                tax_id=tax_id,
                is_approved=False  # Needs admin approval
            )
            
            db.session.add(new_restaurant)
            db.session.commit()
            
            flash('Restoran hesabınız başarıyla oluşturuldu! Admin onayından sonra aktif olacaktır.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Kayıt sırasında bir hata oluştu: {str(e)}', 'danger')
            return redirect(url_for('register_restaurant'))
    
    return render_template("register_restaurant.html")

# Admin kaydı
@app.route("/register/admin", methods=["GET", "POST"])
def register_admin():
    if request.method == "POST":
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        admin_code = request.form.get('admin_code')
        
        # Check if passwords match
        if password != confirm_password:
            flash('Şifreler eşleşmiyor!', 'danger')
            return redirect(url_for('register_admin'))
        
        # Verify admin code (in a real application, this would be more secure)
        if admin_code != "secret_admin_code":
            flash('Geçersiz admin kodu!', 'danger')
            return redirect(url_for('register_admin'))
        
        # Check if email is already registered
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Bu email adresi zaten kayıtlı!', 'danger')
            return redirect(url_for('register_admin'))
        
        # Create new admin user
        hashed_password = generate_password_hash(password)
        new_admin = User(
            name=name,
            email=email,
            password=hashed_password,
            user_type='admin'
        )
        
        try:
            db.session.add(new_admin)
            db.session.commit()
            flash('Admin hesabınız başarıyla oluşturuldu!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Kayıt sırasında bir hata oluştu: {str(e)}', 'danger')
            return redirect(url_for('register_admin'))
    
    return render_template("register_admin.html")





# Restaurant approval action (approve/reject)
@app.route("/admin/restaurant-action/<int:restaurant_id>", methods=["POST"])
@login_required
@admin_required
def restaurant_action(restaurant_id):
    action = request.form.get('action')
    restaurant = Restaurant.query.get_or_404(restaurant_id)
    
    if action == 'approve':
        restaurant.is_approved = True
        db.session.commit()
        flash(f'{restaurant.restaurant_name} onaylandı!', 'success')
    elif action == 'reject':
        # You might want to add a notification system later
        # For now, let's just remove the restaurant and its owner
        user_id = restaurant.user_id
        db.session.delete(restaurant)
        user = User.query.get(user_id)
        db.session.delete(user)
        db.session.commit()
        flash(f'{restaurant.restaurant_name} reddedildi!', 'danger')
    
    return redirect(url_for('restaurant_approvals'))




# Restaurant approval page
@app.route("/admin/restaurant-approvals", methods=["GET"])
@login_required
@admin_required
def restaurant_approvals():
    # Get all pending restaurant approvals
    pending_restaurants = Restaurant.query.filter_by(is_approved=False).all()
    # Join with user data to get owner information
    restaurant_data = []
    for restaurant in pending_restaurants:
        owner = User.query.get(restaurant.user_id)
        restaurant_data.append({
            'restaurant': restaurant,
            'owner': owner
        })
    return render_template("restaurant_approvals.html", restaurant_data=restaurant_data)

# Admin orders page
@app.route("/admin/orders", methods=["GET"])
@login_required
@admin_required
def admin_orders():
    # Get filters from query parameters
    status_filter = request.args.get('status', 'all')
    restaurant_id = request.args.get('restaurant_id', 'all')
    sort_by = request.args.get('sort_by', 'date')
    sort_dir = request.args.get('sort_dir', 'desc')
    
    # Base query
    orders_query = Order.query
    
    # Apply filters
    if status_filter != 'all':
        orders_query = orders_query.filter(Order.status == status_filter)
    
    if restaurant_id != 'all' and restaurant_id.isdigit():
        orders_query = orders_query.filter(Order.restaurant_id == int(restaurant_id))
    
    # Apply sorting
    if sort_by == 'date':
        if sort_dir == 'asc':
            orders_query = orders_query.order_by(Order.order_date.asc())
        else:
            orders_query = orders_query.order_by(Order.order_date.desc())
    elif sort_by == 'amount':
        if sort_dir == 'asc':
            orders_query = orders_query.order_by(Order.total_amount.asc())
        else:
            orders_query = orders_query.order_by(Order.total_amount.desc())
    elif sort_by == 'status':
        if sort_dir == 'asc':
            orders_query = orders_query.order_by(Order.status.asc())
        else:
            orders_query = orders_query.order_by(Order.status.desc())
    
    # Execute query
    orders = orders_query.all()
    
    # Get all restaurants for the filter dropdown
    restaurants = Restaurant.query.filter_by(is_approved=True).all()
    
    # Define possible statuses for filter dropdown
    statuses = ['pending', 'preparing', 'delivering', 'delivered', 'cancelled']
    
    return render_template(
        "admin_orders.html", 
        orders=orders, 
        restaurants=restaurants,
        statuses=statuses,
        current_status=status_filter,
        current_restaurant=restaurant_id,
        current_sort_by=sort_by,
        current_sort_dir=sort_dir
    )


if __name__ == "__main__":
    app.run(debug=True)
