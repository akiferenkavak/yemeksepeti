from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Restaurant

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # some security process not much important in our case


# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yemeksepeti.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

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
    return render_template("admin_dashboard.html")

# Restaurant dashboard page
@app.route("/restaurant/dashboard")
@login_required
@restaurant_required
def restaurant_dashboard():
    return render_template("restaurant_dashboard.html")



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


if __name__ == "__main__":
    app.run(debug=True)
