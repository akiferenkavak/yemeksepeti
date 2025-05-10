from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # some security process not much important in our case


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



@app.route("/")
def home():
    return render_template("index.html")


# Giriş sayfası
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        # Burada gerçek bir veritabanı kontrolü yapılmalı
        # Şimdilik basit bir örnek:
        if email == "user@example.com" and password == "password":
            session['logged_in'] = True
            session['user_type'] = 'user'
            session['email'] = email
            flash('Başarıyla giriş yaptınız!', 'success')
            return redirect(url_for('home'))
        elif email == "restaurant@example.com" and password == "password":
            session['logged_in'] = True
            session['user_type'] = 'restaurant'
            session['email'] = email
            flash('Restoran hesabınıza giriş yaptınız!', 'success')
            return redirect(url_for('restaurant_dashboard')) 
        elif email == "admin@example.com" and password == "password":
            session['logged_in'] = True
            session['user_type'] = 'admin'
            session['email'] = email
            flash('Admin hesabınıza giriş yaptınız!', 'success')
            return redirect(url_for('admin_dashboard'))
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
        # Form verilerini alın
        # Burada gerçek bir veritabanına kayıt işlemi yapılmalı
        flash('Kullanıcı hesabınız başarıyla oluşturuldu!', 'success')
        return redirect(url_for('login'))
    
    return render_template("register_user.html")

# Restoran kaydı
@app.route("/register/restaurant", methods=["GET", "POST"])
def register_restaurant():
    if request.method == "POST":
        # Form verilerini alın
        # Burada gerçek bir veritabanına kayıt işlemi yapılmalı
        flash('Restoran hesabınız başarıyla oluşturuldu! Admin onayından sonra aktif olacaktır.', 'success')
        return redirect(url_for('login'))
    
    return render_template("register_restaurant.html")

# Admin kaydı
@app.route("/register/admin", methods=["GET", "POST"])
def register_admin():
    if request.method == "POST":
        # Form verilerini alın
        # Burada gerçek bir veritabanına kayıt işlemi yapılmalı
        flash('Admin hesabınız başarıyla oluşturuldu!', 'success')
        return redirect(url_for('login'))
    
    return render_template("register_admin.html")


if __name__ == "__main__":
    app.run(debug=True)
