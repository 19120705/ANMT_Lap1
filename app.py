import email
from flask import Flask, redirect, url_for, render_template, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
import hashlib
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
# from .encrypt import encrypt



from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
# from bs4 import Tag
import hashlib


def generate_RSA(bits=2048):
    '''
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    '''
    #from Crypto.PublicKey import RSA 
    new_key = RSA.generate(bits, e=65537) 
    public_key = new_key.publickey().exportKey("PEM") 
    private_key = new_key.exportKey("PEM") 
    return public_key,private_key

#ENCRYPT K_PRI WITH AES
def AES_encrypt(key,message):
    cipher=AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    #ciphertext,tag =cipher.encrypt_and_digest(message.encode('ascii'))
    ciphertext,tag =cipher.encrypt_and_digest(message)
    return nonce, ciphertext, tag

def AES_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce )
    plaintext = cipher.decrypt(ciphertext)
    try: 
        cipher.verify(tag)
        return plaintext
    except:
        return False













app = Flask(__name__)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

#-----------------------------MODELS---------------------------------------------->

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(40), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    salt = db.Column(db.String(32), nullable=False)

class ProfileUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(40), nullable=False, unique=True)
    name = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.String(10))
    address = db.Column(db.String(50))
    date = db.Column(db.String(20))
    kpublic = db.Column(db.String(256), nullable=False)
    kprivate = db.Column(db.String(256), nullable=False)

class AESKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(40), nullable=False, unique=True)
    nonce = db.Column(db.String(256), nullable=False)
    tag = db.Column(db.String(256), nullable=False)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



#-----------------------FORMS------------------------------------------------------>

class RegisterForm(FlaskForm):

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    
    email = StringField(validators=[
                           InputRequired(), Length(min=11, max=40)], render_kw={"placeholder": "Email"})

    # fullname = StringField(validators=[
    #                        InputRequired(), Length(min=11, max=40)], render_kw={"placeholder": "Full name"})           

    # address = StringField(validators=[
    #                        InputRequired(), Length(min=11, max=40)], render_kw={"placeholder": "Address"})

    # phone = StringField(validators=[
    #                        InputRequired(), Length(10)], render_kw={"placeholder": "Phone"})   
    submit = SubmitField('Register')
    # Check email exist
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'That email already exists. Please choose a different one.')
    

class LoginForm(FlaskForm):
    email = StringField(validators=[
                           InputRequired(), Length(min=11, max=40)], render_kw={"placeholder": "Email"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=request.form["email"]).first()
        if user:
            if hashlib.scrypt(request.form["password"].encode(),
             salt=user.salt, n=2**14, r=8, p=1, dklen=32)==user.password:
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = ProfileUser()
    email = current_user.email
    name_to_show = ProfileUser.query.filter_by(email=email).first()
    return render_template('dashboard.html', form = form, name_to_show = name_to_show)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        salt= get_random_bytes(32)
        password = request.form["password"]
        hashed_password = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        new_user = User(email=request.form["email"], password=hashed_password, salt = salt)
        db.session.add(new_user)
        kpublic, kprivate = generate_RSA()
        nonce,ciphertext,tag =AES_encrypt(hashed_password,kprivate)
        new_aeskey = AESKey(email=request.form["email"], nonce = nonce, tag = tag)
        db.session.add(new_aeskey)
        new_profile = ProfileUser(email=request.form["email"], name=request.form["name"],
         phone=request.form["phone"], address = request.form["address"], date =  request.form["date"]
         ,kpublic = kpublic, kprivate = ciphertext)
        db.session.add(new_profile)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html', form=form)




if __name__ == "__main__":
    app.run(debug=True)
