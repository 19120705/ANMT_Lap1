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
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
# from bs4 import Tag
import hashlib
import binascii


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


#Encrypt file
def test_encypt(session_key,enc_session_key,filename):
    with open(filename, 'rb') as f:
        data= f.read()
    file_out = open(filename+"_encrypt", "wb")
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    file_out.close()

def test_decrypt(private_key,filename):
    file_in = open(filename+"_encrypt", "rb")
    enc_session_key, nonce, tag, ciphertext = [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    with open(filename+"_decrypt", 'wb') as out:
        out.write(data)






















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
    email = current_user.email
    profile = ProfileUser.query.filter_by(email=current_user.email).first()
    return render_template('dashboard.html', profile = profile)


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
        # create public key and private key
        kpublic, kprivate = generate_RSA()
        nonce,ciphertext,tag =AES_encrypt(hashed_password,kprivate)
        # encrypt private key with AES
        new_aeskey = AESKey(email=request.form["email"], nonce = nonce, tag = tag)
        db.session.add(new_aeskey)
        new_profile = ProfileUser(email=request.form["email"], name=request.form["name"],
         phone=request.form["phone"], address = request.form["address"], date =  request.form["date"]
         ,kpublic = kpublic, kprivate = ciphertext)
        db.session.add(new_profile)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@ app.route('/uploadfile', methods=['GET', 'POST'])
def upload():
    return render_template("uploadfile.html")  







@app.route('/success', methods = ['GET', 'POST'])  
def success():  
    if request.method == 'POST':

        session_key = get_random_bytes(16)
        #print(session_key)

        # Encrypt the session key with the public RSA key:
        profile = ProfileUser.query.filter_by(email=current_user.email).first()
        aes = AESKey.query.filter_by(email=current_user.email).first()
        recipient_key = RSA.import_key(profile.kpublic)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        f = request.files['file']  
        f.save(f.filename)

        test_encypt(session_key,enc_session_key,f.filename)

        private_key = AES_decrypt(current_user.password, aes.nonce, profile.kprivate, aes.tag)
        private_key_real = RSA.import_key(private_key)
        test_decrypt(private_key_real,f.filename)

        return render_template("success.html", name = f.filename)  




def sign_file(filename,private_key):
    with open(filename, 'rb') as f:
        msg_b = f.read()
    #msg = b'A message for signing'
    hash = SHA256.new(msg_b)
    signer = PKCS115_SigScheme(private_key)
    signature = signer.sign(hash)
    file_out = open(filename+".sig", "wb")
    [ file_out.write(x) for x in (signature,msg_b) ]
    file_out.close()



@app.route('/signature', methods = ['GET','POST'])  
def sig():
    if request.method == 'POST':
        f = request.files['file']
        profile = ProfileUser.query.filter_by(email=current_user.email).first()
        aes = AESKey.query.filter_by(email=current_user.email).first()
        private_key = AES_decrypt(current_user.password, aes.nonce, profile.kprivate, aes.tag)
        private_key_real = RSA.import_key(private_key)  
        sign_file(f.filename, private_key_real)
        return render_template("sigsuccess.html")
    return render_template("signature.html") 


@app.route('/checksig', methods = ['GET','POST'])
@login_required
def check_sig():
    return render_template("checksig.html") 


def verify_file(sign_filename,filename,public_key):
    #msg = b'hello vn 123 @'
    with open(filename, 'rb') as f:
        msg= f.read()
    
    #print(msg)
    
    file_in = open(sign_filename, "rb")
    signature,msg_2 = [file_in.read(x) for x in (256, -1) ]
    #print(msg_2)
    #print(signature)
    hash = SHA256.new(msg)
    signer = PKCS115_SigScheme(public_key)
    try:
        signer.verify(hash, signature)
        return True
    except:
        return False



@app.route('/check', methods = ['GET','POST'])
@login_required
def check():
    if request.method == 'POST':
        arr  = ProfileUser.query.all()
        filename1 = request.form["filename"]
        filename2 = request.form["filename2"]
        for i in arr:
            if verify_file(filename2, filename1, RSA.import_key(i.kpublic)):
                return render_template("check.html",i=i)
        flash("Not find")


     



if __name__ == "__main__":
    app.run(debug=True)
