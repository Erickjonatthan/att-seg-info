from datetime import datetime
from flask import Flask, redirect, request, jsonify, render_template, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['JWT_SECRET_KEY'] = 'supersecretkey'
app.config['SECRET_KEY'] = 'mysecret'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Desabilitar a proteção CSRF apenas para desenvolvimento
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), nullable=False)
    data_criacao = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    bloco_texto = db.Column(db.String(500), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)

# Lista de possíveis Roles
roles = ['admin', 'user', 'guest']

# Rota para página inicial
@app.route('/')
def home():
    return render_template('index.html')

# Rota para página de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        new_user = User(
            nome=data['nome'],
            data_criacao=datetime.utcnow(),
            bloco_texto=data['bloco_texto'],
            username=data['username'],
            password=hashed_pw,
            role="user"
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('register.html')

# Promover a Role do Usuário
@app.route('/promote', methods=['POST'])
@jwt_required()
def promote():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role != 'admin':
        return jsonify({'message': 'Access denied'}), 403
    data = request.form
    user_to_promote = User.query.filter_by(username=data['username']).first()
    if user_to_promote:
        user_to_promote.role = 'admin'
        db.session.commit()
        return redirect(url_for('dashboard'))
    return jsonify({'message': 'User not found'}), 404

# Rota de Login
@app.route('/login', methods=['POST'])
def login():
    data = request.form
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        additional_claims = {'role': user.role}
        access_token = create_access_token(identity=user.username, additional_claims=additional_claims)
        response = redirect(url_for('dashboard'))
        response.set_cookie('access_token_cookie', access_token)
        return response
    return jsonify({'message': 'Invalid credentials'}), 401

# Rota de Login como Convidado
@app.route('/guest', methods=['GET'])
def guest():
    guest_user = User.query.filter_by(username="guest").first()
    if not guest_user:
        guest_user = User(
            nome="Guest User",
            data_criacao=datetime.utcnow(),
            bloco_texto="Guest access granted",
            username="guest",
            password=bcrypt.generate_password_hash("guest").decode('utf-8'),
            role="guest"
        )
        db.session.add(guest_user)
        db.session.commit()
    additional_claims = {'role': guest_user.role}
    access_token = create_access_token(identity=guest_user.username, additional_claims=additional_claims)
    response = redirect(url_for('dashboard'))
    response.set_cookie('access_token_cookie', access_token)
    return response

# Rota Protegida para Página de Pós-Login
@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user:
        return render_template('dashboard.html', username=user.username, role=user.role)
    return jsonify({'message': 'User not found'}), 404

# Rota Protegida com Controle de Acesso
@app.route('/admin', methods=['GET'])
@jwt_required()
def admin():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user and user.role != 'admin':
        return jsonify({'message': 'Access denied'}), 403
    return jsonify({'message': 'Welcome Admin'})

# Criptografia AES
key = b'Sixteen byte key'  # Chave de 16 bytes para AES

def encrypt_aes(data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_aes(enc_data):
    enc_data = base64.b64decode(enc_data)
    nonce, tag, ciphertext = enc_data[:16], enc_data[16:32], enc_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# Criptografia RSA
key_pair = RSA.generate(2048)
public_key = key_pair.publickey().export_key()
private_key = key_pair.export_key()

def encrypt_rsa(data):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return base64.b64encode(cipher_rsa.encrypt(data.encode())).decode()

def decrypt_rsa(enc_data):
    private_rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_rsa_key)
    return cipher_rsa.decrypt(base64.b64decode(enc_data)).decode()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
