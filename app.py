from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import base64
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['JWT_SECRET_KEY'] = 'supersecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)

# Rota para página inicial
@app.route('/')
def home():
    return render_template('index.html')

# Rota de Registro
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_pw, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'})

# Rota de Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'username': user.username, 'role': user.role})
        return jsonify({'token': access_token})
    return jsonify({'message': 'Invalid credentials'}), 401

# Rota Protegida com Controle de Acesso
@app.route('/admin', methods=['GET'])
@jwt_required()
def admin():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
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
