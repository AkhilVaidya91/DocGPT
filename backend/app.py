from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import openai
import os
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this!
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(100))
    date_of_birth = db.Column(db.Date)
    gender = db.Column(db.String(20))
    document_path = db.Column(db.String(200))

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Username already exists"}), 400
    
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"msg": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    
    return jsonify({"msg": "Invalid username or password"}), 401

@app.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    return jsonify({
        "id": user.id,
        "username": user.username,
        "name": user.name,
        "date_of_birth": user.date_of_birth.isoformat() if user.date_of_birth else None,
        "gender": user.gender
    }), 200

@app.route('/user', methods=['PUT'])
@jwt_required()
def update_user():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    data = request.json
    user.name = data.get('name', user.name)
    user.date_of_birth = datetime.strptime(data.get('date_of_birth'), '%Y-%m-%d').date() if data.get('date_of_birth') else user.date_of_birth
    user.gender = data.get('gender', user.gender)
    
    db.session.commit()
    return jsonify({"msg": "User information updated successfully"}), 200

@app.route('/user', methods=['DELETE'])
@jwt_required()
def delete_user():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({"msg": "User deleted successfully"}), 200

@app.route('/onboarding', methods=['POST'])
@jwt_required()
def onboarding():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    data = request.json
    user.name = data.get('name')
    user.date_of_birth = datetime.strptime(data.get('date_of_birth'), '%Y-%m-%d').date()
    user.gender = data.get('gender')
    
    db.session.commit()
    return jsonify({"msg": "User information updated successfully"}), 200

@app.route('/chat', methods=['POST'])
@jwt_required()
def chat():
    current_user = get_jwt_identity()
    user_input = request.json.get('input')
    
    # Here you would typically call the OpenAI API
    # For demonstration, we'll just echo the input
    response = f"Echo: {user_input}"
    
    return jsonify({"response": response}), 200

@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_document():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    if 'file' not in request.files:
        return jsonify({"msg": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"msg": "No selected file"}), 400
    
    if file and file.filename.endswith('.pdf'):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        user.document_path = file_path
        db.session.commit()
        
        return jsonify({"msg": "File uploaded successfully"}), 200
    else:
        return jsonify({"msg": "Invalid file type. Please upload a PDF."}), 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)