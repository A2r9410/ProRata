from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from flask_cors import CORS
from flask_bcrypt import Bcrypt

app = Flask(__name__)
CORS(app)

# Configuración de MongoDB
app.config["MONGO_URI"] = "mongodb://mongo_container:27017/pro_rata"
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

@app.route("/")
def home():
    return jsonify({"message": "¡Bienvenido a ProRata!"})

@app.route("/test-db")
def test_db():
    # Insertar un documento de prueba
    db = mongo.db
    test_collection = db.test
    test_collection.insert_one({"test_key": "test_value"})
    return jsonify({"message": "Conexión con MongoDB exitosa."})

@app.route("/users/register", methods=["POST"])
def register():
    db = mongo.db

    # Obtener datos del cliente
    data = request.json
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    # Validar que los datos estén completos
    if not name or not email or not password:
        return jsonify({"error": "Faltan datos"}), 400

    # Verificar si el email ya está registrado
    if db.users.find_one({"email": email}):
        return jsonify({"error": "El email ya está registrado"}), 400

    # Encriptar la contraseña
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    # Crear el usuario
    user = {
        "name": name,
        "email": email,
        "password": hashed_password,
        "groups": []
    }
    db.users.insert_one(user)

    return jsonify({"message": "Usuario registrado exitosamente"}), 201

import jwt
import datetime

# Clave secreta para firmar los tokens (¡cámbiala por algo más seguro en producción!)
SECRET_KEY = "supersecretkey"

@app.route("/users/login", methods=["POST"])
def login():
    db = mongo.db

    # Obtener datos del cliente
    data = request.json
    email = data.get("email")
    password = data.get("password")

    # Validar que los datos estén completos
    if not email or not password:
        return jsonify({"error": "Faltan datos"}), 400

    # Buscar al usuario en la base de datos
    user = db.users.find_one({"email": email})
    if not user:
        return jsonify({"error": "El usuario no existe"}), 404

    # Verificar la contraseña
    if not bcrypt.check_password_hash(user["password"], password):
        return jsonify({"error": "Credenciales incorrectas"}), 401

    # Generar el token JWT
    token = jwt.encode(
        {
            "user_id": str(user["_id"]),
            "email": user["email"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)  # Expira en 24 horas
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    return jsonify({"token": token}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
