from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from functools import wraps
from functools import wraps
from flask import render_template
from functools import wraps
from flask import session, redirect, url_for

import datetime
import jwt

app = Flask(__name__)
CORS(app)

# Configuración de MongoDB
app.config["MONGO_URI"] = "mongodb://mongo_container:27017/pro_rata"
mongo = PyMongo(app)
bcrypt = Bcrypt(app)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token faltante"}), 401

        try:
            decoded = jwt.decode(token.split(" ")[1], SECRET_KEY, algorithms=["HS256"])
            current_user = decoded["user_id"]
        except:
            return jsonify({"error": "Token inválido"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect("/login")
    return redirect("/dashboard")  


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

    # Obtener datos del formulario o JSON
    if request.is_json:  # Si el contenido es JSON
        data = request.json
    else:  # Si el contenido proviene de un formulario HTML
        data = request.form

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    # Validar que los datos estén completos
    if not name or not email or not password:
        return jsonify({"error": "Faltan datos"}), 400

    # Verificar si el nombre de usuario o email ya está registrado
    if db.users.find_one({"$or": [{"email": email}, {"name": name}]}):
        return jsonify({"error": "El email o el nombre de usuario ya están registrados"}), 400

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

    # Mensaje de éxito
    return jsonify({"message": "Usuario registrado exitosamente"}), 201


# Clave secreta para firmar los tokens (¡cámbiala por algo más seguro en producción!)
SECRET_KEY = "supersecretkey"

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/users/login", methods=["POST"])
def login():
    db = mongo.db

    # Detectar si la solicitud proviene de un formulario HTML
    if request.content_type == "application/json":
        data = request.json
        identifier = data.get("identifier")
        password = data.get("password")
    elif request.content_type == "application/x-www-form-urlencoded":
        identifier = request.form["identifier"]
        password = request.form["password"]
    else:
        return jsonify({"error": "Tipo de contenido no soportado"}), 415

    # Validar los datos
    if not identifier or not password:
        return jsonify({"error": "Faltan datos"}), 400

    # Buscar al usuario en la base de datos
    user = db.users.find_one({"$or": [{"email": identifier}, {"name": identifier}]})
    if not user or not bcrypt.check_password_hash(user["password"], password):
        return jsonify({"error": "Credenciales incorrectas"}), 401

    # Generar token JWT
    token = jwt.encode(
        {
            "user_id": str(user["_id"]),
            "email": user["email"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),  # Expira en 24 horas
        },
        SECRET_KEY,
        algorithm="HS256",
    )

    return jsonify({"token": token}), 200


@app.route("/groups/create", methods=["POST"])
@token_required
def create_group(current_user):
    db = mongo.db

    # Obtener datos del cliente
    data = request.json
    group_name = data.get("name")
    members = data.get("members")

    # Validar los datos
    if not group_name or not members:
        return jsonify({"error": "Faltan datos"}), 400

    # Crear el grupo
    group = {
        "name": group_name,
        "members": members,
        "created_by": current_user,  # ID del usuario que creó el grupo
        "created_at": datetime.datetime.utcnow(),
    }

    # Guardar el grupo en la base de datos
    group_id = db.groups.insert_one(group).inserted_id

    return jsonify({"message": "Grupo creado exitosamente", "group_id": str(group_id)}), 201

@app.route("/users")
@login_required
def users():
    db = mongo.db
    users_list = list(db.users.find({}, {"_id": 0, "name": 1, "email": 1}))  # Solo nombre y email
    return render_template("users.html", users=users_list)


@app.route("/groups")
def groups():
    db = mongo.db
    groups_list = list(db.groups.find({}, {"_id": 0, "name": 1, "members": 1}))  # Solo nombre y miembros
    return render_template("groups.html", groups=groups_list)

@app.route("/funds/register", methods=["GET", "POST"])
def register_fund():
    db = mongo.db
    if request.method == "POST":
        user_id = request.form.get("user_id")
        amount = request.form.get("amount")
        month = request.form.get("month")

        # Validar los datos
        if not user_id or not amount or not month:
            return "Todos los campos son obligatorios", 400

        # Convertir el monto a float
        try:
            amount = float(amount)
        except ValueError:
            return "El monto debe ser un número válido", 400

        # Crear el registro del fondo
        fund = {
            "user_id": user_id,
            "amount": amount,
            "month": month,
            "created_at": datetime.datetime.utcnow(),
        }

        # Guardar en la base de datos
        db.funds.insert_one(fund)
        return redirect(url_for("funds"))

    # Obtener la lista de usuarios para el formulario
    users = list(db.users.find({}, {"_id": 1, "name": 1}))
    return render_template("register_fund.html", users=users)

@app.route("/funds")
def funds():
    db = mongo.db
    funds_list = list(db.funds.find())
    # Obtener los nombres de los usuarios
    users = {user["_id"]: user["name"] for user in db.users.find({}, {"_id": 1, "name": 1})}
    return render_template("funds.html", funds=funds_list, users=users)

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login_form():
    if request.method == "POST":
        identifier = request.form["identifier"]
        password = request.form["password"]

        # Buscar al usuario en la base de datos
        user = mongo.db.users.find_one({"$or": [{"email": identifier}, {"name": identifier}]})
        if not user or not bcrypt.check_password_hash(user["password"], password):
            # Renderiza el formulario con un mensaje de error si las credenciales son incorrectas
            return render_template("login.html", error="Credenciales incorrectas")

        # Generar el token JWT
        token = jwt.encode(
            {
                "user_id": str(user["_id"]),
                "email": user["email"],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),  # Expira en 24 horas
            },
            SECRET_KEY,
            algorithm="HS256",
        )

        # Guardar el token en la sesión
        session["auth_token"] = token

        # Redirigir al dashboard o página protegida
        return redirect("/dashboard")  # Cambia "/dashboard" por la ruta que prefieras

    # Si es una solicitud GET, renderiza el formulario de login
    return render_template("login.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
