# Usa la imagen oficial de Python
FROM python:3.10

# Establece el directorio de trabajo
WORKDIR /app

# Copia los requisitos y el código al contenedor
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Expone el puerto Flask (5000)
EXPOSE 5000

# Comando para iniciar Flask
CMD ["flask", "run", "--host=0.0.0.0"]
