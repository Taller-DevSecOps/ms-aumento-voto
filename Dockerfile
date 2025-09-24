# Usar una imagen base mínima de Linux
FROM alpine:latest

# Establecer el directorio de trabajo
WORKDIR /example

# Copiar todos los archivos locales al contenedor (opcional)
COPY . /example

# Comando por defecto: mostrar un mensaje
CMD ["echo", "¡Este es un contenedor básico!"]
