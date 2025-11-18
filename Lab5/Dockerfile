# Dockerfile único para todos los contenedores
# C1, C2, C3 serán solo clientes SSH
# C4/S1 será cliente Y servidor SSH con Ubuntu 22.10

# ========================================
# Contenedor C1 - Ubuntu 16.10 (Cliente SSH)
# ========================================
FROM ubuntu:16.10 AS c1
LABEL name="C1" version="Ubuntu 16.10 - Cliente SSH"

ENV DEBIAN_FRONTEND=noninteractive

# Configurar repositorios antiguos (Correcto para esta versión)
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

# Instalar cliente OpenSSH y tcpdump
RUN apt-get update && \
    apt-get install -y openssh-client iputils-ping net-tools tcpdump && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN echo "Contenedor C1 - Ubuntu 16.10 - Cliente SSH" > /etc/container-info

CMD ["tail", "-f", "/dev/null"]

# ========================================
# Contenedor C2 - Ubuntu 18.10 (Cliente SSH)
# ========================================
FROM ubuntu:18.10 AS c2
LABEL name="C2" version="Ubuntu 18.10 - Cliente SSH"

ENV DEBIAN_FRONTEND=noninteractive

# Configurar repositorios antiguos (Correcto para esta versión)
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

# Instalar cliente OpenSSH y tcpdump
RUN apt-get update && \
    apt-get install -y openssh-client iputils-ping net-tools tcpdump && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN echo "Contenedor C2 - Ubuntu 18.10 - Cliente SSH" > /etc/container-info

CMD ["tail", "-f", "/dev/null"]

# ========================================
# Contenedor C3 - Ubuntu 20.10 (Cliente SSH)
# ========================================
FROM ubuntu:20.10 AS c3
LABEL name="C3" version="Ubuntu 20.10 - Cliente SSH"

ENV DEBIAN_FRONTEND=noninteractive

# Configurar repositorios antiguos (Correcto para esta versión)
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

# Instalar cliente OpenSSH y tcpdump
RUN apt-get update && \
    apt-get install -y openssh-client iputils-ping net-tools tcpdump && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN echo "Contenedor C3 - Ubuntu 20.10 - Cliente SSH" > /etc/container-info

CMD ["tail", "-f", "/dev/null"]

# ========================================
# Contenedor C4/S1 - Ubuntu 22.10 (Cliente Y Servidor SSH)
# ========================================
FROM ubuntu:22.10 AS c4
LABEL name="C4/S1" version="Ubuntu 22.10 - Cliente y Servidor SSH"

ENV DEBIAN_FRONTEND=noninteractive

# --- FIX 1 (CORREGIDO): 22.10 es EOL no-LTS, por lo que USA 'old-releases' ---
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list


# Instalar OpenSSH Server Y Cliente (ambos)
RUN apt-get update && \
    apt-get install -y \
    openssh-server \
    openssh-client \
    sudo \
    iputils-ping \
    net-tools \
    nano \
    vim \
    tcpdump && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Crear directorio necesario para SSH
RUN mkdir -p /var/run/sshd

# Generar las claves de host del servidor (sigue siendo necesario)
RUN ssh-keygen -A

# Crear usuario "prueba" con contraseña "prueba"
RUN useradd -m -s /bin/bash prueba && \
    echo 'prueba:prueba' | chpasswd && \
    usermod -aG sudo prueba

# Configurar SSH para permitir autenticación con contraseña (forma limpia)
RUN sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config

# Exponer puerto SSH
EXPOSE 22

# Información del contenedor
RUN echo "Contenedor C4/S1 - Ubuntu 22.10" > /etc/container-info && \
    echo "Rol: Cliente SSH Y Servidor SSH" >> /etc/container-info && \
    echo "Usuario: prueba" >> /etc/container-info && \
    echo "Contraseña: prueba" >> /etc/container-info

# Iniciar servicio SSH
CMD ["/usr/sbin/sshd", "-D"]