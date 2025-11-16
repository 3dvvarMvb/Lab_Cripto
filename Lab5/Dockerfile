# Dockerfile único para todos los contenedores
# C1, C2, C3 serán solo clientes SSH
# C4/S1 será cliente Y servidor SSH con Ubuntu 22.10

# ========================================
# Contenedor C1 - Ubuntu 16.10 (Cliente SSH)
# ========================================
FROM ubuntu:16.10 AS c1
LABEL name="C1" version="Ubuntu 16.10 - Cliente SSH"

ENV DEBIAN_FRONTEND=noninteractive

# Configurar repositorios antiguos
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

# Instalar cliente OpenSSH
RUN apt-get update && \
    apt-get install -y openssh-client iputils-ping net-tools && \
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

# Configurar repositorios antiguos
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

# Instalar cliente OpenSSH
RUN apt-get update && \
    apt-get install -y openssh-client iputils-ping net-tools && \
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

# Configurar repositorios antiguos
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

# Instalar cliente OpenSSH
RUN apt-get update && \
    apt-get install -y openssh-client iputils-ping net-tools && \
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

# Configurar repositorios antiguos
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
    vim && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Crear directorio necesario para SSH
RUN mkdir -p /var/run/sshd

# Crear usuario "prueba" con contraseña "prueba"
RUN useradd -m -s /bin/bash prueba && \
    echo 'prueba:prueba' | chpasswd && \
    usermod -aG sudo prueba

# Configurar SSH para permitir autenticación con contraseña
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && \
    echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config && \
    echo 'ChallengeResponseAuthentication no' >> /etc/ssh/sshd_config

# Exponer puerto SSH
EXPOSE 22

# Información del contenedor
RUN echo "Contenedor C4/S1 - Ubuntu 22.10" > /etc/container-info && \
    echo "Rol: Cliente SSH Y Servidor SSH" >> /etc/container-info && \
    echo "Usuario: prueba" >> /etc/container-info && \
    echo "Contraseña: prueba" >> /etc/container-info

# Iniciar servicio SSH
CMD ["/usr/sbin/sshd", "-D"]