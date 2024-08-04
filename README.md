# Proyecto TFM

Este proyecto consiste en una aplicación web para subir archivos y verificar sus hashes contra bases de datos de malware. Utiliza Python, Django, SQLite y MongoDB en el BackEnd y HTML, CSS y JS en el FrontEnd.

## Instalación de Python3 y pip en Ubuntu

1. Actualiza los paquetes del sistema:
    ```bash
    sudo apt update
    sudo apt upgrade
    ```

2. Instala Python 3:
    ```bash
    sudo apt install python3
    ```

3. Instala pip para Python 3:
    ```bash
    sudo apt install python3-pip
    ```

4. Verifica la instalación:
    ```bash
    python3 --version
    pip3 --version
    ```

## Creación de un entorno virtual e instalación de requerimientos

1. Instala `virtualenv`:
    ```bash
    sudo pip3 install virtualenv
    ```

2. Crea un entorno virtual:
    ```bash
    virtualenv venv
    ```

3. Activa el entorno virtual:
    ```bash
    source venv/bin/activate
    ```

4. Instala los paquetes requeridos:
    ```bash
    pip install -r requirements.txt
    ```

5. SQLLite. Normalmente viene instalado con Python, pero si no, es necesario instalarlo para que funcione correctamente Django.

## Configuración de MongoDB con Docker para la base de datos de Hashes.

1. Instala Docker en Ubuntu.

2. Ejecuta un contenedor MongoDB:
    ```bash
    docker run --name mongodb -d -p 27017:27017 mongo:5.0
    ```

## Preparación de la base de datos y ejecución de la aplicación

1. Realiza las migraciones necesarias:
    ```bash
    python3 manage.py makemigrations
    python3 manage.py migrate
    ```

2. Ejecuta la aplicación:
    ```bash
    python3 manage.py runserver 0.0.0.0:8000
    ```

## Licencia

Este proyecto está licenciado bajo los términos de la licencia MIT y GNU 3.0
