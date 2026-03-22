# ict2213_applied_crypto

Install and Setup Docker Engine
---------------------------------------------------------------------------------------------------------------
1. Install Docker Engine inside WSL
- sudo apt update
- sudo apt install docker.io docker-compose

2. Start Docker Service (get it to start running)
- sudo service docker start

To verify docker version:
- docker --version

Test:
- docker run hello-world

(if permission denied)
- sudo usermod -aG docker $USER
- exit
- groups

 -> should see docker
- docker run hello-world

3. Start docker and connect to MariaDB (using WSL):

Change directory to your project folder in WSL terminal

To start docker: 
- docker-compose up -d

(health: starting) -> MariaDB is starting. Wait until (health: healthy)

4. Connect to MariaDB

To enter the container:
- docker exec -it applied_crypto_db mariadb -u root -p
- docker exec -it applied_crypto_db mariadb -u crypto_user -p

(password: cryptopass)


!! Any updates to db_init/init.sql, models.py, app.py need to rerun:
- docker-compose down
- docker volume rm ict2213_crypto_mariadb_data
- docker-compose up -d

To get MariaDB to re-run init.sql, must remove the active volume. Otherwise MariaDB keeps the existing data.

To access Adminer GUI to view database
---------------------------------------------------------------------------------------------------------------
1. Go to 
http://localhost:8080
to open db viewer gui

2. Login:

System: MySQL

Server: db

Username: crypto_user

Password: cryptopass

Database: applied_crypto

Run application:
---------------------------------------------------------------------------------------------------------------
1. Cd to client folder
2. Run in terminal:
- python3 app.py
