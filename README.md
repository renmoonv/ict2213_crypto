# ict2213_applied_crypto

Download Docker Engine
1. install docker engine inside WSL
sudo apt update
sudo apt install docker.io docker-compose
---------------------------------------------------------------------------------------------------------------
2. start docker (get it to start running)
sudo service docker start
- to verify:
docker --version
- test:
docker run hello-world

(if permission denied)
sudo usermod -aG docker $USER
exit
groups -> should see docker
docker run hello-world
---------------------------------------------------------------------------------------------------------------
3. start docker and connect to MariaDB: USE WSL
- to start docker: cd to your project directory in wsl terminal
docker-compose up -d

(health: starting) -> MariaDB is starting. Wait until (health: healthy)
---------------------------------------------------------------------------------------------------------------
4. Connect to MariaDB
- to enter the container:
docker exec -it applied_crypto_db mariadb -u root -p
(password: cryptopass)

 docker exec -it applied_crypto_db mariadb -u crypto_user -p
(password: cryptopass)
---------------------------------------------------------------------------------------------------------------

!! Any updates to db_init/init.sql , models.py, app.py :
docker-compose down
docker volume rm ict2213_crypto_mariadb_data
docker-compose up -d

- To get MariaDB to re-run init.sql, must remove the active volume. Else MariaDB keeps the existing data.
