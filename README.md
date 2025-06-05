#### Initial Postgres local setup
Install Postgres.app
Install libpq via homebrew

psql -U postgres
create database greenlight;
\c greenlight
CREATE ROLE greenlight WITH LOGIN PASSWORD 'changeme';
CREATE EXTENSION IF NOT EXISTS citext;
exit

##### Test connection with new user
