# User service

User service is one of the **microservices**.

He is responsible for registration, user identification in the system, allows you to create a new user, get information about a user who already exists. It also allows you to modify or delete user data.

Allows you to obtain a user token for further verification of its permissions. It can also send emails confirming registration or password changes.

![GitHub repo size](https://img.shields.io/github/repo-size/ss-o-furda/part_of_proj-user_service)

## Installation

Clone the repository and go to the directory:
```bash
git clone https://github.com/ss-o-furda/part_of_proj-user_service.git
cd part_of_proj-user_service
```
Create a virtual environment and use the package manager [pip](https://pip.pypa.io/en/stable/) to install the libraries that are required:
```bash
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```
After, install the **common_lib** required for http-responses and sending emails:
```bash
pip install -e common_lib/
```
You also need [PostgreSQL](https://www.postgresql.org/) to work.
```bash
cd user_service
python manage.py db init
python manage.py db migrate
python manage.py db upgrade
```
To check:
```bash
psql -U postgres
\c userdb
\dt
```
and if you see:
```bash
              List of relations
 Schema |      Name       | Type  |  Owner   
--------+-----------------+-------+----------
 public | alembic_version | table | postgres
 public | users           | table | postgres
 (2 rows)
```

#### Congratulations, you're great!

Now you can run application. 

Just type ```python user_service/app.py``` and open ```http://0.0.0.0:8000``` in your browser.


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.