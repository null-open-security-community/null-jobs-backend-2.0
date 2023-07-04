# null-jobs-backend
null jobs backend revamping

## Setup
```
# creating virtualenv
python -m venv venv
source venv/bin/activate

# source the env file in terminal
set -a
source ./.env
set +a

# installing requirement
pip install -r requirements.txt

# start the server
python manage.py runserver
```

Note: Swagger url will be available at
http://localhost:8000/api/docs
