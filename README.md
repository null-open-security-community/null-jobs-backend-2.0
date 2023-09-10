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

# install pre-commit
pip install pre-commit

# start the server
python manage.py runserver
```

Note: Swagger url will be available at
http://localhost:8000/api/docs

## Setting up OAuth 2.0
- Get your OAuth Client id and Secret from
https://support.google.com/cloud/answer/6158849?hl=en

- Paste the OAuth Credentials in .env file
  ```
  # Google auth Credentials
  GOOGLE_OAUTH_CLIENT_ID='google client id'
  GOOGLE_OAUTH_SECRET='google secret'
  ```
