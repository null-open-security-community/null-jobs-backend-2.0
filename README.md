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

# load the seed files
Directory: utils/seed
Command: `python manage.py loaddata utils/seed/filename.json
NOTE: Load the seed files only in this order
1. Company
2. Job
3. User
Because, in a recent change, we made User.job_id as a temporary field in the User model,
so in case where the User.job_id isn't present (maybe the job seeker hasn't applied to any job or isn't working yet),
so especially in such cases, loading User seed file before Job seed file can result in error.

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
