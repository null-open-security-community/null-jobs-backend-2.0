# null-jobs-backend
Null Jobs Backend Revamping: We are building Null Jobs 2.0, that will have django backend rest framework in backend and react in frontend.

Please feel free to contribute and reach out to us.

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

<hr>

## Test cases setup:

lets migrate the db first for testing env
<br>
```
python manage.py migrate --settings=null_jobs_backend.test_settings
```


whenever you make changes to your models, you need to create new migrations and apply them to both your development and testing databases to keep the schemas in sync
```
python manage.py makemigrations --settings=null_jobs_backend.test_settings
```

In order to run the test cases over test_db
```
python manage.py test --settings=null_jobs_backend.test_settings
```

## Contributors and sponsors

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-4-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

Thanks goes to these wonderful people
([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/hims1911"><img src="https://avatars.githubusercontent.com/u/26831864?v=4?s=100" width="100px;" alt="Himanshu Sharma"/><br /><sub><b>Himanshu Sharma</b></sub></a><br /><a href="https://github.com/null-open-security-community/null-jobs-backend-2.0/commits/main/?author=hims1911" title="Code">💻</a> <a href="https://github.com/null-open-security-community/null-jobs-backend-2.0/commits/main/?author=hims1911" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/YogeshUpdhyay"><img src="https://avatars.githubusercontent.com/u/53992168?v=4?s=100" width="100px;" alt="Yogesh Upadhyay"/><br /><sub><b>Yogesh Upadhyay</b></sub></a><br /><a href="https://github.com/yezz123/authx/issues?q=author%3AYogeshUpdhyay" title="Bug reports">🐛</a><a href="https://github.com/null-open-security-community/null-jobs-backend-2.0/commits/main/?author=YogeshUpdhyay" title="Code">💻</a> <a href="https://github.com/null-open-security-community/null-jobs-backend-2.0/commits/main/?author=YogeshUpdhyay" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Himan10"><img src="https://avatars.githubusercontent.com/u/33115688?v=4?s=100" width="100px;" alt="Himanshu Bhatnagar"/><br /><sub><b>Himanshu Bhatnagar</b></sub></a><br /><a href="https://github.com/null-open-security-community/null-jobs-backend-2.0/commits/main/?author=Himan10" title="Code">💻</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the
[all-contributors](https://github.com/all-contributors/all-contributors)
specification. Contributions of any kind welcome!

## License

This project is licensed under the terms of the MIT License.
