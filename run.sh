#!/bin/bash

python manage.py makemigrations
python manage.py makemigrations apps.jobs
python manage.py makemigrations apps.accounts
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
