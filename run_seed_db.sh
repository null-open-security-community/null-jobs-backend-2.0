#!/bin/bash

echo "Here Print Me!"
python manage.py loaddata utils/seed/company.json
python manage.py loaddata utils/seed/job.json
python manage.py loaddata utils/seed/userprofile.json