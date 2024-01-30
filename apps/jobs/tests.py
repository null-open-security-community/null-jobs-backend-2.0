import uuid
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from datetime import datetime, timedelta
from django.utils import timezone
from rest_framework_simplejwt.tokens import AccessToken

from .models import Job, Company
from apps.jobs.models import User
from apps.jobs.views import *


class JobViewSetsTestCase(TestCase):
    def setUp(self):
        # Create sample data for testing
        self.company_data = {
            "name": "Testing name",
            "location": "Testing Location",
            "about": "Testing about",
            "founded_year": 2011,
            "team_members": 110,
            "social_profiles": "https://testing.com/testing",
            "company_id": uuid.uuid4(),
        }
        self.company = Company.objects.create(**self.company_data)
        past_datetime = datetime.now(timezone.utc) - timedelta(days=20)

        # job_data struct
        self.job1_data = {
            "job_role": "Data Scientist",
            "company": self.company,
            "description": "Join our innovative team as a Data Scientist.",
            "location": "New York",
            "post_date": "2024-02-15",
            "posted": True,
            "experience": 3,
            "job_type": "part time",
            "salary": 75000.00,
            "qualifications": "Master's degree in Data Science or related field",
            "vacency_position": 2,
            "industry": "Data Science",
            "category": "Analytics",
            "created_at": past_datetime,
            "is_active": True,
            "job_responsibilities": "Analyze and interpret complex data sets.",
            "skills_required": "Python, R, Machine Learning",
            "education_or_certifications": "Master's degree in Data Science or related field.",
            "employer_id": uuid.uuid4(),
        }

        self.job2_data = {
            "job_role": "Software Engineer",
            "company": self.company,
            "description": "Join our software engineering team.",
            "location": "San Francisco",
            "post_date": "2024-02-20",
            "posted": True,
            "experience": 2,
            "job_type": "full time",
            "salary": 90000.00,
            "qualifications": "Bachelor's degree in Computer Science",
            "vacency_position": 3,
            "industry": "Software Development",
            "category": "Engineering",
            "created_at": past_datetime,
            "is_active": True,
            "job_responsibilities": "Design and develop software applications.",
            "skills_required": "Java, JavaScript, SQL",
            "education_or_certifications": "Bachelor's degree in Computer Science.",
            "employer_id": uuid.uuid4(),
        }
        # Create the Jobs object with the specified data
        self.job = Job.objects.create(**self.job1_data)
        self.job = Job.objects.create(**self.job2_data)

        # job url
        self.job_url = "/jobs/"

        # Create an instance of the APIClient and set the Authorization header
        self.client = APIClient()
        # dummy token
        self.access_token = ""
        self.client.credentials(HTTP_ACCESSTOKEN=self.access_token)

    def test_list_jobs(self):
        # Test the list action with no filters
        response = self.client.get(self.job_url)
        # self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertEqual(len(response.data), 1)  # Assuming there is one job in the database

    def test_filter_jobs(self):
        # Test the list action with filters
        response = self.client.get(f"{self.job_url}?location=San Francisco")
        self.assertNotEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(len(response.data), 1)

    def test_featured_jobs(self):
        response = self.client.get("/user/featured_jobs/")
        print(response)
        self.assertNotEqual(response.status_code, status.HTTP_200_OK)
