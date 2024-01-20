import uuid

from django.test import TestCase

# Create your tests here.


from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken

from .models import Job, Company
from apps.jobs.models import User

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
            "company_id": uuid.uuid4()
        }
        self.company = Company.objects.create(**self.company_data)

        # job_data struct
        self.job_data = {
            "job_role": "Data Scientist",
            "company": self.company,
            "description": "Join our innovative team as a Data Scientist.",
            "location": "New York, NY",
            "post_date": "2024-02-15",
            "posted": True,
            "experience": 3,
            "job_type": "part time",
            "salary": 75000.00,
            "qualifications": "Master's degree in Data Science or related field",
            "vacency_position": 2,
            "industry": "Data Science",
            "category": "Analytics",
            "is_active": True,
            "job_responsibilities": "Analyze and interpret complex data sets.",
            "skills_required": "Python, R, Machine Learning",
            "education_or_certifications": "Master's degree in Data Science or related field.",
            "employer_id": uuid.uuid4()
        }

        self.job = Job.objects.create(**self.job_data)

        # job url
        self.job_url = '/jobs/'

        # Create an instance of the APIClient and set the Authorization header
        self.client = APIClient()
        # dummy token
        self.access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwidXNlcl9pZCI6IjhmMzdlZWRiLWM2MmEtNDIyZS05NTY1LTM2NjI3OTljMjlhOSJ9.L8FwFbO1I3ohhbcPZTAD0yxEyCYFuez2k_dn3B9pQ8U"
        self.client.credentials(HTTP_ACCESSTOKEN=self.access_token)


    def test_list_jobs(self):
        # Test the list action with no filters
        response = self.client.get(self.job_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # Assuming there is one job in the database

    def test_filter_jobs(self):
        # Test the list action with filters
        response = self.client.get(self.job_url, {'location': 'Mumbai'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # Assuming one job matches the filter
