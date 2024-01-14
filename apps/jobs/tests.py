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
            "name": "Test Company",
            "location": "Test Location",
            "about": "A test company for unit testing",
            "company_id": uuid.uuid4(),
        }
        self.company = Company.objects.create(**self.company_data)

        # job_data struct
        self.job_data = {
            "job_role": "Software Engineer",
            "company": self.company,
            "description": "Sample job description",
            "location": "Mumbai",
            "post_date": "2023-01-01",
            "posted": True,
            "experience": 2,
            "employer_id": uuid.uuid4(),
            "job_type": "Full-Time",
            "salary": 75000.00,
            "qualifications": "Bachelor's degree in Computer Science",
            "vacency_position": 3,
            "industry": "Technology",
            "job_responsibilities": "Sample responsibilities",
            "skills_required": "Python, Django, REST API",
            "education_or_certifications": "Bachelor's degree",
            "is_active": False
            # Add other required fields for Job model
        }
        self.job = Job.objects.create(**self.job_data)

        # job url
        self.job_url = '/jobs/'

        # Create an instance of the APIClient and set the Authorization header
        self.client = APIClient()



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
