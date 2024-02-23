import uuid

from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken
from django.urls import reverse
from apps.jobs.views import JobViewSets
from .models import Company, Job
from apps.accounts.models import User

# Create your tests here.


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

        # job_data struct
        self.job1 = Job.objects.create(
            job_role="Test Job 1",
            company=self.company,
            description="Test Description 1",
            location="Test Location 1",
            post_date="2024-02-15",
            posted=True,
            experience=3,
            job_type="Part-time",
            salary=75000.00,
            qualifications="Bachelor's degree in Test",
            vacency_position=2,
            industry="Test Industry",
            category="Test Category",
            is_active=True,
            job_responsibilities="Test Responsibilities 1",
            skills_required="Test Skills 1",
            education_or_certifications="Bachelor's degree in Test",
            employer_id=uuid.uuid4(),
        )
        self.job2 = Job.objects.create(
            job_role="Test Job 2",
            company=self.company,
            description="Test Description 2",
            location="Test Location 2",
            post_date="2024-02-16",
            posted=True,
            experience=4,
            job_type="Full-time",
            salary=90000.00,
            qualifications="Master's degree in Test",
            vacency_position=3,
            industry="Another Industry",
            category="Another Category",
            is_active=True,
            job_responsibilities="Test Responsibilities 2",
            skills_required="Test Skills 2",
            education_or_certifications="Master's degree in Test",
            employer_id=uuid.uuid4(),
        )
        self.user = User.objects.create_user(
            name="testuser",
            password="testpassword",
            email="testemail",
            user_type="Job Seeker",
        )
        # self.user.job = self.job1
        # self.user.job = self.job2
        self.user.save()
        self.job_url = "/jobs/"
        self.client = APIClient()
        self.access_token = AccessToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        self.client.force_authenticate(user=self.user)

    # def test_list_jobs(self):
    #     url = self.job_url
    #     response = self.client.get(url)
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_public_jobs(self):
        url = "/jobs/public_jobs/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_public_jobs_empty(self):
        print("Before setting is_created to False:")
        # print("job1.is_created:", self.job1.is_created)
        # print("job2.is_created:", self.job2.is_created)
        self.job1.is_created = False
        self.job1.save()
        self.job2.is_created = False
        self.job2.save()
        url = "/jobs/public_jobs/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 0)
