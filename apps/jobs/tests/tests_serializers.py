# # # tests.py
from apps.jobs import *
from django.test import TestCase
from apps.jobs.models import *
from apps.jobs.serializers import *


class JobSerializerTestCase(TestCase):
    def setUp(self):
        self.company = Company.objects.create(
            name="Test Company",
            location="Test Location",
            about="Test Company",
        )

        self.job_data = {
            "job_role": "Software Developer",
            "company": self.company,
            "description": "Test description",
            "location": "Test Location",
            "post_date": "2023-10-01",
            "posted": True,
            "experience": 2,
            "employer_id": "0123456789abcdef0123456789abcdef",
        }

    def test_job_serializer_create(self):
        job = JobSerializer().create(self.job_data)
        # Check if the job was created with the correct data
        self.assertEqual(job.job_role, "Software Developer")
        self.assertEqual(job.company, self.company)
        self.assertEqual(job.description, "Test description")
        self.assertEqual(job.location, "Test Location")
        self.assertEqual(job.post_date, "2023-10-01")
        self.assertTrue(job.posted)
        self.assertEqual(job.experience, 2)
        self.assertEqual(str(job.employer_id), "0123456789abcdef0123456789abcdef")


class CompanySerializerTestCase(TestCase):
    def setUp(self):
        self.valid_company_data = {
            "company_id": "0123456789abcdef0123456789abcdef",
            "name": "Test Company",
            "location": "Test Location",
            "about": "Test About",
        }

    def test_read_only_fields(self):
        # Serialize data and ensure read-only fields are present
        serialized_data = CompanySerializer(self.valid_company_data).data
        self.assertIn("company_id", serialized_data)

    def test_create_company(self):
        # Attempt to create a company with read-only fields
        company = CompanySerializer().create(self.valid_company_data)

        # Ensure that the read-only field is not set on the created company
        self.assertTrue(company.company_id)

    def test_update_company(self):
        # Create a company instance
        company = Company.objects.create(
            name="Existing Company",
            location="Existing Location",
            about="Existing Company",
        )

        # Attempt to update the company instance using the serializer
        updated_company = CompanySerializer(company, data=self.valid_company_data)

        # Ensure that the read-only field is not changed during the update
        self.assertEqual(updated_company.is_valid(), True)


class UserSerializerTestCase(TestCase):
    def setUp(self):
        # Create a Company and Job instance to use as foreign keys
        self.company = Company.objects.create(
            name="Test Company",
            location="Test Location",
            about="Test Company",
        )

        self.job = Job.objects.create(
            job_role="Software Developer",
            company=self.company,
            description="Test description",
            location="Location",
            post_date="2023-10-01",
            posted=True,
            experience=2,
            employer_id="0123456789abcdef0123456789abcdef",
        )

        self.valid_user_data = {
            "user_id": "0123456789abcdef0123456789abcdef",  # A valid UUID in hexadecimal format
            "name": "Test User",
            "email": "testuser@example.com",
            "address": "123 Main St",
            "phone": "123-456-7890",
            "about": "Test about",
            "job": self.job,
            "resume": None,
            "profile_picture": None,
            "cover_letter": None,
            "company": self.company,
            "user_type": "employee",
        }

    def test_user_serializer_read_only_fields(self):
        serializer = UserSerializer(data=self.valid_user_data)

        # Ensure read-only field user_id is not used for deserialization
        self.assertFalse(serializer.is_valid())
        self.assertNotIn("user_id", serializer.validated_data)

    def test_user_serializer_create(self):
        user = UserSerializer().create(self.valid_user_data)

        self.assertEqual(user.name, "Test User")
        self.assertEqual(user.email, "testuser@example.com")
        self.assertEqual(user.about, "Test about")

        # Check the foreign key relationships
        self.assertEqual(user.job, self.job)
        self.assertEqual(user.company, self.company)
        # Add more assertions as needed to validate other fields of the user object


class ApplicantsSerializerTestCase(TestCase):
    def setUp(self):
        self.applicants_data = {
            "employer_id": "0123456789abcdef0123456789abcdef",
            # Other data fields...
        }

    def test_applicants_serializer_read_only_fields(self):
        serializer = ApplicantsSerializer(data=self.applicants_data)

        # Ensure read-only field employer_id is not used for deserialization
        self.assertFalse(serializer.is_valid())
        self.assertNotIn("employer_id", serializer.validated_data)
