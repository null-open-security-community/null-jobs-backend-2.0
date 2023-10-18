from apps import jobs
from django.test import TestCase
from apps.jobs.models import Applicants, Job, User, Company
import datetime


class CompanyModelTestCase(TestCase):
    def setUp(self):
        self.company_data = {
            "name": "Test Company",
            "location": "Test Location",
            "about": "Test About",
        }

    def test_company_model_creation(self):
        company = Company(**self.company_data)
        company.save()

        self.assertEqual(company.name, "Test Company")
        self.assertEqual(company.location, "Test Location")
        self.assertEqual(company.about, "Test About")

        # Check that company_id is not None
        self.assertIsNotNone(company.company_id)


def test_company_model_str_method(self):
    company = Company(**self.company_data)
    company.save()

    expected_str = "Test Company"
    self.assertEqual(str(company), expected_str)


class JobModelTestCase(TestCase):
    def setUp(self):
        self.company = Company.objects.create(
            name="Test Company", location="Test Location", about="Test Company"
        )
        self.job_data = {
            "job_role": "Software Developer",
            "company": self.company,
            "description": "Test about",
            "location": "Test location",
            "post_date": "2023-10-01",
            "posted": True,
            "experience": 2,
            "employer_id": "0123456789abcdef0123456789abcdef",
        }

    def test_job_model_creation(self):
        job = Job(**self.job_data)
        job.save()

        self.assertEqual(job.job_role, "Software Developer")
        self.assertEqual(job.company.name, "Test Company")
        self.assertEqual(job.description, "Test about")
        self.assertEqual(job.location, "Test location")
        self.assertEqual(job.post_date, "2023-10-01")
        self.assertTrue(job.posted)
        self.assertEqual(job.experience, 2)
        self.assertEqual(str(job.employer_id), "0123456789abcdef0123456789abcdef")

    def test_job_model_str_method(self):
        job = Job(**self.job_data)
        job.save()

        expected_str = "Software Developer"
        self.assertEqual(str(job), expected_str)


class UserModelTestCase(TestCase):
    def setUp(self):
        self.company = Company.objects.create(
            company_id="0123456789abcdef0123456789abcdef",
            name="Test Company",
            location="Test Location",
            about="Test about",
        )

        self.job = Job.objects.create(
            job_role="Test Developer",
            location="Test Location",
            description="Test Job",
            company_id="0123456789abcdef0123456789abcdef",
            post_date="2023-10-01",
            posted=True,
            experience=2,
            employer_id="0123456789abcdef0123456789abcdef",
        )

        self.user_data = {
            "name": "John Doe",
            "email": "john@example.com",
            "address": "123 Main St",
            "phone": "123-456-7890",
            "about": "Test about",
            "job": self.job,  # Provide a non-null value for 'about'
            "company": self.company,
            "user_type": "employee",
        }

    def test_user_model_creation(self):
        user = User(**self.user_data)
        user.save()

        self.assertEqual(user.name, "John Doe")
        self.assertEqual(user.email, "john@example.com")
        self.assertEqual(user.address, "123 Main St")
        self.assertEqual(user.phone, "123-456-7890")
        self.assertEqual(user.about, "Test about")
        self.assertEqual(user.company.name, "Test Company")
        self.assertEqual(user.user_type, "employee")

    def test_user_model_str_method(self):
        user = User(**self.user_data)
        user.save()

        expected_str = "John Doe"
        self.assertEqual(str(user), expected_str)


class ApplicantsModelTestCase(TestCase):
    def setUp(self):
        # Create a test Company instance
        self.company = Company.objects.create(
            name="Test Company",
            location="Test Location",
            about="Test Company",
        )

        # Create a test User instance associated with the Company
        self.user = User.objects.create(
            name="Test User",
            email="test@example.com",
            address="Test Address",
            phone="1234567890",
            about="Test about",
            job=None,
            resume=None,
            company=self.company,
        )

        # Create a test Job instance associated with the Company
        self.job = Job.objects.create(
            job_role="Software Developer",
            company=self.company,  # Associate the Job with the Company
            description="Test job description",
            location="Test location",
            post_date=datetime.date(2023, 10, 1),
            posted=True,
            experience=2,
            employer_id="0123456789abcdef0123456789abcdef",
            company_id=self.company.company_id,  # Use the correct company_id
        )

    def test_applicants_model(self):
        # Create an Applicants instance
        applicants = Applicants.objects.create(
            job=self.job,
            user=self.user,
            status="applied",
            created_at=datetime.datetime.now(),
            updated_at=datetime.datetime.now(),
            is_deleted=False,
            is_active=True,
            employer_id="0123456789abcdef0123456789abcdef",
            # Add other Applicants fields here
        )

        # Retrieve the Applicants instance from the database
        retrieved_applicants = Applicants.objects.get(pk=applicants.pk)

        # Perform assertions to check if the data matches
        self.assertEqual(retrieved_applicants.job.job_role, self.job.job_role)
        self.assertEqual(retrieved_applicants.user.name, self.user.name)
        self.assertEqual(retrieved_applicants.status, "applied")
        self.assertIsNotNone(retrieved_applicants.created_at)
        self.assertIsNotNone(retrieved_applicants.updated_at)
        self.assertFalse(retrieved_applicants.is_deleted)
        self.assertTrue(retrieved_applicants.is_active)
        self.assertEqual(
            str(retrieved_applicants.employer_id).replace("-", ""),
            "0123456789abcdef0123456789abcdef",
        )
