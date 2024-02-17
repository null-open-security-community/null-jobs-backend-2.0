"""This file contains constant which are also used in other parts of the jobs API code,
It helps you to declare the variable with their value here, and use them anywhere else"""

STATUS_CHOICES = (
    ("under-reviewed", "Under-Reviewed"),
    ("shortlisted", "Shortlisted"),
    ("accepted", "Accepted"),
    ("rejected", "Rejected"),
    ("on-hold", "On-Hold"),
)

GENDER = (("male", "Male"), ("female", "Female"), ("other", "Other"))

HIRING_STATUS = (("hiring", "HIRING"), ("open to work", "OPEN TO WORK"))


JOB_TYPE = (
    ("full time", "FULL TIME"),
    ("part time", "PART TIME"),
    ("contract", "CONTRACT"),
    ("internship", "INTERNSHIP"),
)

EMPLOYER_ID = "employer_id"
USER_ID = "user_id"
JOB_ID = "job_id"
COMPANY_ID = "company_id"

DB_TABLE_COMPANY = "tbl_company"
DB_TABLE_JOBS = "tbl_job"
DB_TABLE_USER_PROFILE = "tbl_user_profile"

RESUME_DOCUMENT_TYPE = "resume"
PROFILE_PICTURE_DOCUMENT_TYPE = "profile_picture"
COVER_LETTER_DOCUMENT_TYPE = "cover_letter"

ITEMS_PER_PAGE = 5
PAST_3_WEEK_DATETIME_DAYS18 = 18

EMPLOYER = "Employer"
JOB_SEEKER = "Job Seeker"
MODERATOR = "Moderator"
