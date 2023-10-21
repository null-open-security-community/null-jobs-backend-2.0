import os

import pyotp
from django.core.mail import EmailMessage


class Util:
    @staticmethod
    def send_email(data: dict):
        """Send mail with the OTP secret"""

        if not data or not isinstance(data, dict):
            raise Exception("Data isn't valid")

        to_email = data.get("to_email", "")
        from_email = os.environ.get("EMAIL_FROM")

        if not to_email or not from_email:
            raise ValueError("Incomplete mail details provided")

        email = EmailMessage(
            subject=data["subject"],
            body=data["body"],
            from_email=from_email,
            to=to_email,
        )

        try:
            email.send()
        except Exception as err:
            raise Exception(f"Exception occurred in 'send_mail': {err}")


class OTP:
    """generate secret for a new user"""

    @staticmethod
    def generate_secret_with_otp():
        try:
            base32secret3232 = pyotp.random_base32()
            otp = pyotp.TOTP(
                base32secret3232, interval=300, digits=6
            )  # otp valid for 5 minutes (300sec)
            time_otp = otp.now()
            return time_otp, base32secret3232
        except Exception as err:
            raise Exception(f"Exception occurred in 'generate_secret_with_otp': {err}")

    @staticmethod
    def generate_otp(user):
        """generate otp for a user"""

        # otp valid for 5 minutes (300sec)
        try:
            otp = pyotp.TOTP(user.otp_secret, interval=300, digits=6)
            time_otp = otp.now()
            return time_otp
        except Exception as err:
            raise Exception(f"Exception occurred in 'generating OTP': {err}")

    @staticmethod
    def verify_otp(user, otp):
        """verify otp"""

        try:
            return pyotp.TOTP(user.otp_secret, interval=300, digits=6).verify(otp)
        except Exception as err:
            raise Exception(f"Exception occurred in 'verify_otp': {err}")
