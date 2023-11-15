import os
import pyotp
from django.core.mail import EmailMessage
import logging


class Util:
    logger = logging.getLogger("accounts.Util")

    @staticmethod
    def send_email(data, self):
        try:
            email = EmailMessage(
                subject=data["subject"],
                body=data["body"],
                from_email=os.environ.get("EMAIL_FROM"),
                to=[data["to_email"]],
            )
            email.send()
        except Exception as e:
            self.logger.error(f"Error sending email: {e}")


class OTP:
    # generate secret for a new user
    logger = logging.getLogger("accounts.OTP")

    @staticmethod
    def generate_secret_with_otp(self):
        try:
            base32secret3232 = pyotp.random_base32()
            otp = pyotp.TOTP(
                base32secret3232, interval=300, digits=6
            )  # otp valid for 5 minutes (300sec)
            time_otp = otp.now()
            return time_otp, base32secret3232
        except Exception as e:
            self.logger.error(f"Error generating secret with OTP: {e}")

    # generate otp for a user
    @staticmethod
    def generate_otp(user, self):
        try:
            otp = pyotp.TOTP(
                user.otp_secret, interval=300, digits=6
            )  # otp valid for 5 minutes (300sec)
            time_otp = otp.now()
            return time_otp
        except Exception as e:
            self.logger.error(f"Error generating OTP for user: {e}")

    # verify otp
    @staticmethod
    def verify_otp(user, otp):
        try:
            return pyotp.TOTP(user.otp_secret, interval=300, digits=6).verify(otp)
        except Exception as e:
            OTP.logger.error(f"Error verifying OTP for user: {e}")
            return False
