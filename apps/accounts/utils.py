import os
import pyotp
from django.core.mail import EmailMessage
import logging


class Util:
    @staticmethod
    def send_email(data):
        logger = logging.getLogger(Util)
        logger.info(
            f'Sending email to {data["to_email"]} with subject: "{data["subject"]}"'
        )
        try:
            email = EmailMessage(
                subject=data["subject"],
                body=data["body"],
                from_email=os.environ.get("EMAIL_FROM"),
                to=[data["to_email"]],
            )
            email.send()
            logger.info(f'Email sent successfully to {data["to_email"]}')
        except Exception as e:
            logger.error(
                f'Failed to send email to {data["to_email"]}: {str(e)}'
            )  # error if sending e-mails fails


class OTP:
    # generate secret for a new user
    @staticmethod
    def generate_secret_with_otp():
        logger = logging.getLogger(OTP)
        logging.info("Generating secret OTP")
        base32secret3232 = pyotp.random_base32()
        otp = pyotp.TOTP(
            base32secret3232, interval=300, digits=6
        )  # otp valid for 5 minutes (300sec)
        time_otp = otp.now()
        return time_otp, base32secret3232

    # generate otp for a user
    @staticmethod
    def generate_otp(user):
        logger = logging.getLogger(OTP)
        logging.info("Generating otp for user")
        try:
            otp = pyotp.TOTP(
                user.otp_secret, interval=300, digits=6
            )  # otp valid for 5 minutes (300sec)
            time_otp = otp.now()
            return time_otp
        except Exception as e:
            logger.error(f"Failed to generate OTP")

    # verify otp
    @staticmethod
    def verify_otp(user, otp):
        return pyotp.TOTP(user.otp_secret, interval=300, digits=6).verify(otp)
