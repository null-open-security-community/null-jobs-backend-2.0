import os
import pyotp
from django.core.mail import EmailMessage


class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data["subject"],
            body=data["body"],
            from_email=os.environ.get("EMAIL_FROM"),
            to=[data["to_email"]],
        )
        email.send()


class OTP:
    
    # generate secret for a new user
    @staticmethod
    def generate_secret_with_otp():
        base32secret3232 = pyotp.random_base32()
        otp = pyotp.TOTP(base32secret3232, interval=300, digits=6) # otp valid for 5 minutes (300sec)
        time_otp = otp.now()
        return time_otp, base32secret3232

    # generate otp for a user
    @staticmethod
    def generate_otp(user):
        otp = pyotp.TOTP(user.otp_secret, interval=300, digits=6)  # otp valid for 5 minutes (300sec)
        time_otp = otp.now()
        return time_otp
    
    # verift otp
    @staticmethod
    def verify_otp(user, otp):
        return pyotp.TOTP(user.otp_secret, interval=300, digits=6).verify(otp)
