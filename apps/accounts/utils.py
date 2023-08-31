from django.core.mail import EmailMessage
import os
import pyotp


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
    @staticmethod
    def generate_otp():
        base32secret3232 = pyotp.random_base32()
        otp = pyotp.TOTP(base32secret3232, interval=300, digits=6)
        time_otp = otp.now()
        return time_otp, base32secret3232

    @staticmethod
    def verify_otp(user, otp):
        return pyotp.TOTP(user.otp_secret, interval=300, digits=6).verify(otp)
