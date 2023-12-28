import threading
from typing import Any
from django.core.mail import EmailMessage


class EmailThread(threading.Thread):
    def __init__(self, subject, body, recipient_list) :
        self.subject = subject
        self.body = body
        self.recipient_list = recipient_list
        super().__init__()

    def run(self):
        msg = EmailMessage(subject=self.subject, body=self.body, to=self.recipient_list)
        msg.send()


def send_email(subject, body, recipient_list):
    EmailThread(subject=subject, body=body, recipient_list=recipient_list).start()