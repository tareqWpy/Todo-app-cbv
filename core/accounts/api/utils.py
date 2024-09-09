import threading

"""
A thread for sending emails.

This class extends the threading.Thread class and is used to send emails in a separate thread.

Attributes:
email_obj : Email
    The email object to be sent.

Methods:
run()
    Sends the email using the email_obj's send method.
"""


class EmailThread(threading.Thread):
    def __init__(self, email_obj):
        """
        Constructs all the necessary attributes for the EmailThread object.

        Parameters:
        email_obj (Email): The email object to be sent.
        """
        threading.Thread.__init__(self)
        self.email_obj = email_obj

    def run(self):
        """
        Sends the email using the email_obj's send method.

        Returns:
        None
        """
        self.email_obj.send()
