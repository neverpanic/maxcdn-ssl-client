"""
Exceptions that can occur while using maxcdn-ssl-client
"""

import traceback

class SslApiClientException(Exception):
    """
    A superclass for all exceptions raised by maxcdn-ssl-client
    """
    __slots__ = ('message', 'cause')

    def __init__(self, message, cause=None):
        self.message = message
        self.cause = cause
        super().__init__()

    def __str__(self):
        string = "SslApiClientException: {}".format(self.message)
        if self.cause:
            exception = "".join(
                traceback.format_exception(type(self.cause),
                                           self.cause,
                                           self.cause.__traceback__))
            string += "\nCaused by:\n{}".format(exception)
        return string

class CommunicationException(SslApiClientException):
    """
    An error while communicating with the API server
    """
    pass

class ApiFailureException(SslApiClientException):
    """
    An error due to an invalid use of the API
    """
    pass

class CryptographyException(SslApiClientException):
    """
    An error due to an invalid cryptographic operation
    """
    pass

class LogicException(SslApiClientException):
    """
    An error due to business logic
    """
    pass
