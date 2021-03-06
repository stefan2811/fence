from cdiserrors import APIError


class AuthError(APIError):
    pass


class UserError(APIError):
    def __init__(self, message):
        self.message = str(message)
        self.code = 400


class BlacklistingError(APIError):
    def __init__(self, message):
        self.message = str(message)
        self.code = 400


class InternalError(APIError):
    def __init__(self, message):
        super(InternalError, self).__init__(message)
        self.message = str(message)
        self.code = 500


class Unauthorized(APIError):
    def __init__(self, message):
        self.message = str(message)
        self.code = 401


class NotFound(APIError):
    def __init__(self, message):
        self.message = str(message)
        self.code = 404


class NotSupported(APIError):
    def __init__(self, message):
        self.message = str(message)
        self.code = 400


class UnavailableError(APIError):
    def __init__(self, message):
        self.message = str(message)
        self.code = 503
