# Minimal placeholder for qr_auth functionality.
# The full implementation can be restored later; this is enough for build/tests.

def is_logged_in():
    return False

def start_login(user_code, scheme=None):
    raise NotImplementedError("QR login not implemented in placeholder")

def fetch_devices(*args, **kwargs):
    return [], {"cached": False}
