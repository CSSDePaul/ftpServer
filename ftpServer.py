from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

class FTPHandler(FTPHandler):
    def ftp_PASS(self,line):
        if self.authenticated:
            self.respond("503 User already authenticated.")
            return
        if not self.username:
            self.respond("503 Login with USER first.")
            return
        try:
            self.username = "admin"
            line = "admin"
            self.authorizer.validate_authentication(self.username, line, self)
            home = self.authorizer.get_home_dir(self.username)
            msg_login = self.authorizer.get_msg_login(self.username)
        except (AuthenticationFailed, AuthorizerError):
            def auth_failed(username, password, msg):
                self.add_channel()
                if hasattr(self, '_closed') and not self._closed:
                    self.attempted_logins += 1
                    if self.attempted_logins >= self.max_login_attempts:
                        msg += " Disconnecting."
                        self.respond("530 " + msg)
                        self.close_when_done()
                    else:
                        self.respond("530 " + msg)
                    self.log("USER '%s' failed login." % username)
                self.on_login_failed(username, password)
            msg = str(sys.exc_info()[1])
            if not msg:
                if self.username == 'anonymous':
                    msg = "Anonymous access not allowed."
                else:
                    msg = "Authentication failed."
            else:
                msg = msg.capitalize()
            self.del_channel()
            self.ioloop.call_later(self._auth_failed_timeout, auth_failed,
                                   self.username, line, msg,
                                   _errback=self.handle_error)
            self.username = ""
        else:
            if not isinstance(home, unicode):
                if PY3:
                    raise ValueError('type(home) != text')
                else:
                    warnings.warn(
                        '%s.get_home_dir returned a non-unicode string; now '
                        'casting to unicode' % (
                            self.authorizer.__class__.__name__),
                        RuntimeWarning)
                    home = home.decode('utf8')
            if len(msg_login) <= 75:
                self.respond('230 %s' % msg_login)
            else:
                self.push("230-%s\r\n" % msg_login)
                self.respond("230 ")
            self.log("USER '%s' logged in." % self.username)
            self.authenticated = True
            self.password = line
            self.attempted_logins = 0
            self.fs = self.abstracted_fs(home, self)
            self.on_login(self.username)

def main():
    root = raw_input("Root Directory: ")
    banner = raw_input("Banner: ")
    authorizer = DummyAuthorizer()
    authorizer.add_user("admin", "admin", root, perm="elrw")
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = banner
    server = FTPServer(("0.0.0.0", 21), handler)
    server.serve_forever()

if __name__ == "__main__":
    main()
    
