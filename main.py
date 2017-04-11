#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import webapp2
import re
import cgi

header = """
<!DOCTYPE html>
<html>
<head>
    <title>User Signup</title>
    <style type="text/css">
        .error {
            color: red;
        }
    </style>
</head>
<body>
    <h1>Signup</h1>
"""

footer = """
</body>
</html>
"""

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class MainHandler(webapp2.RequestHandler):
    def get(self):
        form = """
        <form method="post">
            <table>
            <tr>
                <td><label>Username</label></td>
                <td><input name="username" type="text" value="" required><span class="error"></span></td>
            </tr>
            <tr>
                <td><label>Password</label></td>
                <td><input name="passowrd" type="password" value="" required><span class="error"></span></td>
            </tr>
            <tr>
                <td><label>Verify Password</label></td>
                <td><input name="verify" type="password" value="" required><span class="error"></span></td>
            </tr>
            <tr>
                <td><label>Email (optional)</label></td>
                <td><input name="email" type="text" value=""><span class="error"></span></td>
            </tr>
            </table>
            <input type="submit">
        </form>
        """
        self.response.write(header + form + footer)

    def post(self):
        haveError = False

        username = cgi.escape(self.request.get("username"), quote=True)
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = cgi.escape(self.request.get("email"), quote=True)

        error_user = ""
        error_pwd = ""
        error_verify = ""
        error_email = ""

        if not valid_username(username):
            error_user = "invalid username"
            have_error = True
        if not valid_password(password):
            error_pwd = "invalid password"
            have_error = True
        if password != verify:
            error_verify = "your passwords didn't match"
            have_error = True
        if not valid_email(email):
            error_email = "invalid email"
            have_error = True

        if have_error:
            form = """
            <form method="post">
            <table>
            <tr>
                <td><label>Username</label></td>
                <td><input name="username" type="text" value="{0}" required><span class="error">{1}</span></td>
            </tr>
            <tr>
                <td><label>Password</label></td>
                <td><input name="passowrd" type="password" value="" required><span class="error">{2}</span></td>
            </tr>
            <tr>
                <td><label>Verify Password</label></td>
                <td><input name="verify" type="password" value="" required><span class="error">{3}</span></td>
            </tr>
            <tr>
                <td><label>Email (optional)</label></td>
                <td><input name="email" type="text" value="{4}"><span class="error">{5}</span></td>
            </tr>
            </table>
            <input type="submit">
            </form>
            """.format(username, error_user, error_pwd, error_verify, email, error_email)
            self.response.write(header + form + footer)
        else:
            self.redirect("/welcome?username=" + username)

class Welcome(webapp2.RequestHandler):
    def get(self):
        username = self.request.get("username")
        welcomemsg = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>User Signup</title>
        </head>
        <body>
            <h2>Welcome, {0}!</h2>
        """.format(username)
        if valid_username(username):
            self.response.write(welcomemsg + footer)
        else:
            self.redirect("/?username=" + username)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', Welcome)
], debug=True)
