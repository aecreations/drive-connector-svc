# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

class AuthorizationError(Exception):
    def __init__(self, errMsg):
        super().__init__(errMsg)
        self.name = "AuthorizationError"
        self.message = errMsg

    def __str__(self):
        return f"{self.name}: {self.message}"
