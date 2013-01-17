#Copyright 2012 Linkedin
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
#

#define here any function that manages access to the site.

from flask import Flask, request

def is_authorized():
    authorizedUser=False
    if not request.environ['SERVER_SOFTWARE'][:8]=="Werkzeug":
        if not authorizedUser:
            abort(401)
