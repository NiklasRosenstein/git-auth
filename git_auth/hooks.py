# -*- mode: python; tab-width: 2; coding: utf8 -*-
#
# Copyright (C) 2015 Niklas Rosenstein
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

import os
import json


def parse_webhooks(filename):
  ''' Parses a file containing webhook URLs and returns a dictionary. '''

  # XXX: Callers should catch ValueErrors

  if not os.path.isfile(filename):
    return {}
  result = {}
  with open(filename, 'r') as fp:
    return json.load(fp)


def write_webhooks(filename, hooks):
  ''' Writes a dictionary containing webhook URLs to the specified file. '''

  # XXX: Validate hooks parameter

  with open(filename, 'w') as fp:
    json.dump(hooks, fp, indent=1)


def invoke_webhook(url, data):
  ''' Invokes the webhook at the specified URL with the JSON *data*. '''

  # XXX: Implement invoke_webhook()
  raise NotImplementedError("invoke_webhook() not implemented")
