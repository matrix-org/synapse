# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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

import os.path
import tempfile

from synapse.config import ConfigError
from synapse.util.stringutils import random_string

from tests import unittest


class BaseConfigTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.hs = hs

    def test_loading_missing_templates(self):
        # Use a temporary directory that exists on the system, but that isn't likely to
        # contain template files
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Attempt to load an HTML template from our custom template directory
            template = self.hs.config.read_templates(["sso_error.html"], tmp_dir)[0]

        # If no errors, we should've gotten the default template instead

        # Render the template
        a_random_string = random_string(5)
        html_content = template.render({"error_description": a_random_string})

        # Check that our string exists in the template
        self.assertIn(
            a_random_string,
            html_content,
            "Template file did not contain our test string",
        )

    def test_loading_custom_templates(self):
        # Use a temporary directory that exists on the system
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create a temporary bogus template file
            with tempfile.NamedTemporaryFile(dir=tmp_dir) as tmp_template:
                # Get temporary file's filename
                template_filename = os.path.basename(tmp_template.name)

                # Write a custom HTML template
                contents = b"{{ test_variable }}"
                tmp_template.write(contents)
                tmp_template.flush()

                # Attempt to load the template from our custom template directory
                template = (
                    self.hs.config.read_templates([template_filename], tmp_dir)
                )[0]

        # Render the template
        a_random_string = random_string(5)
        html_content = template.render({"test_variable": a_random_string})

        # Check that our string exists in the template
        self.assertIn(
            a_random_string,
            html_content,
            "Template file did not contain our test string",
        )

    def test_loading_template_from_nonexistent_custom_directory(self):
        with self.assertRaises(ConfigError):
            self.hs.config.read_templates(
                ["some_filename.html"], "a_nonexistent_directory"
            )
