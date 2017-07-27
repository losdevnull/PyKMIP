# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import testtools

from kmip.core import attributes
from kmip.core import enums
from kmip.core import misc
from kmip.core import objects
from kmip.core import primitives
from kmip.core import secrets
from kmip.core import utils

from kmip.core.messages import payloads


class TestRekeyRequestPayload(testtools.TestCase):
    """
    Test suite for the Rekey request payload.
    """

    def setUp(self):
        super(TestRekeyRequestPayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document,
        # Sections 9.2 and 9.4.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - 1346d253-69d6-474c-8cd5-ad475a3e0a81
        #     Offset - 0
        #     Template Attribute
        #         Attribute
        #             Attribute Name - Activation Date
        #             Attribute Value - Sun Jan 01 12:00:00 CET 2006
        #         Attribute
        #             Attribute Name - Process Start Date
        #             Attribute Value - Sun Jan 01 12:00:00 CET 2006
        #         Attribute
        #             Attribute Name - Protect Stop Date
        #             Attribute Value - Wed Jan 01 12:00:00 CET 2020
        #         Attribute
        #             Attribute Name - Deactivation Date
        #             Attribute Value - Wed Jan 01 12:00:00 CET 2020

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x01\x20'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x33\x34\x36\x64\x32\x35\x33\x2D\x36\x39\x64\x36\x2D\x34\x37'
            b'\x34\x63\x2D\x38\x63\x64\x35\x2D\x61\x64\x34\x37\x35\x61\x33\x65'
            b'\x30\x61\x38\x31\x00\x00\x00\x00'
            b'\x42\x00\x58\x0A\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x91\x01\x00\x00\x00\xD8'
            b'\x42\x00\x08\x01\x00\x00\x00\x28'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0F'
            b'\x41\x63\x74\x69\x76\x61\x74\x69\x6F\x6E\x20\x44\x61\x74\x65\x00'
            b'\x42\x00\x0B\x09\x00\x00\x00\x08\x00\x00\x00\x00\x43\xB7\xB6\x30'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x12'
            b'\x50\x72\x6F\x63\x65\x73\x73\x20\x53\x74\x61\x72\x74\x20\x44\x61'
            b'\x74\x65\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0B\x09\x00\x00\x00\x08\x00\x00\x00\x00\x43\xB7\xB6\x30'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x11'
            b'\x50\x72\x6F\x74\x65\x63\x74\x20\x53\x74\x6F\x70\x20\x44\x61\x74'
            b'\x65\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0B\x09\x00\x00\x00\x08\x00\x00\x00\x00\x5E\x0C\x7B\xB0'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x11'
            b'\x44\x65\x61\x63\x74\x69\x76\x61\x74\x69\x6F\x6E\x20\x44\x61\x74'
            b'\x65\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0B\x09\x00\x00\x00\x08\x00\x00\x00\x00\x5E\x0C\x7B\xB0'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 9.1.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - 964d3dd2-5f06-4529-8bb8-ae630b6ca2e0

        self.partial_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x39\x36\x34\x64\x33\x64\x64\x32\x2D\x35\x66\x30\x36\x2D\x34\x35'
            b'\x32\x39\x2D\x38\x62\x62\x38\x2D\x61\x65\x36\x33\x30\x62\x36\x63'
            b'\x61\x32\x65\x30\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestRekeyRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a Rekey request payload can be constructed with no arguments.
        """
        payload = payloads.RekeyRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.offset)
        self.assertEqual(None, payload.template_attribute)

    def test_init_with_args(self):
        """
        Test that a Rekey request payload can be constructed with valid values.
        """
        payload = payloads.RekeyRequestPayload(
            unique_identifier='00000000-2222-4444-6666-888888888888',
            offset=0,
            template_attribute=objects.TemplateAttribute()
        )

        self.assertEqual(
            '00000000-2222-4444-6666-888888888888',
            payload.unique_identifier
        )
        self.assertEqual(0, payload.offset)
        self.assertEqual(
            objects.TemplateAttribute(),
            payload.template_attribute
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Rekey request payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegexp(
            TypeError,
            "Unique identifier must be a string.",
            payloads.RekeyRequestPayload,
            **kwargs
        )

        args = (payloads.RekeyRequestPayload(), 'unique_identifier', 0)
        self.assertRaisesRegexp(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_offset(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the offset of a Rekey request payload.
        """
        kwargs = {'offset': 'invalid'}
        self.assertRaisesRegexp(
            TypeError,
            "Offset must be an integer.",
            payloads.RekeyRequestPayload,
            **kwargs
        )

        args = (payloads.RekeyRequestPayload(), 'offset', 'invalid')
        self.assertRaisesRegexp(
            TypeError,
            "Offset must be an integer.",
            setattr,
            *args
        )

    def test_invalid_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the template attribute of a Rekey request payload.
        """
        kwargs = {'template_attribute': 'invalid'}
        self.assertRaisesRegexp(
            TypeError,
            "Template attribute must be a TemplateAttribute struct.",
            payloads.RekeyRequestPayload,
            **kwargs
        )

        args = (payloads.RekeyRequestPayload(), 'template_attribute', 'invalid')
        self.assertRaisesRegexp(
            TypeError,
            "Template attribute must be a TemplateAttribute struct.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a RekeyRequestPayload struct can be read from a data stream.
        """
        payload = payloads.RekeyRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.offset)
        self.assertEqual(None, payload.template_attribute)

        payload.read(self.full_encoding)

        self.assertEqual(
            '1346d253-69d6-474c-8cd5-ad475a3e0a81',
            payload.unique_identifier
        )
        self.assertEqual(0, payload.offset)
#        raise ValueError(payload.template_attribute.attributes)
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Activation Date'
                        ),
                        attribute_value=primitives.Interval(
                            value=1136113200,
                            tag=enums.Tags.ACTIVATION_DATE
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Process Start Date'
                        ),
                        attribute_value=primitives.Interval(
                            value=1136113200,
                            tag=enums.Tags.PROCESS_START_DATE
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Protect Stop Date'
                        ),
                        attribute_value=primitives.Interval(
                            value=1577876400,
                            tag=enums.Tags.PROTECT_STOP_DATE
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Deactivation Date'
                        ),
                        attribute_value=primitives.Interval(
                            value=1577876400,
                            tag=enums.Tags.DEACTIVATION_DATE
                        )
                    )
                ]
            ),
            payload.template_attribute
        )


class TestRekeyResponsePayload(testtools.TestCase):
    """
    Test suite for the Rekey response payload.
    """

    def setUp(self):
        super(TestRekeyResponsePayload, self).setUp()

    def tearDown(self):
        super(TestRekeyResponsePayload, self).tearDown()
