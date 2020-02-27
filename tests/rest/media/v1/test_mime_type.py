from synapse.rest.media.v1.mime_type import MimeType

from tests import unittest


class MimeTypeTests(unittest.TestCase):
    def test_basic_types(self):
        """Tests basic, trivially valid uses of MimeType."""
        png = MimeType("image/png")
        self.assertEqual(png.type, "image")
        self.assertEqual(png.subtype, "png")

        html = MimeType("TEXT/HTML")
        self.assertEqual(html.type, "text")
        self.assertEqual(html.subtype, "html")

        binary = MimeType("Application/Octet-Stream")
        self.assertEqual(binary.type, "application")
        self.assertEqual(binary.subtype, "octet-stream")

    def test_normalization(self):
        """Tests that commonly encountered invalid mime types are corrected."""
        jpg = MimeType("image/jpg")
        self.assertEqual(jpg.type, "image")
        self.assertEqual(jpg.subtype, "jpeg")

        jpg_caps = MimeType("image/JPG")
        self.assertEqual(jpg_caps.type, "image")
        self.assertEqual(jpg_caps.subtype, "jpeg")

        jpeg = MimeType("image/jpeg")
        self.assertEqual(jpeg.type, "image")
        self.assertEqual(jpeg.subtype, "jpeg")

        self.assertEqual(jpg, jpg_caps)
        self.assertEqual(jpg, jpeg)

    def test_equality(self):
        """Tests checking equality between MimeTypes."""
        jpg = MimeType("image/jpeg")
        jpg2 = MimeType("Image/Jpeg")
        png = MimeType("image/png")

        self.assertEqual(jpg, jpg2)
        self.assertNotEqual(jpg, png)
        self.assertEqual(jpg, "image/jpeg")

    def test_bad_format(self):
        """Tests incorrectly formatted media types."""
        with self.assertRaises(ValueError):
            MimeType("image/jpeg/v1")

        with self.assertRaises(ValueError):
            MimeType("image")

        with self.assertRaises(ValueError):
            MimeType("")
