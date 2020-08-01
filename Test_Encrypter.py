from Encrypter import *
import unittest
import Encrypter


# range of characters the encrypter supports is [31, 127]

class TestClass(unittest.TestCase):
    def setUp(self):
        self.caeser = Encrypter.Caeser()
        self.affine = Encrypter.Affine()
        self.polyalphabetic = Encrypter.Polyalphabetic()

    def test_caeser_encrypt(self):
        """
        CAESER CIPHER:
        Moves characters along alphabet by n, n in Natural numbers modulo 95.
        """
        ######################
        #  TYPE CHECKING
        ######################
        # If you give the wrong types, raise an appropriate error
        self.assertRaises(TypeError, self.caeser.encrypt, True, 7)  # first argument should be string ONLY
        self.assertRaises(TypeError, self.caeser.encrypt, "irrelevant string", "7")  # second argument must be int
        # if you give an unsupported character, it raises an error
        self.assertRaises(UnsupportedCharError, self.caeser.encrypt, "{}".format(chr(31)), -9)
        self.assertRaises(UnsupportedCharError, self.caeser.encrypt, "{}".format(chr(128)), -9)

        ######################
        #  RESULTS CHECKING
        ######################
        # happy path testing
        self.assertEqual("khoor", self.caeser.encrypt("hello", 3))
        self.assertEqual("KHOOR", self.caeser.encrypt("HELLO", 3))
        self.assertEqual("hello", self.caeser.encrypt("hello", 0))
        # giving no arguments resuls in expression = "", shift = 0; which returns ""
        self.assertEqual(self.caeser.encrypt(), "")
        # negative shift is allowed
        self.assertEqual("ebiil", self.caeser.encrypt("hello", -3))
        # length of string is preserved by caeser cipher
        self.assertEqual(len(self.caeser.encrypt("hello", 1)), len("hello"))
        # we want the cipher to be case sensitive
        self.assertNotEqual(self.caeser.encrypt("A", 7), self.caeser.encrypt("a", 7))
        # shift should be modulo 95
        self.assertEqual(self.caeser.encrypt("hello world!", 4), self.caeser.encrypt("hello world!", -91))

    def test_caseer_decrypt(self):
        """ identical function to encrypt, just with (decrypt shift) = -(encrypt shift) (mod 95); the requirements are
        the same, the results are reversed. """
        ######################
        #  TYPE CHECKING
        ######################
        # ensure that ciphertext is string, and shift is a number
        self.assertRaises(TypeError, self.caeser.encrypt, True, 7)  # first argument should be string ONLY
        self.assertRaises(TypeError, self.caeser.encrypt, "irrelevant string", "7")  # second argument must be int
        # if you give an unsupported character, it raises an error
        self.assertRaises(UnsupportedCharError, self.caeser.encrypt, "{}".format(chr(31)), -9)
        self.assertRaises(UnsupportedCharError, self.caeser.encrypt, "{}".format(chr(128)), -9)

        ######################
        #  RESULTS CHECKING
        ######################
        # happy path testing
        self.assertEqual("hello", self.caeser.decrypt("khoor", 3))
        self.assertEqual("HELLO", self.caeser.decrypt("KHOOR", 3))
        self.assertEqual("hello", self.caeser.decrypt("hello", 0))
        # negative shift is allowed
        self.assertEqual("hello", self.caeser.decrypt("ebiil", -3))
        # length of string is preserved by decryption
        self.assertEqual(len(self.caeser.decrypt("hello", 1)), len("hello"))
        # we want the cipher to be case sensitive
        self.assertNotEqual(self.caeser.decrypt("A", 7), self.caeser.decrypt("a", 7))
        # shift should be modulo 95
        self.assertEqual(self.caeser.decrypt("hello world!", 4), self.caeser.decrypt("hello world!", -91))
        # giving no arguments resuls in expression = "", shift = 0; which returns ""
        self.assertEqual(self.caeser.decrypt(), "")

    def test_affine_encrypt(self):
        # I think this part is going to be in each test, just slightly adapted for each test
        ######################
        #  TYPE CHECKING
        ######################
        # If you give the wrong types, raise an appropriate error
        # first argument has to be string
        self.assertRaises(TypeError, self.affine.encrypt, True, 7, 2)
        # second and third argument has to be an int
        self.assertRaises(TypeError, self.affine.encrypt, "irrelevant string", "7", 2)
        self.assertRaises(TypeError, self.affine.encrypt, "irrelevant string", 7, "2")

        # if you give an unsupported character, it raises an error
        self.assertRaises(UnsupportedCharError, self.affine.encrypt, "{}".format(chr(31)), -9, 12)
        self.assertRaises(UnsupportedCharError, self.affine.encrypt, "{}".format(chr(128)), -9, 12)

        # giving the function nothing results in "" being returned
        self.assertEqual(self.affine.encrypt(), "")

        """ our alphabet has a length of 95. If the multiplicative shift is not coprime with 95, then the encryption
        cannot be decrypted. So we will raise an error telling the user that the combination is undecryptable """
        self.assertRaises(UndecryptableCombinationError, self.affine.encrypt, "Irrelevant string", 5, 1)

        ######################
        #  RESULTS CHECKING
        ######################
        # happy path tests
        self.assertEqual(self.affine.encrypt("hello", 4, 6), ")|99E")

        # affine cipher should be case sensitive
        self.assertNotEqual(self.affine.encrypt("hello", 4, 6), self.affine.encrypt("HELLO", 4, 6))

        # can handle negative shifts just fine
        self.assertEqual(self.affine.encrypt("str", -201, -4), "A6L")

        # length is preserved by affine encryption
        self.assertEqual(len(self.affine.encrypt("str", -201, -4)), len("str"))

        # shift should be mod 95, for both shifts
        self.assertEqual(self.affine.encrypt("String1", 97, 102), self.affine.encrypt("String1", 97, 7))
        self.assertEqual(self.affine.encrypt("String2", 97, 102), self.affine.encrypt("String2", 2, 102))
        self.assertEqual(self.affine.encrypt("String3", 97, 102), self.affine.encrypt("String3", 2, 7))

    def test_affine_decrypt(self):
        """ This has the same requirements as affine encryption, just with results reversed; so may as well just modify
        the tests from above """

        ######################
        #  TYPE CHECKING
        ######################
        # If you give the wrong types, raise an appropriate error
        # first argument has to be string
        self.assertRaises(TypeError, self.affine.decrypt, True, 7, 2)
        # second and third argument has to be an int
        self.assertRaises(TypeError, self.affine.decrypt, "irrelevant string", "7", 2)
        self.assertRaises(TypeError, self.affine.decrypt, "irrelevant string", 7, "2")

        # if you give an unsupported character, it raises an error
        self.assertRaises(UnsupportedCharError, self.affine.decrypt, "{}".format(chr(31)), -9, 12)
        self.assertRaises(UnsupportedCharError, self.affine.decrypt, "{}".format(chr(128)), -9, 12)

        # giving the function nothing results in "" being returned
        self.assertEqual(self.affine.decrypt(), "")

        """ our alphabet has a length of 95. If the multiplicative shift is not coprime with 95, then the encryption
        cannot be decrypted. So we will raise an error telling the user that the combination is undecryptable """
        self.assertRaises(UndecryptableCombinationError, self.affine.decrypt, "Irrelevant string", 5, 1)

        self.assertEqual(self.affine.decrypt(")|99E", 4, 6), "hello")

        # affine cipher should be case sensitive
        self.assertNotEqual(self.affine.decrypt("hello", 4, 6), self.affine.decrypt("HELLO", 4, 6))

        # can handle negative shifts just fine
        self.assertEqual(self.affine.decrypt("A6L", -201, -4), "str")

        # length is preserved by affine encryption
        self.assertEqual(len(self.affine.decrypt("str", -201, -4)), len("str"))

        # shift should be mod 95, for both shifts
        self.assertEqual(self.affine.decrypt("String1", 97, 102), self.affine.decrypt("String1", 97, 7))
        self.assertEqual(self.affine.decrypt("String2", 97, 102), self.affine.decrypt("String2", 2, 102))
        self.assertEqual(self.affine.decrypt("String3", 97, 102), self.affine.decrypt("String3", 2, 7))

    def test_polyalphabetic_encrypt(self):
        """ User gives a plaintext and then keystring """
        # Two arguments, both of which are strings. Should raise a TypeError otherwise
        self.assertRaises(TypeError, False, "Irrelevant")
        self.assertRaises(TypeError, "Irrelevant", True)
        self.assertRaises(TypeError, None, [])

        # Entering nothing returns ""
        self.assertEqual("", self.polyalphabetic.encrypt())

        # if either string contains an unsupported character, raise an error
        self.assertRaises(UnsupportedCharError, self.polyalphabetic.encrypt, chr(21), "world")
        self.assertRaises(UnsupportedCharError, self.polyalphabetic.encrypt, chr(128), "this string is fine")

        # cipher is case sensitive for both strings
        self.assertNotEqual(self.polyalphabetic.encrypt("hi", "bye"), self.polyalphabetic.encrypt("HI", "bye"))
        self.assertNotEqual(self.polyalphabetic.encrypt("hi", "bye"), self.polyalphabetic.encrypt("hi", "BYE"))

        # length is preserved by affine encryption
        self.assertEqual(len(self.polyalphabetic.encrypt("plaintext", "ciphertext")), len("plaintext"))

        # happy path testing
        self.assertEqual(self.polyalphabetic.encrypt("Hello world!", "IBM 5100"), "2HZ-EQH@\ORA")

    def test_polyalphabetic_decrypt(self):
        # same as before but with results reversed
        # Two arguments, both of which are strings. Should raise a TypeError otherwise
        self.assertRaises(TypeError, False, "Irrelevant")
        self.assertRaises(TypeError, "Irrelevant", True)
        self.assertRaises(TypeError, None, [])

        # Entering nothing returns ""
        self.assertEqual("", self.polyalphabetic.decrypt())

        # if either string contains an unsupported character, raise an error
        self.assertRaises(UnsupportedCharError, self.polyalphabetic.decrypt, chr(21), "world")
        self.assertRaises(UnsupportedCharError, self.polyalphabetic.decrypt, chr(128), "this string is fine")

        # cipher is case sensitive for both strings
        self.assertNotEqual(self.polyalphabetic.decrypt("hi", "bye"), self.polyalphabetic.decrypt("HI", "bye"))
        self.assertNotEqual(self.polyalphabetic.decrypt("hi", "bye"), self.polyalphabetic.decrypt("hi", "BYE"))

        # length is preserved by affine decryption
        self.assertEqual(len(self.polyalphabetic.decrypt("plaintext", "ciphertext")), len("plaintext"))

        # happy path testing
        self.assertEqual(self.polyalphabetic.decrypt("2HZ-EQH@\ORA", "IBM 5100"), "Hello world!")
