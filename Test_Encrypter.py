from Encrypter import *
import unittest
import Encrypter


# range of characters the encrypter supports is [31, 127]

class TestClass(unittest.TestCase):
    def setUp(self):
        self.caeser = Encrypter.Caeser()
        self.affine = Encrypter.Affine()

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
        self.assertRaises(TypeError, self.affine.encrypt, True, 7, 2)  # first argument has to be string
        # second and third argument has to be an int
        self.assertRaises(TypeError, self.affine.encrypt, "irrelevant string", "7", 2)
        self.assertRaises(TypeError, self.affine.encrypt, "irrelevant string", 7, "2")

        # if you give an unsupported character, it raises an error
        self.assertRaises(UnsupportedCharError, self.affine.encrypt, "{}".format(chr(31)), -9, 12)
        self.assertRaises(UnsupportedCharError, self.affine.encrypt, "{}".format(chr(128)), -9, 12)

        # giving the function nothing results in "" being returned
        self.assertEqual(self.affine.encrypt(), "")

    def test_affine_decrypt(self):
        pass

    def test_polyalphabetic_encrypt(self):
        # get a word, turn that word into sequence of numbers, use numbers for caeser ciphers, repeat num list until
        # end of plaintext, and thats your ciphertext
        pass

    def test_polyalphabetic_decrypt(self):
        pass
