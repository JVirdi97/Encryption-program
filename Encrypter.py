from tkinter import *
from math import gcd  # we only want the gcd function, so single it out from the math package


# RANGE OF CHARACTERS IS [chr(32), chr(127)]
class UnsupportedCharError(Exception):
    def __init__(self, details):
        self.details = details

    def __repr__(self):
        return "UnsupportedCharError. Unsupported character: {}".format(self.details)


class UndecryptableCombinationError(Exception):
    def __repr__(self):
        return "UndecryptableCombinationError. This combination cannot be decrypted. Ensure that the multiplcative " \
               "shift is coprime relative to 95."


class Caeser:
    def encrypt(self, plaintext="", shift=0):
        if not isinstance(plaintext, str):
            plaintext_type = type(plaintext)
            raise TypeError("Plaintext must be a string. You gave {}.".format(plaintext_type))
        if not isinstance(shift, int):
            shift_type = type(shift)
            raise TypeError("Shift must be an integer. You gave {}.".format(shift_type))

        shift %= 95  # shift = shift mod 95, as our alphabet length is 95

        ciphertext = ""

        for char in plaintext:
            char_num = ord(char)
            if char_num < 32 or char_num > 127:
                raise UnsupportedCharError(char)
            # need to do -32 to begin, as there if an offset of 32 from 0 for our alphabet
            char_num -= 32
            char_num += shift
            char_num %= 95
            # we subtracted 32 to put start of alphabet at zero, now add 32 to compensate before converting to chars
            char_num += 32
            ciphertext += chr(char_num)
        return ciphertext

    def decrypt(self, plaintext="", shift=0):
        shift *= -1
        return self.encrypt(plaintext, shift)


class Affine:
    # function prototypes, will complete these once I've come up with tests
    def encrypt(self, plaintext="", mul_shift=0, add_shift=0):
        if not isinstance(plaintext, str):  # if the plaintext is not a string, then we cant encrypt it
            raise TypeError("Plaintext must be a string")
        if not isinstance(mul_shift, int):  # ensure that shifts are integers
            raise TypeError("Multiplicative shift needs to be an integer.")
        if not isinstance(add_shift, int):
            raise TypeError("Additive shift needs to be an integer.")
        if plaintext == "" and mul_shift == 0 and add_shift == 0:
            return ""
        if gcd(mul_shift, 95) != 1:
            raise UndecryptableCombinationError

        # this will have characters added to it to make the encrypted message which we will return
        ciphertext = ""

        for char in plaintext:  # for each character in the original message
            if ord(char) <= 31 or ord(char) >= 128:  # check that the character is not an unsupported one
                raise UnsupportedCharError(char)
            char_num = ord(char)  # convert character to number so we can carry out encryption
            char_num -= 32  # to make it so alphabet is indexed at 0, not 32
            char_num = char_num * mul_shift + add_shift  # step 1 of encryption
            char_num %= 95  # step 2
            char_num += 32  # for conversion back, add 32 as our range is [32, 127]
            ciphertext += chr(char_num)  # turn the number back into a character, and add that to the encrypted string
        return ciphertext

    def decrypt(self):
        pass
