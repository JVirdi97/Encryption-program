from tkinter import *


# RANGE OF CHARACTERS IS [chr(32), chr(127)]

class UnsupportedCharError(Exception):
    def __init__(self, details):
        self.details = details

    def __repr__(self):
        return "UnsupportedCharError. Unsupported character: {}".format(self.details)


class Caeser:
    def encrypt(self, expression="", shift=0):
        if not isinstance(expression, str):
            expression_type = type(expression)
            raise TypeError("Expression must be a string. You gave {}.".format(expression_type))
        if not isinstance(shift, int):
            shift_type = type(shift)
            raise TypeError("Shift must be an integer. You gave {}.".format(shift_type))

        shift %= 95  # shift = shift mod 95, as our alphabet length is 95

        ciphertext = ""

        for char in expression:
            char_num = ord(char)
            if char_num < 32 or char_num > 127:
                raise UnsupportedCharError(char)
            char_num -= 32
            char_num += shift
            char_num %= 95
            char_num += 32
            ciphertext += chr(char_num)
        return ciphertext

    def decrypt(self, expression="", shift=0):
        shift *= -1
        return self.encrypt(expression, shift)


class Affine:
    # function prototypes, will complete these once I've come up with tests
    def encrypt(self):
        pass

    def decrypt(self):
        pass


# for i in range(32, 127):
#     print("'{}'".format(chr(i)))
