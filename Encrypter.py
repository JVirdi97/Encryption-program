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

    def decrypt(self, ciphertext="", mul_shift=0, add_shift=0):
        if not isinstance(ciphertext, str):  # if the ciphertext is not a string, then we cant decrypt it
            raise TypeError("Ciphertext must be a string")
        if not isinstance(mul_shift, int):  # ensure that shifts are integers
            raise TypeError("Multiplicative shift needs to be an integer.")
        if not isinstance(add_shift, int):
            raise TypeError("Additive shift needs to be an integer.")
        if ciphertext == "" and mul_shift == 0 and add_shift == 0:
            return ""
        if gcd(mul_shift, 95) != 1:
            raise UndecryptableCombinationError

        plaintext = ""
        for i in ciphertext:
            char_num = ord(i)
            if ord(i) > 127 or 32 > ord(i):
                raise UnsupportedCharError(i)
            char_num -= 32
            """  Detailed explanation of next step 
            Suppose we have an alphabet with length l and an integer a satisfying 0 < a < l. Then from Euler's
            theorem, given that gcd(a, m) = 1,
                                            a^tot(l) = 1 (mod l) 
            tot(l) is the Euler totient function of l, which counts the number of coprime integers greater than 0 and
            less than l. It follows that a^[tot(l)-1] = a^(-1) (mod l).
            We have an alphabet length of 95, with tot(95) = 72. So our modular multiplicative inverse is given by
                                            a^(-1) = a^71 (mod 95)
            For affine encryption we are given a character C, a multiplicative shift M and an additive shift A. To 
            encrypt a character we calculate the following:
                                            CM+A (mod 95)
            To reverse this, we calculate:
                                            (C-A)*M^(-1) (mod 95)
            We have a way to compute the inverse of M from above, so applying that gives us our new inverse formula:
                                            (C-A)*(M^71) (mod 95)
            NOTE: these formulas assume the alphabet is indexed at 0. Ours is indexed at 32 but that just means we need
                  to subtract 32 before applying these formulas and then add 32 afterwards.                                            
            """
            char_num -= add_shift
            char_num *= (mul_shift ** 71)
            char_num %= 95
            char_num += 32
            plaintext += chr(char_num)
        return plaintext


class Polyalphabetic:
    def encrypt(self, plaintext="", keystring=""):
        # get a word, turn that word into sequence of numbers, use numbers for caeser ciphers, repeat num list until
        # end of plaintext, and thats your ciphertext
        if not isinstance(plaintext, str):
            raise TypeError("Plaintext needs to be a string")
        if not isinstance(keystring, str):
            raise TypeError("Key needs to be a string")

        ciphertext = ""
        shift_list = []  # to store our shifts in for when calling the caeser cipher
        for i in keystring:  # turning keystring into list of shifts for caeser cipher
            if 127 < ord(i) or ord(i) < 32:
                raise UnsupportedCharError(i)
            shift_list.append(ord(i))

        len_shift_list = len(shift_list)
        caeser = Caeser()  # rather than creating a new Caeser instance each iteration, just make 1 here
        for i in range(0, len(plaintext)):
            if 127 < ord(plaintext[i]) or ord(plaintext[i]) < 32:
                raise UnsupportedCharError(i)
            index = i % len_shift_list  # to keep index within shift_list or we'd get IndexError
            ciphertext += caeser.encrypt(plaintext[i], shift_list[index])
        return ciphertext

    def decrypt(self, ciphertext="", keystring=""):
        if not isinstance(ciphertext, str):
            raise TypeError("Ciphertext needs to be a string")
        if not isinstance(keystring, str):
            raise TypeError("Key needs to be a string")

        plaintext = ""
        shift_list = []  # to store our shifts in for when calling the caeser cipher
        for i in keystring:  # turning keystring into list of shifts for caeser cipher
            if 127 < ord(i) or ord(i) < 32:
                raise UnsupportedCharError(i)
            shift_list.append(ord(i))

        len_shift_list = len(shift_list)
        caeser = Caeser()  # rather than creating a new Caeser instance each iteration, just make 1 here
        for i in range(0, len(ciphertext)):
            if 127 < ord(ciphertext[i]) or ord(ciphertext[i]) < 32:
                raise UnsupportedCharError(i)
            index = i % len_shift_list  # to keep index within shift_list or we'd get IndexError
            plaintext += caeser.decrypt(ciphertext[i], shift_list[index])
        return plaintext
