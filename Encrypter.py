import tkinter
from math import gcd
from tkinter import *
from tkinter import ttk

# To display to the user if they want to find out what alphabet we use.
listAlphabet = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l",
                "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x",
                "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
                "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V",
                "W", "X", "Y", "Z", "1", "2", "3", "4", "5", "6", "7", "8",
                "9", "0", ".", ",", "?", " "]

# We'll use this dictionary to convert from numbers to letters and vice versa
alphabetDict = {0: "a", 1: "b", 2: "c", 3: "d", 4: "e", 5: "f", 6: "g",
                7: "h", 8: "i", 9: "j", 10: "k", 11: "l", 12: "m", 13: "n",
                14: "o", 15: "p", 16: "q", 17: "r", 18: "s", 19: "t", 20: "u",
                21: "v", 22: "w", 23: "x", 24: "y", 25: "z", 26: "A", 27: "B",
                28: "C", 29: "D", 30: "E", 31: "F", 32: "G", 33: "H", 34: "I",
                35: "J", 36: "K", 37: "L", 38: "M", 39: "N", 40: "O", 41: "P",
                42: "Q", 43: "R", 44: "S", 45: "T", 46: "U", 47: "V", 48: "W",
                49: "X", 50: "Y", 51: "Z", 52: "1", 53: "2", 54: "3", 55: "4",
                56: "5", 57: "6", 58: "7", 59: "8", 60: "9", 61: "0", 62: ".",
                63: ",", 64: "?", 65: "!", 66: " "}

alphabet_length = len(listAlphabet)


def convert_letter_to_num(letter):
    """ To go from number to letter, we just use alphabetDict[number],
        this function does the reverse."""
    alphabet_dict_values = list(alphabetDict.values())
    return alphabet_dict_values.index(letter)


class UnsupportedCharError(Exception):
    """ Raised when a character which is not in our alphabet is in the
        plaintext/ciphertext. """

    def __init__(self, details=""):
        self.details = details

    def __repr__(self):
        return "UnsupportedCharError. Unsupported character: " \
               "{}".format(self.details)


class UndecryptableCombinationError(Exception):
    """ Raised when a shift is not coprime with 41, meaning that the
        encryption cannot be reversed. For the affine decryption function """

    def __init__(self, details=""):
        self.details = details

    def __repr__(self):
        return "UndecryptableCombinationError. {}".format(self.details)


class EmptyTextError(Exception):
    """ Raised when either plaintext or ciphertext is "" """

    def __repr__(self):
        return "EmptyTextError. Cannot operate on an empty string."


class EmptyShiftError(Exception):
    """ Raised when the shift is either 0, or an empty matrix/string """

    def __repr__(self):
        return "Key is empty, encryption cannot be performed."


class Caeser:
    @staticmethod
    def encrypt(plaintext="", shift=0):
        # region validation checks
        try:
            shift = int(shift)
        except ValueError:
            return "Shift must be an integer. No decimal points are allowed."
        if plaintext == "":
            return "Cannot operate on an empty string."
        if shift == 0:
            return "Cannot operate with shift equal to zero."
        # endregion

        ciphertext = ""
        for char in plaintext:
            # check that the character is in our alphabet
            if char not in listAlphabet:
                raise UnsupportedCharError(char)
            char_num = convert_letter_to_num(char)
            # mod 42 -> [0, 41], which is our alphabet range.
            char_num += shift
            char_num %= alphabet_length
            ciphertext += alphabetDict[char_num]
        return ciphertext

    def decrypt(self, ciphertext, shift):
        return self.encrypt(ciphertext, -shift)


class Affine:
    @staticmethod
    def encrypt(plaintext, mul_shift, add_shift):
        # region validation checks
        for i in mul_shift:
            if not (48 < ord(i) < 57):
                return "Multiplicative shift needs to be an integer."
        for j in add_shift:
            if not (48 < ord(j) < 57):
                return "Additive shift needs to be an integer."
        if plaintext == "":
            return "Cannot operate on an empty string."
        if add_shift == 0 and mul_shift == 0:
            return "Cannot operate with shifts equal to zero."
        if gcd(mul_shift, alphabet_length) != 1:
            return "This combination is undecryptable. Please choose a " \
                   "different shift."
        # endregion

        ciphertext = ""
        for char in plaintext:
            # check that the character is not an unsupported one
            if char not in listAlphabet:
                raise UnsupportedCharError(char)
            # convert character to number
            char_num = alphabetDict[char]
            char_num = char_num * mul_shift + add_shift
            char_num %= alphabet_length
            # turn the number back into a character, and add it to ciphertext
            ciphertext += alphabetDict[char_num]
        return ciphertext

    @staticmethod
    def decrypt(ciphertext, mul_shift, add_shift):
        # region validation checks
        if not isinstance(ciphertext, str):
            raise TypeError("Plaintext must be a string")
        if not isinstance(mul_shift, int):
            raise TypeError("Multiplicative shift needs to be an integer.")
        if not isinstance(add_shift, int):
            raise TypeError("Additive shift needs to be an integer.")
        if ciphertext == "":
            raise EmptyTextError()
        if add_shift == 0 and mul_shift == 0:
            raise EmptyShiftError()
        if gcd(mul_shift, alphabet_length) != 1:
            raise UndecryptableCombinationError
        # endregion

        plaintext = ""
        char_num = 0
        for i in ciphertext:
            if i not in alphabetDict.values():
                raise UnsupportedCharError(i)
            """  Detailed explanation of next step 
            Suppose we have an alphabet with length l and an integer a 
            satisfying 0 < a < l. Then from Euler's theorem, given that 
            gcd(a, m) = 1,
                                            a^tot(l) = 1 (mod l) 
            tot(l) is the Euler totient function of l, which counts the 
            number of coprime integers greater than 0 and less than l. It 
            follows that a^[tot(l)-1] = a^(-1) (mod l).
            We have an alphabet length of 41, with tot(41) = 40. So our 
            modular multiplicative inverse is given by
                                            a^(-1) = a^39 (mod 41)
            For affine encryption we are given a character C, a multiplicative 
            shift M and an additive shift A. To encrypt a character we 
            calculate the following:
                                            CM+A (mod 41)
            To reverse this, we calculate:
                                            (C-A)*M^(-1) (mod 41)
            We have a way to compute the inverse of M from above, so applying 
            that gives us our new inverse formula:
                                            (C-A)*(M^39) (mod 41)
            """
            char_num -= add_shift
            char_num *= (mul_shift ** 23)
            char_num %= alphabet_length
            plaintext += alphabetDict[char_num]
        return plaintext


class Polyalphabetic:
    @staticmethod
    def encrypt(plaintext="", keystring=""):
        # get a word, turn that word into sequence of numbers, use numbers for caeser ciphers, repeat num list until
        # end of plaintext, and thats your ciphertext

        # region validation checks
        if not isinstance(plaintext, str):
            raise TypeError("Plaintext needs to be a string")
        if not isinstance(keystring, str):
            raise TypeError("Key needs to be a string")
        if plaintext == "":
            raise EmptyTextError
        if keystring == "":
            raise EmptyShiftError
        # endregion

        ciphertext = ""
        shift_list = []  # to store our shifts in for when calling the caeser cipher
        for i in keystring:  # turning keystring into list of shifts for caeser cipher
            if i not in listAlphabet:
                raise UnsupportedCharError(i)
            shift_list.append(convert_letter_to_num(i))

        len_shift_list = len(shift_list)
        caeser = Caeser()  # rather than creating a new Caeser instance each iteration, just make 1 here
        for i in range(0, len(plaintext)):
            if i not in listAlphabet:
                raise UnsupportedCharError(str(i))
            index = i % len_shift_list  # to keep index within shift_list or we'd get IndexError
            ciphertext += caeser.encrypt(plaintext[i], shift_list[index])
        return ciphertext

    @staticmethod
    def decrypt(ciphertext="", keystring=""):
        # region validation checks
        if not isinstance(ciphertext, str):
            raise TypeError("Ciphertext needs to be a string")
        if not isinstance(keystring, str):
            raise TypeError("Key needs to be a string")
        if ciphertext == "":
            raise EmptyTextError
        if keystring == "":
            raise EmptyShiftError
        # endregion

        plaintext = ""
        shift_list = []  # to store our shifts in for when calling the caeser cipher
        for i in keystring:  # turning keystring into list of shifts for caeser cipher
            if i not in listAlphabet:
                raise UnsupportedCharError(i)
            shift_list.append(convert_letter_to_num(i))

        len_shift_list = len(shift_list)
        caeser = Caeser()  # rather than creating a new Caeser instance each iteration, just make 1 here
        for i in range(0, len(ciphertext)):
            if ciphertext[i] not in listAlphabet:
                raise UnsupportedCharError(ciphertext[i])
            index = i % len_shift_list  # to keep index within shift_list, or we'd get IndexError
            plaintext += caeser.decrypt(ciphertext[i], shift_list[index])
        return plaintext


def patch():
    """ This function will determine which function needs to be called,
        and calls the appropriate function. """
    patch_dict = {0: Caeser.encrypt, 1: Affine.encrypt, 2: Polyalphabetic.encrypt,
                  3: Caeser.decrypt, 4: Affine.decrypt, 5: Polyalphabetic.decrypt}
    fn_no = 0
    print("This is to get rid of the warnings...{}{}".format(str(patch_dict), str(fn_no)))

    # if encryptVar.get() == "Decrypt":
    #     fn_no = 3
    # if encryptTypeVar.get() == "Caeser":
    #     fn_no += 0
    # elif encryptTypeVar.get() == "Affine":
    #     fn_no += 1
    # elif encryptTypeVar.get() == "Polyalphabetic":
    #     fn_no += 2
    #
    # if encryptTypeVar.get() == "Affine":
    #     result = patch_dict[fn_no](operand_tb.get(), affine2.get(), op_key.get())
    # else:
    #     result = patch_dict[fn_no](operand_tb.get(), op_key.get())


class App(tkinter.Tk):
    def __init__(self):
        super().__init__()

        self.geometry("400x320")
        self.title("Encryption system")

        # encrypt options:
        self.encryptOptions = ["Encrypt", "Decrypt"]
        self.encryptOptionVar = tkinter.StringVar(self, "Encrypt")

        # encrypt type options:
        self.encryptTypeOptions = ["Caeser", "Affine", "Polyalphabetic"]
        self.encryptTypeOptionVar = tkinter.StringVar(self, "Caeser")

        # choose type of encryption
        self.encrypt_type_dd = ttk.OptionMenu(self,
                                              self.encryptTypeOptionVar,
                                              *self.encryptTypeOptions,
                                              command=self.affine_changed)

        # affine entry
        self.affine2_entry = ttk.Entry(self, width=30, state="disabled")

        self.create_widgets()

    def create_widgets(self):
        paddings = {'padx': 5, 'pady': 5}

        # encrypt/decrypt
        encrypt_option_label = ttk.Label(self, text="Encrypt or decrypt?")
        encrypt_option_label.grid(row=0, column=0, sticky=W, **paddings)

        encrypt_option_dd = ttk.OptionMenu(self,
                                           self.encryptOptionVar,
                                           self.encryptOptions[0],
                                           *self.encryptOptions)
        encrypt_option_dd.grid(column=1, row=0)

        # encryption type e.g. affine
        encrypt_type_label = ttk.Label(self, text="Encryption type: ")
        encrypt_type_label.grid(row=1, column=0)

        self.encrypt_type_dd = ttk.OptionMenu(self,
                                              self.encryptTypeOptionVar,
                                              self.encryptTypeOptions[0],
                                              *self.encryptTypeOptions,
                                              command=self.affine_changed)
        self.encrypt_type_dd.grid(row=1, column=1)

        operand_label = ttk.Label(self, text="Text to operate on: ")
        operand_label.grid(column=0, row=2)

        operand_entry = ttk.Entry(self, width=30)
        operand_entry.grid(column=1, row=2)

        operator_label = ttk.Label(self, text="Key: ")
        operator_label.grid(column=0, row=3)
        operator_entry = ttk.Entry(self, width=30)
        operator_entry.grid(column=1, row=3)

        affine2_label = ttk.Label(self, text="Second affine variable: ")
        affine2_label.grid(column=0, row=4)

        self.affine2_entry.grid(column=1, row=4)

        go_btn = ttk.Button(self, text="Go!", command=patch)
        go_btn.grid(column=0, row=5)

        result_label = ttk.Label(self, text="Result: ")
        result_label.grid(column=0, row=6)

        result_box = ttk.Entry(self, width=40)
        result_box.grid(column=1, row=6)

    def affine_changed(self, *args):
        if self.encryptTypeOptionVar.get() == "Affine":
            self.affine2_entry["state"] = "enabled"
        else:
            self.affine2_entry["state"] = "disabled"


if __name__ == "__main__":
    app = App()
    app.mainloop()
