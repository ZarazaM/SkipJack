class SkipJack:
    def __init__(self):

        self.__TABLE_F = []
        self._define_F()

        self.__w1 = 0
        self.__w2 = 0
        self.__w3 = 0
        self.__w4 = 0

    def _define_F(self):
        from skipjackfolder.skipjack_consts import TABLE_F
        self.__TABLE_F = TABLE_F

    def encrypt(self, plaintext, key):
        """
        encode message
        :param plaintext: 64-bit integer value
        :param key: list with length 10, each value is 1 byte
        :return: 64-bit integer ciphertext
        """

        self._split_words(plaintext)

        for round_num in range(1, 33):
            if (1 <= round_num <= 8) or (17 <= round_num <= 24):
                self._A_rule(round_num, key)
                # self._print_status(round_num)
            if (9 <= round_num <= 16) or (25 <= round_num <= 32):
                self._B_rule(round_num, key)
                # self._print_status(round_num)

        return self._append_words()

    def decrypt(self, ciphertext, key):
        """
        decode message
        :param ciphertext: 64-bit integer ciphertext
        :param key: list with length 10, each value is 1 byte
        :return: 64-bit integer deciphered text
        """

        self._split_words(ciphertext)

        for round_num in reversed(range(1, 33)):
            if (25 <= round_num <= 32) or (9 <= round_num <= 16):
                self._B_rule_inverse(round_num, key)
                # self._print_status(round_num)
            if (17 <= round_num <= 24) or (1 <= round_num <= 8):
                self._A_rule_inverse(round_num, key)
                # self._print_status(round_num)

        return self._append_words()

    def _A_rule(self, round_num, key):
        """
        performs A rule
        :param round_num: current round number
        :param key: list with length 10, each value is 1 byte
        :return:
        """
        c1 = self.__w1
        c2 = self.__w2
        c3 = self.__w3
        self.__w1 = self._G_permutation(round_num, key, c1) ^ self.__w4 ^ round_num
        self.__w2 = self._G_permutation(round_num, key, c1)
        self.__w3 = c2
        self.__w4 = c3

    def _A_rule_inverse(self, round_num, key):
        """
        performs A^-1 rule
        :param round_num: current round number
        :param key: list with length 10, each value is 1 byte
        :return:
        """
        c1 = self.__w1
        c2 = self.__w2
        self.__w1 = self._G_permutation_inverse(round_num, key, c2)
        self.__w2 = self.__w3
        self.__w3 = self.__w4
        self.__w4 = c1 ^ c2 ^ round_num

    def _B_rule(self, round_num, key):
        """
        performs B rule
        :param round_num: current round number
        :param key: list with length 10, each value is 1 byte
        :return:
        """
        c1 = self.__w1
        c2 = self.__w2
        c3 = self.__w3
        self.__w1 = self.__w4
        self.__w2 = self._G_permutation(round_num, key, c1)
        self.__w3 = c1 ^ c2 ^ round_num
        self.__w4 = c3

    def _B_rule_inverse(self, round_num, key):
        """
        performs B^-1 rule
        :param round_num: current round number
        :param key: list with length 10, each value is 1 byte
        :return:
        """
        c1 = self.__w1
        self.__w1 = self._G_permutation_inverse(round_num, key, self.__w2)
        self.__w2 = self._G_permutation_inverse(round_num, key, self.__w2) ^ self.__w3 ^ round_num
        self.__w3 = self.__w4
        self.__w4 = c1

    def _G_permutation(self, round_num, key, w):
        """
        performs G permutation
        :param round_num: current round number
        :param key: list with length 10, each value is 1 byte
        :param w: 16-bit word
        :return: 16-bit word after G permutation
        """
        g = [0 for _ in range(6)]
        g[0] = (w >> 8) & 0xff
        g[1] = w & 0xff
        j = (4 * (round_num - 1)) % 10

        for i in range(2, 6):
            g[i] = self.__TABLE_F[g[i - 1] ^ key[j]] ^ g[i - 2]
            j = (j + 1) % 10

        return (g[4] << 8) | g[5]

    def _G_permutation_inverse(self, round_num, key, w):
        """
        performs G^-1 permutation
        :param round_num: current round number
        :param key: list with length 10, each value is 1 byte
        :param w: 16-bit word
        :return: 16-bit word after G^-1 permutation
        """

        g = [0 for _ in range(6)]
        g[4] = (w >> 8) & 0xff
        g[5] = w & 0xff
        j = (4 * (round_num - 1) + 3) % 10

        for i in reversed(range(4)):
            g[i] = self.__TABLE_F[g[i + 1] ^ key[j]] ^ g[i + 2]
            j = (j - 1) % 10

        return (g[0] << 8) | g[1]

    def _append_words(self):
        """
        concatenate 4 16-bit words into 1 64-bit word
        :return: 64-bit length word
        """

        x1 = self.__w1 << 3 * 16
        x2 = self.__w2 << 2 * 16
        x3 = self.__w3 << 1 * 16
        x4 = self.__w4
        return x1 | x2 | x3 | x4

    def _split_words(self, w):
        """
        split 64-bit word into 4 16-bit words
        :param w: 64-bit word
        :return:
        """

        self.__w1 = (w >> (16 * 3)) & 0xffff
        self.__w2 = (w >> (16 * 2)) & 0xffff
        self.__w3 = (w >> (16 * 1)) & 0xffff
        self.__w4 = w & 0xffff

    def _print_status(self, round_num):
        """
        print current cipher value
        :param round_num: current round number
        :return:
        """

        w = self._append_words()
        print('round = ' + str(round_num) + ' ' + hex(w))

    @staticmethod
    def convert_input_text(user_input):
        """
        convert source text into 64-bit integer blocks
        :param user_input: source text
        :return: list with 64-bit integer blocks
        """

        word_list = [ord(symbol) for symbol in user_input]

        if len(word_list) % 4 != 0:
            for i in range(4 - (len(word_list) % 4)):
                word_list.append(0)

        result_list = []
        for word in range(len(word_list) // 4):
            p1 = word_list[0 + word * 4] << 16 * 3
            p2 = word_list[1 + word * 4] << 16 * 2
            p3 = word_list[2 + word * 4] << 16 * 1
            p4 = word_list[3 + word * 4]

            result_list.append(p1 | p2 | p3 | p4)

        return result_list


# PT = 0x1307605513076055
# KEY = [0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
#
# sj = SkipJack()
# CT = sj.encrypt(PT, KEY)
#
# DT = sj.decrypt(CT, KEY)
#
# print('Plain text: ' + hex(PT))
# print('Cipher text: ' + hex(CT))
# print('Decrypted text: ' + hex(DT))
