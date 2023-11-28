import string
from sympy import totient
import math


class CaesarCipher:
    def __init__(self, key: int):
        self.key = key
        self.__plain_text = ""
        self.__cipher_text = ""

    def encrypt(self, text: str) -> str:
        """加密"""
        result = ""
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                if is_upper:
                    encrypted_char = chr((ord(char) + self.key - ord('A')) % 26 + ord('A'))
                else:
                    encrypted_char = chr((ord(char) + self.key - ord('a')) % 26 + ord('a'))
                result += encrypted_char
            else:
                result += char
        self.__cipher_text = result
        return result

    def decrypt(self, text: str) -> str:
        """解密"""
        self.key = -self.key
        self.__plain_text = self.encrypt(text)
        self.key = -self.key
        return self.__plain_text

    def get_ciphertext(self):
        """获取密文"""
        return self.__cipher_text

    def get_plaintext(self):
        """获取明文"""
        return self.__plain_text


class KeywordCipher:
    def __init__(self, key: str):
        self.key = key
        self.__plain_text = ""
        self.__cipher_text = ""

    def generate_alphabet(self):
        # 生成关键字字母表
        keyword = self.key.upper()
        alphabet = list(string.ascii_uppercase)
        keyword_set = set(keyword)
        keyword_alphabet = [char for char in keyword + ''.join(alphabet) if char not in keyword_set]
        return keyword_alphabet

    def encrypt(self, plaintext: str) -> str:
        # 生成关键字字母表
        keyword_alphabet = self.generate_alphabet()

        # 加密
        ciphertext = ''
        for char in plaintext.upper():
            if char in string.ascii_uppercase:
                index = string.ascii_uppercase.index(char)
                ciphertext += keyword_alphabet[index]
            else:
                ciphertext += char
        self.__cipher_text = ciphertext

        return self.__cipher_text

    def decrypt(self, ciphertext: str) -> str:
        # 生成关键字字母表
        keyword_alphabet = self.generate_alphabet()

        # 解密
        plaintext = ''
        for char in ciphertext.upper():
            if char in string.ascii_uppercase:
                try:
                    index = keyword_alphabet.index(char)
                    plaintext += string.ascii_uppercase[index]
                except ValueError:
                    # 如果 char 不在关键字字母表中，直接添加到明文中
                    plaintext += char
            else:
                plaintext += char
        self.__plain_text = plaintext

        return self.__plain_text

    def get_plaintext(self) -> str:
        return self.__plain_text

    def get_ciphertext(self) -> str:
        return self.__cipher_text


class RSA:
    # 明文,写入即固定，其后加解密的结果都写入ciphertext
    __plaintext = "plaintext"
    # 密文
    __ciphertext = "ciphertext"
    # 以下为加密过程需要输入的数字，prime_p,prime_q为偶数，prime_p与prime_q相乘得到n，e与n互质。
    prime_p = 0
    prime_q = 0
    key_e = 0
    # 以下为解密过程需要输入的数字
    decrypt_key_n = 0
    decrypt_key_d = 0
    # 以下为加密完成后得到的两个密钥
    key_n = 0
    key_d = 0

    def __init__(self, keys):
        # 使用空格作为分隔符将字符串拆分为子字符串
        keys_as_strings = keys.split(";")
        if len(keys_as_strings) == 3:
            self.prime_p, self.prime_q, self.key_e = map(int, keys_as_strings)
        elif len(keys_as_strings) == 2:
            self.decrypt_key_d, self.decrypt_key_n = map(int, keys_as_strings)
        else:
            raise ValueError("ERROR:Value error")
        # 将子字符串转换为整数列表

    @staticmethod
    def _mod_inverse_(public_key_e, euler_n):  # 计算最小模反函数
        private_key_d = 1
        while 1:
            if (private_key_d * public_key_e - 1) % euler_n == 0:
                return private_key_d
            else:
                private_key_d += 1

    @staticmethod
    def _if_prime_(number):  # 判断数字是否为质数
        if number < 0:
            return 0
        counter = 0
        for i in range(1, number + 1):
            if number % i == 0:
                counter += 1
        if counter == 2:
            return 1
        else:
            return 0

    @staticmethod
    def _are_coprime_(euler_n, public_key_e):  # 判断两数是否互质
        return math.gcd(euler_n, public_key_e) == 1

    def _get_public_key_n_(self):  # 获取p，q，获取其乘积，即公钥n
        public_key_n = self.prime_p * self.prime_q
        self.key_n = public_key_n

    def _get_public_key_e_(self, public_key_n):  # 获取公钥e，并判断其是否与n的欧拉函数互质，参数为公钥n
        euler_n = totient(public_key_n)
        if self._are_coprime_(euler_n, self.key_e):  # 判断是否互质
            self.key_e = self.key_e
        else:
            raise ValueError("ERROR:This number is not coprime with the public key n")

    def get_plaintext(self):
        return self.__plaintext

    def get_ciphertext(self):
        return self.__ciphertext

    def _get_private_key_(self, euler_n):  # 获取私钥d，其为e关于n的欧拉函数的模反函数
        self.key_d = self._mod_inverse_(self.key_e, euler_n)

    def _encrypt_char_(self, plain_char):  # 加密单个字符
        plain_char_num = ord(plain_char)
        cipher_char_num = (plain_char_num ** self.key_e) % self.key_n
        return chr(cipher_char_num)

    def _decrypt_char_(self, cipher_char):  # 解密单个字符
        cipher_char_num = ord(cipher_char)
        plain_char_num = (cipher_char_num ** self.decrypt_key_d) % self.decrypt_key_n
        return chr(plain_char_num)

    def encrypt(self, plaintext):  # 加密字符串
        if self._if_prime_(self.prime_p) == 0 or self._if_prime_(
                self.prime_q) == 0 or self.prime_q <= 1 or self.prime_p <= 1 or self.key_e <= 1:  # 分别判断两数是否为质数
            raise ValueError("ERROR:Value error!")
        self._get_public_key_n_()
        if not self._are_coprime_(totient(self.key_n), self.key_e):
            raise ValueError("ERROR:Value error!")
        self._get_public_key_e_(self.key_n)
        self._get_private_key_(totient(self.key_n))
        ciphertext = ""
        for char in plaintext:
            ciphertext += self._encrypt_char_(char)
        self.__ciphertext = ciphertext
        return ciphertext

    def decrypt(self, ciphertext):  # 解密字符串
        plaintext = ""
        for char in ciphertext:
            if char == '\n':
                continue
            plaintext += self._decrypt_char_(char)
        self.__plaintext = plaintext
        return plaintext


class PlayfairCipher:

    def __init__(self, key: str):  # key 是一个字符串
        self.key = key        # 密钥初始化   # 有时间的话可以考虑一下共有私有变量（不必了）
        self.__plain_text = ""
        self.__cipher_text = ""

    def std_key(self) -> str:                # 对密钥的输入进行标准化
        key_str = self.key.lower()    # 统一为小写
        return_key = ''
        for item in key_str:
            if item == 'j':            # 将所有的 ‘j’ 都替换为  'i'
                item = 'i'
                return_key += item
            elif item not in return_key:   # 去重
                return_key += item
            else:
                continue
        return return_key

    def key_dict_space(self, text: str) -> dict:  # 用于生成标准密钥空间，是一个可以映射每个单词在密钥表中坐标的字典，密钥表在代码最下面有示例
        key_space_dict = {}
        key = text
        alphabet = "abcdefghiklmnopqrstuvwxyz"   # 字母表，方便后续生成密钥串

        for item in alphabet:        # 将密钥后半部分填充
            if item not in key:
                key += item
            else:
                continue

        x = 1
        y = 1
        for word in key:
            if x < 5:
                key_space_dict[word] = x + y*10    # 坐标表示为 ’yx‘
                x += 1
            else:
                key_space_dict[word] = x + y*10
                x = 1      # x 回滚到 1
                y += 1     # y 继续增加

        return key_space_dict

    def key_dict_mirror(self, text: str) -> dict:     # 这是用来1生成坐标对应字母的表
        key_mir_dict = {}                  # 就是把上面的函数反过来
        key = text
        alphabet = "abcdefghiklmnopqrstuvwxyz"

        for item in alphabet:  # 补 全 25 位密钥表
            if item not in key:
                key += item
            else:
                continue

        x = 1
        y = 1             # 两个坐标 与 加解密有关
        for word in key:  # 生成字典的镜像
            if x < 5:
                key_mir_dict[x + y * 10] = word
                x += 1
            else:
                key_mir_dict[x + y * 10] = word
                x = 1  # x 回滚到 1
                y += 1  # y 向前进位

        return key_mir_dict

    def std_plain_txt(self, text: str) -> str:       # 规范明文，在有连续相同字符的地方插入 q
        std_plain_txt = ''
        repeat_monitor = ''  # 一会循环时候检查有没有两个挨着的重复的检控器变量
        new_str = text.replace(' ', '')  # 除去文本中的空格
        new_str = new_str.replace('\n', '')  # 去除换行符，无奈至举，后续可以把for循环改成while循环给加回来
        new_str = new_str.lower()  # 将大写改成小写
        for item in new_str:
            if item == repeat_monitor:
                std_plain_txt += 'q'
                std_plain_txt += item
                repeat_monitor = item
            else:
                std_plain_txt += item
                repeat_monitor = item
        txt_len = len(std_plain_txt)
        if txt_len % 2 == 0:
            return std_plain_txt
        if txt_len % 2 == 1:
            std_plain_txt += 'q'
            return std_plain_txt
        else:
            return "error in fun std_plain_txt()"

    def encrypt(self, text: str) -> str:   # 加密需要传入明文  # 这里不能直接传私有参数明文码？
        std_p_txt = self.std_plain_txt(text)   # 标准明文输入
        use_key = self.std_key()               # 标准密钥
        std_ctxt = ''                          # 标准密文返回值
        key_dict = self.key_dict_space(use_key)
        key_mir_dict = self.key_dict_mirror(use_key)

        for item in range(0, len(std_p_txt), 2):
            char_1 = std_p_txt[item]
            char_2 = std_p_txt[item + 1]  # 取出两个连续的明文字符
            index_1 = key_dict[char_1]  # 字符 1 对应得坐标
            index_2 = key_dict[char_2]  # 字符 2 对应得坐标
            x_1 = index_1 % 10  # 横坐标，从左至右递增
            y_1 = (index_1 - x_1) / 10  # 纵坐标，自上而下递增
            x_2 = index_2 % 10  # python 有小数
            y_2 = (index_2 - x_2) / 10

            ctxt_1 = ''  # 加密时用到的字符暂存变量
            ctxt_2 = ''
            if y_1 == y_2:  # 两字符对应密码表中同行
                if x_1 != 5 and x_2 != 5:  # 两个字符均不在表边缘
                    ctxt_1 = key_mir_dict[y_1 * 10 + (x_1 + 1)]  # 向右着一个
                    ctxt_2 = key_mir_dict[y_2 * 10 + (x_2 + 1)]
                    std_ctxt += ctxt_1
                    std_ctxt += ctxt_2  # 密文写入。是不是本可以更节约资源一些？只是我没想到？
                elif x_1 != 5 and x_2 == 5:  # 有一方面的明文抵达边界
                    ctxt_1 = key_mir_dict[y_1 * 10 + (x_1 + 1)]
                    ctxt_2 = key_mir_dict[y_2 * 10 + 1]  # 直接将靠近边缘的重启
                    std_ctxt += ctxt_1
                    std_ctxt += ctxt_2
                elif x_1 == 5 and x_2 != 5:
                    ctxt_1 = key_mir_dict[y_1 * 10 + 1]
                    ctxt_2 = key_mir_dict[y_2 * 10 + (x_2 + 1)]
                    std_ctxt += ctxt_1
                    std_ctxt += ctxt_2
                else:
                    print("something error in plain text")
            elif x_1 == x_2:  # 两个字符在同一列
                if y_1 != 5 and y_2 != 5:
                    ctxt_1 = key_mir_dict[(y_1 + 1) * 10 + x_1]
                    ctxt_2 = key_mir_dict[(y_2 + 1) * 10 + x_2]
                    std_ctxt += ctxt_1
                    std_ctxt += ctxt_2
                elif y_1 != 5 and y_2 == 5:
                    ctxt_1 = key_mir_dict[(y_1 + 1) * 10 + x_1]
                    ctxt_2 = key_mir_dict[1 * 10 + x_2]  # 回退到第一行
                    std_ctxt += ctxt_1
                    std_ctxt += ctxt_2
                elif y_1 == 5 and y_2 != 5:
                    ctxt_1 = key_mir_dict[1 * 10 + x_1]  # 回退到第一行
                    ctxt_2 = key_mir_dict[(y_2 + 1) * 10 + x_2]
                    std_ctxt += ctxt_1
                    std_ctxt += ctxt_2
                else:
                    print("there is something error in plain text ")
            else:  # elif y_1 != y_2 & x_1 != x_2: # 既不同行也不同列
                ctxt_1 = key_mir_dict[y_1 * 10 + x_2]  # 取对角线
                ctxt_2 = key_mir_dict[y_2 * 10 + x_1]
                std_ctxt += ctxt_1
                std_ctxt += ctxt_2

        self.__cipher_text = std_ctxt    # 可以删掉，感觉这个好像对你的代码没什么用
        return std_ctxt

    def decrypt(self, text: str) -> str:
        std_ctxt = text  # 拷贝一下
        std_p_txt = ''  # 标准明文，（结尾可能含有q，中间可能含有q，后续会写函数来去掉可能的q）
        use_key = self.std_key()  # 规范key字符串
        key_dict = self.key_dict_space(use_key)
        key_mir_dict = self.key_dict_mirror(use_key)

        for item in range(0, len(std_ctxt), 2):
            char_1 = std_ctxt[item]
            char_2 = std_ctxt[item + 1]  # 取出两个连续的明文字符
            index_1 = key_dict[char_1]  # 字符 1 对应得坐标
            index_2 = key_dict[char_2]  # 字符 2 对应得坐标
            x_1 = index_1 % 10  # 横坐标，从左至右递增
            y_1 = (index_1 - x_1) / 10  # 纵坐标，自上而下递增
            x_2 = index_2 % 10  # python 有小数，mlgbz
            y_2 = (index_2 - x_2) / 10

            p_txt_1 = ''  # 加密时用到的字符暂存变量
            p_txt_2 = ''
            if y_1 == y_2:  # 两字符对应密码表中同行
                if x_1 != 1 and x_2 != 1:  # 两个字符均不在表边缘
                    p_txt_1 = key_mir_dict[y_1 * 10 + (x_1 - 1)]  # 向右着一个
                    p_txt_2 = key_mir_dict[y_2 * 10 + (x_2 - 1)]
                    std_p_txt += p_txt_1
                    std_p_txt += p_txt_2  # 密文写入。是不是本可以更节约资源一些？只是我没想到？
                elif x_1 != 1 and x_2 == 1:  # 有一方面的明文抵达边界
                    p_txt_1 = key_mir_dict[y_1 * 10 + (x_1 - 1)]
                    p_txt_2 = key_mir_dict[y_2 * 10 + 5]  # 直接将靠近边缘的重启
                    std_p_txt += p_txt_1
                    std_p_txt += p_txt_2
                elif x_1 == 1 and x_2 != 1:
                    p_txt_1 = key_mir_dict[y_1 * 10 + 5]
                    p_txt_2 = key_mir_dict[y_2 * 10 + (x_2 - 1)]
                    std_p_txt += p_txt_1
                    std_p_txt += p_txt_2
                else:
                    print("something error in plain text")
            elif x_1 == x_2:  # 两个字符在同一列
                if y_1 != 1 and y_2 != 1:
                    p_txt_1 = key_mir_dict[(y_1 - 1) * 10 + x_1]
                    p_txt_2 = key_mir_dict[(y_2 - 1) * 10 + x_2]
                    std_p_txt += p_txt_1
                    std_p_txt += p_txt_2
                elif y_1 != 1 and y_2 == 1:
                    p_txt_1 = key_mir_dict[(y_1 - 1) * 10 + x_1]
                    p_txt_2 = key_mir_dict[5 * 10 + x_2]  # 回退到第一行
                    std_p_txt += p_txt_1
                    std_p_txt += p_txt_2
                elif y_1 == 1 and y_2 != 1:
                    p_txt_1 = key_mir_dict[5 * 10 + x_1]  # 回退到第一行
                    p_txt_2 = key_mir_dict[(y_2 - 1) * 10 + x_2]
                    std_p_txt += p_txt_1
                    std_p_txt += p_txt_2
                else:
                    print("there is something error in plain text ")
            else:  # elif y_1 != y_2 & x_1 != x_2: # 既不同行也不同列
                p_txt_1 = key_mir_dict[y_1 * 10 + x_2]  # 取对角线
                p_txt_2 = key_mir_dict[y_2 * 10 + x_1]  # 取对角的解密时候不用变
                std_p_txt += p_txt_1
                std_p_txt += p_txt_2

        # 去除没有用的 占位 字符 ‘q’
        counter = 0
        std_p_txt_2 = ''
        for item_2 in std_p_txt:
            if counter < len(std_p_txt) - 1:
                if std_p_txt[counter] == 'q' and std_p_txt[counter - 1] == std_p_txt[counter + 1]:
                    counter += 1
                    continue
                else:
                    std_p_txt_2 += std_p_txt[counter]
                    counter += 1
            elif counter == len(std_p_txt) - 1 and std_p_txt[counter] == 'q':
                break
            elif counter == len(std_p_txt) - 1 and std_p_txt[counter] != 'q':
                std_p_txt_2 += std_p_txt[counter]
            else:
                print("error when delete charactar 'q")

        self.__plain_text = std_p_txt_2
        return std_p_txt_2

    def get_ciphertext(self):
        return self.__cipher_text

    def get_plaintext(self):
        return self.__plain_text

    def set_plaintext(self, text: str):
        # 设置明文
        self.__plain_text = text

    def set_ciphertext(self):
        # 设置密文   我觉得可以直接用这个设置1明文密文，这样加密函数就不用设置入口参数了，可以直接啥都不设置
        self.__cipher_text = self.decrypt(self.__plain_text)
