import binascii
import string
from sympy import totient
import math
from copy import deepcopy
import base64


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


class VigenereCipher:
    def __init__(self, key):
        self.key = key
        self.__plain_text = ""
        self.__cipher_text = ""

    def encrypt(self, text):
        key = self.key
        encrypted_text = ''
        key_repeated = (key * (len(text) // len(key) + 1))[:len(text)]

        for i in range(len(text)):
            char = text[i]
            if char.isalpha():
                shift = ord(key_repeated[i].upper()) - ord('A')
                encrypted_char = chr((ord(char.upper()) - ord('A') + shift) % 26 + ord('A'))
                # 保持原文大小写形式
                if char.islower():
                    encrypted_char = encrypted_char.lower()
                encrypted_text += encrypted_char
            else:
                encrypted_text += char

        return encrypted_text

    def decrypt(self, text):
        key = self.key
        decrypted_text = ''
        key_repeated = (key * (len(text) // len(key) + 1))[:len(text)]

        for i in range(len(text)):
            char = text[i]
            if char.isalpha():
                shift = ord(key_repeated[i].upper()) - ord('A')
                decrypted_char = chr((ord(char.upper()) - ord('A') - shift) % 26 + ord('A'))
                # 保持原文大小写形式
                if char.islower():
                    decrypted_char = decrypted_char.lower()
                decrypted_text += decrypted_char
            else:
                decrypted_text += char

        return decrypted_text


class PermutationCipher:
    def __init__(self, key):
        self.key = key
        self.__plain_text = ""
        self.__cipher_text = ""
    # 处理密钥获取密钥的长度及顺序

    def processsecretkey(self, s):
        sLength = len(s)
        tempList = []
        for i in range(len(s)):
            char = s[i]
            # tempList存入密钥单词中字母的ascii码值
            tempList.append(ord(char))
        # tempList2用于存储密钥单词每个字母在列表的顺序
        sKey = []
        # sort_tempList用于存储排序后的tempList
        sort_tempList = sorted(tempList)
        for index_,value in enumerate(tempList):
            sKey.append(sort_tempList.index(value)+1)

        return sKey,sLength

    def encrypt(self, text):
        s = self.key
        # 除去明文中的空格
        tempList = text.split(" ")
        newText = "".join(tempList)
        # 获取处理后明文的长度
        textLength = len(newText)
        # print("text:",newText)
        # 获取密钥及密钥长度
        sKey,sLength = self.processsecretkey(s)

        # 对于长度不够处理后的明文进行补A处理
        while textLength % sLength != 0:
            newText+="A"
            textLength = textLength + 1

        # 更新处理后明文的长度
        textLength = len(newText)
        # print(f"textLength:{textLength}")

        # 根据密钥的长度对明文进行分割
        counter = 1
        temp = []
        tmp = []
        for item_ in newText:
            if  (counter % (sLength) != 0):
                tmp.append(item_)
                counter+=1

            elif  (counter % (sLength) == 0):
                tmp.append(item_)
                temp.append(tmp)
                tmp=[]
                counter+=1

        # 根据密钥对明文进行移位
        for item_ in temp:
            item_copy = deepcopy(item_)
            for i in range(len(item_)):
                item_[i] = item_copy[sKey[i]-1]

        # 对移位后的明文进行拼接形成密文
        ss = ''
        for item_ in temp:
            ss += "".join(item_)
        self.__cipher_text = ss
        return ss

    # 解密
    def decrypt(self, text):
        s = self.key
        # 获取密钥及密钥长度
        sKey, sLength = self.processsecretkey(s)

        # 根据密钥的长度对密文进行分割
        newText = text
        counter = 1
        temp = []
        tmp = []
        for item_ in newText:
            if (counter % (sLength) != 0):
                tmp.append(item_)
                counter += 1

            elif (counter % (sLength) == 0):
                tmp.append(item_)
                temp.append(tmp)
                tmp = []
                counter += 1
        # print(temp)

        # 根据密钥对密文进行移位复原
        for item_ in temp:
            item_copy = deepcopy(item_)
            # print("解密前：",item_)
            for i in range(len(item_)):
                item_[sKey[i] - 1] = item_copy[i]
            # print("解密后：",item_)

        # 对移位复原后的密文进行拼接形成明文
        ss = ''
        for item_ in temp:
            ss += "".join(item_)
        #  除去尾部可能出现的A
        ss = ss.strip("A")
        self.__plain_text = ss
        return ss


class AutokeyCipher:
    def __init__(self, key):
        self.key = key
        self.__plain_text = ""
        self.__cipher_text = ""

    def encrypt(self, text):
        key = self.key
        encrypted_text = ""
        keystream = key
        while len(keystream) < len(text):
            keystream += text[len(keystream) - len(key)]

        for i in range(len(text)):
            char = text[i]
            if char.isalpha():
                shift = ord(keystream[i].upper()) - ord('A')
                encrypted_char = chr((ord(char.upper()) - ord('A') + shift) % 26 + ord('A'))
                # 保持原文大小写形式
                if char.islower():
                    encrypted_char = encrypted_char.lower()
                encrypted_text += encrypted_char
            else:
                encrypted_text += char

        return encrypted_text

    def decrypt(self, text):
        key = self.key
        decrypted_text_with_key = ''
        keystream = key
        while len(keystream) < len(text):
            keystream += text[len(keystream) - len(key)]

        for i in range(len(text)):
            char = text[i]
            if char.isalpha():
                shift = ord(key[i].upper()) - ord('A')
                decrypted_char = chr((ord(char.upper()) - ord('A') - shift) % 26 + ord('A'))
                # 保持原文大小写形式
                if char.islower():
                    decrypted_char = decrypted_char.lower()
                decrypted_text_with_key += decrypted_char
                key += decrypted_char
            else:
                decrypted_text_with_key += char
        decrypted_text = decrypted_text_with_key
        return decrypted_text


class RC4:
    def __init__(self, key):
        self.key = key
        self.__plain_text = ""
        self.__cipher_text = ""

    @staticmethod
    def rc4_setup(key):
        """RC4初始化"""
        if isinstance(key, str):
            key = key.encode()

        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        return S

    def rc4_crypt(self, data):
        """RC4加解密"""
        if isinstance(data, str):
            data = data.encode()

        S = self.rc4_setup(self.key)
        i, j = 0, 0
        res = []
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            res.append(byte ^ S[(S[i] + S[j]) % 256])

        return bytes(res)

    def rc4_encrypt_base64(self, data):
        """RC4加密并转换为base64格式"""
        encrypted_data = self.rc4_crypt(data)
        return base64.b64encode(encrypted_data).decode()

    def rc4_decrypt_base64(self, data):
        """base64格式解码后RC4解密"""
        encrypted_data = base64.b64decode(data)
        return self.rc4_crypt(encrypted_data).decode()

    def encrypt(self, text):
        """RC4加密"""
        return self.rc4_encrypt_base64(text)

    def decrypt(self, text):
        """RC4解密"""
        return self.rc4_decrypt_base64(text)


class DH:
    # 以下变量为两人共享
    prime_q = 0  # 质数（用户协商提供）
    integer_a = 0  # 被q的原根（用户协商提供）
    # 以下变量为二人分别持有
    private_key_x = 0  # 整数x（用户分别提供）
    key_y = 0  # 用户分别计算得出
    # 以下变量为二人各自计算出的共享密钥
    public_key_k = 0

    def __init__(self, keys: str):  # 初始化函数
        # 使用空格作为分隔符将字符串拆分为子字符串
        keys_as_strings = keys.split(";")
        if len(keys_as_strings) != 3 and len(keys_as_strings) != 4:
            raise ValueError("ERROR:Value error!")
        self.prime_q = int(keys_as_strings[0])
        self.integer_a = int(keys_as_strings[1])
        self.private_key_x = int(keys_as_strings[2])
        if self.prime_q <= 1 or self._if_prime_(self.prime_q) != 1 or self.integer_a <= 0 or self.is_primitive_root(
                self.integer_a, self.prime_q) == False or self.private_key_x <= 0:
            raise ValueError("ERROR:Value error!")
        self.kk = self.get_key_y()
        if len(keys_as_strings) == 4:
            self.key = int(keys_as_strings[3])
            self.kk = self.get_public_key_k()


    def get_key_y(self):  # 第一次
        self.key_y = (self.integer_a ** self.private_key_x) % self.prime_q
        return self.key_y

    def get_public_key_k(self):  # 获取对方的key_y并计算出k（第二次）
        public_key_k = (self.key ** self.private_key_x) % self.prime_q
        return public_key_k

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
    def is_primitive_root(a, n):  # 判断a是否为n的原根
        phi = totient(n)
        powers = set()
        for i in range(1, phi + 1):
            power = pow(a, i, n)  # a^i%n
            if power in powers:  # 都不重复是原根
                return False
            powers.add(power)
        return True


class ColumnPermutationCipher:
    def __init__(self, key: str):
        self.key = [int(x) for x in key.split(';')]

    def encrypt(self, plaintext):
        # 计算需要添加的填充字符数
        padding = len(plaintext) % len(self.key)
        if padding != 0:
            plaintext += 'X' * (len(self.key) - padding)

        # 创建二维矩阵，以便按列排列
        matrix = [list(plaintext[i:i+len(self.key)]) for i in range(0, len(plaintext), len(self.key))]

        # 按照密钥的顺序排列列
        encrypted_text = ''
        for col in self.key:
            for row in matrix:
                encrypted_text += row[col]

        return encrypted_text

    def decrypt(self, ciphertext):
        # 计算矩阵的行数
        rows = len(ciphertext) // len(self.key)

        # 根据密钥创建二维矩阵，以便按列排列
        matrix = [['' for _ in range(len(self.key))] for _ in range(rows)]

        # 按照密钥的顺序填充矩阵的列
        index = 0
        for col in self.key:
            for row in range(rows):
                matrix[row][col] = ciphertext[index]
                index += 1

        # 从矩阵中提取解密后的文本，并删除填充字符
        decrypted_text = ''
        for row in matrix:
            decrypted_text += ''.join(row)

        # 删除填充字符
        decrypted_text = decrypted_text.rstrip('X')

        return decrypted_text


class DesCipher:
    def __init__(self, key: str):
        # 出初始化DES加密的参数  IP 置换参数

        # 设置默认密钥
        # self.K = '0111010001101000011010010111001101101001011100110110100101110110'
        self.K = self.str2bin(key)    # 转换为二进制流 形式的 str 字符串
        self.__plain_text = ""
        self.__cipher_text = ""

        self.ip = [
            58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
        ]

        # IP 逆置换参数
        self.ip1 = [
            40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
        ]

        # E 盒扩展盒，用来 32位明文扩展 为48位置换
        self.E = [
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1,
        ]

        # P置换，对经过S盒之后的数据再次进行置换
        self.P = [
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25,
        ]

        # 密钥的K1初始置换
        self.k1 = [
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4,
        ]
        self.k2 = [
            14, 17, 11, 24, 1, 5, 3, 28,
            15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32,
        ]

        # 秘钥循环移位的位数
        self.k0 = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1, ]

        # 全部S盒，16进制表示 S盒是为了将48位转换为32位，有8个盒子
        self.S = [
            [
                0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7,
                0x0, 0xf, 0x7, 0x4, 0xe, 0x2, 0xd, 0x1, 0xa, 0x6, 0xc, 0xb, 0x9, 0x5, 0x3, 0x8,
                0x4, 0x1, 0xe, 0x8, 0xd, 0x6, 0x2, 0xb, 0xf, 0xc, 0x9, 0x7, 0x3, 0xa, 0x5, 0x0,
                0xf, 0xc, 0x8, 0x2, 0x4, 0x9, 0x1, 0x7, 0x5, 0xb, 0x3, 0xe, 0xa, 0x0, 0x6, 0xd,
            ],
            [
                0xf, 0x1, 0x8, 0xe, 0x6, 0xb, 0x3, 0x4, 0x9, 0x7, 0x2, 0xd, 0xc, 0x0, 0x5, 0xa,
                0x3, 0xd, 0x4, 0x7, 0xf, 0x2, 0x8, 0xe, 0xc, 0x0, 0x1, 0xa, 0x6, 0x9, 0xb, 0x5,
                0x0, 0xe, 0x7, 0xb, 0xa, 0x4, 0xd, 0x1, 0x5, 0x8, 0xc, 0x6, 0x9, 0x3, 0x2, 0xf,
                0xd, 0x8, 0xa, 0x1, 0x3, 0xf, 0x4, 0x2, 0xb, 0x6, 0x7, 0xc, 0x0, 0x5, 0xe, 0x9,
            ],
            [
                0xa, 0x0, 0x9, 0xe, 0x6, 0x3, 0xf, 0x5, 0x1, 0xd, 0xc, 0x7, 0xb, 0x4, 0x2, 0x8,
                0xd, 0x7, 0x0, 0x9, 0x3, 0x4, 0x6, 0xa, 0x2, 0x8, 0x5, 0xe, 0xc, 0xb, 0xf, 0x1,
                0xd, 0x6, 0x4, 0x9, 0x8, 0xf, 0x3, 0x0, 0xb, 0x1, 0x2, 0xc, 0x5, 0xa, 0xe, 0x7,
                0x1, 0xa, 0xd, 0x0, 0x6, 0x9, 0x8, 0x7, 0x4, 0xf, 0xe, 0x3, 0xb, 0x5, 0x2, 0xc,
            ],
            [
                0x7, 0xd, 0xe, 0x3, 0x0, 0x6, 0x9, 0xa, 0x1, 0x2, 0x8, 0x5, 0xb, 0xc, 0x4, 0xf,
                0xd, 0x8, 0xb, 0x5, 0x6, 0xf, 0x0, 0x3, 0x4, 0x7, 0x2, 0xc, 0x1, 0xa, 0xe, 0x9,
                0xa, 0x6, 0x9, 0x0, 0xc, 0xb, 0x7, 0xd, 0xf, 0x1, 0x3, 0xe, 0x5, 0x2, 0x8, 0x4,
                0x3, 0xf, 0x0, 0x6, 0xa, 0x1, 0xd, 0x8, 0x9, 0x4, 0x5, 0xb, 0xc, 0x7, 0x2, 0xe,
            ],
            [
                0x2, 0xc, 0x4, 0x1, 0x7, 0xa, 0xb, 0x6, 0x8, 0x5, 0x3, 0xf, 0xd, 0x0, 0xe, 0x9,
                0xe, 0xb, 0x2, 0xc, 0x4, 0x7, 0xd, 0x1, 0x5, 0x0, 0xf, 0xa, 0x3, 0x9, 0x8, 0x6,
                0x4, 0x2, 0x1, 0xb, 0xa, 0xd, 0x7, 0x8, 0xf, 0x9, 0xc, 0x5, 0x6, 0x3, 0x0, 0xe,
                0xb, 0x8, 0xc, 0x7, 0x1, 0xe, 0x2, 0xd, 0x6, 0xf, 0x0, 0x9, 0xa, 0x4, 0x5, 0x3,
            ],
            [
                0xc, 0x1, 0xa, 0xf, 0x9, 0x2, 0x6, 0x8, 0x0, 0xd, 0x3, 0x4, 0xe, 0x7, 0x5, 0xb,
                0xa, 0xf, 0x4, 0x2, 0x7, 0xc, 0x9, 0x5, 0x6, 0x1, 0xd, 0xe, 0x0, 0xb, 0x3, 0x8,
                0x9, 0xe, 0xf, 0x5, 0x2, 0x8, 0xc, 0x3, 0x7, 0x0, 0x4, 0xa, 0x1, 0xd, 0xb, 0x6,
                0x4, 0x3, 0x2, 0xc, 0x9, 0x5, 0xf, 0xa, 0xb, 0xe, 0x1, 0x7, 0x6, 0x0, 0x8, 0xd,
            ],
            [
                0x4, 0xb, 0x2, 0xe, 0xf, 0x0, 0x8, 0xd, 0x3, 0xc, 0x9, 0x7, 0x5, 0xa, 0x6, 0x1,
                0xd, 0x0, 0xb, 0x7, 0x4, 0x9, 0x1, 0xa, 0xe, 0x3, 0x5, 0xc, 0x2, 0xf, 0x8, 0x6,
                0x1, 0x4, 0xb, 0xd, 0xc, 0x3, 0x7, 0xe, 0xa, 0xf, 0x6, 0x8, 0x0, 0x5, 0x9, 0x2,
                0x6, 0xb, 0xd, 0x8, 0x1, 0x4, 0xa, 0x7, 0x9, 0x5, 0x0, 0xf, 0xe, 0x2, 0x3, 0xc,
            ],
            [
                0xd, 0x2, 0x8, 0x4, 0x6, 0xf, 0xb, 0x1, 0xa, 0x9, 0x3, 0xe, 0x5, 0x0, 0xc, 0x7,
                0x1, 0xf, 0xd, 0x8, 0xa, 0x3, 0x7, 0x4, 0xc, 0x5, 0x6, 0xb, 0x0, 0xe, 0x9, 0x2,
                0x7, 0xb, 0x4, 0x1, 0x9, 0xc, 0xe, 0x2, 0x0, 0x6, 0xa, 0xd, 0xf, 0x3, 0x5, 0x8,
                0x2, 0x1, 0xe, 0x7, 0x4, 0xa, 0x8, 0xd, 0xf, 0xc, 0x9, 0x0, 0x3, 0x5, 0x6, 0xb,
            ],
        ]

    # 规范化明文输入
    def std_plaintext(self, pliantext: str) -> str:
        std_plain_txt = ''
        new_str = pliantext.replace('\n', ' ')  # 除去文本中的换行符
        for item in new_str:
            std_plain_txt += item
        return std_plain_txt

    def __substitution(self, table: str, self_table: list) -> str:
        """
        :param table: 需要进行置换的列表,是一个01字符串
        :param self_table: 置换表，在__init__中初始化了
        :return: 返回置换后的01字符串
        """
        # 置换用的 IP 置换啥的
        sub_result = ""
        for i in self_table:
            sub_result += table[i - 1]
        return sub_result

    def str2bin(self, string: str) -> str:
        """
        将明文转为二进制字符串:
        :param string: 任意字符串
        :return:二进制字符串
        """
        plaintext_list = list(bytes(string, 'utf8'))  # 将字符串转成bytes类型，再转成list
        result = []  # 定义返回结果
        for num in plaintext_list:        # 不够的位数填充为 0，切片切掉前缀，添加列尾
            result.append(bin(num)[2:].zfill(8))  # 将列表的每个元素转成二进制字符串，8位宽度
        return "".join(result)

    def bin2str(self, binary: str) -> str:
        """
        二进制字符串转成字符串
        :param binary:
        :return:
        """
        list_bin = [binary[i:i + 8] for i in range(0, len(binary), 8)]  # 对二进制字符串进行切分，每8位为一组
        list_int = []     # 获取从 i 起到 i 后的 全部八个字符
        for b in list_bin:
            list_int.append(int(b, 2))  # 对二进制转成int
        result = bytes(list_int).decode()  # 将列表转成bytes，在进行解码，得到字符串
        return result

    def __bin2int(self, binary: str) -> list:
        """
        由于加密之后的二进制无法直接转成字符，有不可见字符在，utf8可能无法解码，所以需要将二进制字符串每8位转成int型号列表，用于转成bytes再转hex
        :param binary: 二进制字符串
        :return: int型列表
        """
        # 为了解决一些奇怪的字符编解码出现的问题（原来的方案是直接字符串硬转ascii码，但是实际上会出现奇怪字符，而且奇怪字符在编解码时会超长）
        list_bin = [binary[i:i + 8] for i in range(0, len(binary), 8)]  # 对二进制字符串进行切分，每8位为一组
        list_int = []
        for b in list_bin:
            list_int.append(int(b, 2))  # 尾插
        return list_int

    def __int2bin(self, list_int: list) -> str:
        result = []
        for num in list_int:
            result.append(bin(num)[2:].zfill(8))   # int转二进制，去除0b填充0
        return ''.join(result)

    def __get_block_list(self, binary: str) -> list:
        """
        对明文二进制串进行切分，每64位为一块，DES加密以64位为一组进行加密的
        :type binary: 二进制串
        """
        len_binary = len(binary)
        if len_binary % 64 != 0:     # 明文长度不够，进行填充，注意，这是对二进制明文字符串操作
            binary_block = binary + ("0" * (64 - (len_binary % 64)))
            return [binary_block[i:i + 64] for i in range(0, len(binary_block), 64)]
        else:
            return [binary[j:j + 64] for j in range(0, len(binary), 64)]  # 分片

    def modify_secretkey(self):  # 规范化密钥输入  # 测试用的函数，修改默认密钥 可以留着也可以删掉
        """
        修改默认密钥函数
        :return: None
        """
        # 规范化密钥输入
        print('当前二进制形式密钥为:{}'.format(self.K))    # 插入密钥字符串
        print("当前字符串形式密钥为：{}".format(self.bin2str(self.K)))
        newkey = input("输入新的密钥（长度为8）：")   # 获取新的密钥
        if len(newkey) != 8:              # 不是 8位
            print("密钥长度不符合，请重新输入：")
            self.modify_secretkey()
        else:
            bin_key = self.str2bin(newkey)
            self.K = bin_key
            print("当前二进制形式密钥为:{}".format(self.K))  # 实际上并没有奇偶校验

    def __f_funtion(self, right: str, key: str):
        """
        :param right: 明文二进制的字符串加密过程的右半段
        :param key: 当前轮数的密钥
        :return: 进行E扩展，与key异或操作，S盒操作后返回32位01字符串
        """
        # 对right进行E扩展 右半部分进行扩展， 32 -> 48
        e_result = self.__substitution(right, self.E)
        # 与key 进行异或操作
        xor_result = self.__xor_function(e_result, key)
        # 进入S盒子  # 进行选择置换
        s_result = self.__s_box(xor_result)
        # 进行P置换  # S 盒输出要进行P置换
        p_result = self.__substitution(s_result, self.P)
        return p_result

    def __get_key_list(self):
        """
        :return: 返回加密过程中16轮的子密钥
        """
        # 子密钥生成  左右两段密钥合并
        key = self.__substitution(self.K, self.k1)  # 密钥进行置换 K 为默认密钥
        left_key = key[0:28]      # 数组片
        right_key = key[28:56]
        keys = []
        for i in range(1, 17):
            move = self.k0[i - 1]      # 实现循环左移，数组切片进行移动，左移位数查表
            move_left = left_key[move:28] + left_key[0:move]
            move_right = right_key[move:28] + right_key[0:move]
            left_key = move_left
            right_key = move_right
            move_key = left_key + right_key
            ki = self.__substitution(move_key, self.k2)
            keys.append(ki)
        return keys        # 合并全部子密钥

    def __xor_function(self, xor1: str, xor2: str):
        """
        :param xor1: 01字符串
        :param xor2: 01字符串
        :return: 异或操作返回的结果
        """
        # 简单异或运算
        size = len(xor1)   # 32 位
        result = ""
        for i in range(0, size):
            result += '0' if xor1[i] == xor2[i] else '1'
        return result

    def __s_box(self, xor_result: str):
        """
        :param xor_result: 48位01字符串
        :return: 返回32位01字符串
        """
        # S 盒选择
        result = ""
        for i in range(0, 8):
            # 将48位数据分为6组，循环进行
            block = xor_result[i * 6:(i + 1) * 6]   # 切片
            line = int(block[0] + block[5], 2)  # 提取末尾的数字 2 进制->十进制
            colmn = int(block[1:4], 2)  # 中间四个
            res = bin(self.S[i][line * 16 + colmn])[2:]  # 查表结果转二进制
            if len(res) < 4:       # 填补至 4 位
                res = '0' * (4 - len(res)) + res
            result += res
        return result

    def __iteration(self, bin_plaintext: str, key_list: list):
        """
        :param bin_plaintext: 01字符串，64位
        :param key_list: 密钥列表，共16个
        :return: 进行F函数以及和left异或操作之后的字符串
        """
        # 二进制明文比特流切片
        left = bin_plaintext[0:32]
        right = bin_plaintext[32:64]   # 左右切片
        for i in range(0, 16):
            next_lift = right  # 暂存变量，用来交换
            f_result = self.__f_funtion(right, key_list[i])   # 和key表做异或，S盒操作
            next_right = self.__xor_function(left, f_result)  # 做异或 然后交换
            left = next_lift
            right = next_right
        bin_plaintext_result = left + right
        return bin_plaintext_result[32:] + bin_plaintext_result[:32]  # 结果合并 ip逆转在下边

    def encrypt(self, plaintext):
        """
        :param plaintext: 明文字符串
        :return: 密文字符串
        """
        plaintext = self.std_plaintext(plaintext)  # 明文标准化
        bin_plaintext = self.str2bin(plaintext)   # 明文转二进制
        bin_plaintext_block = self.__get_block_list(bin_plaintext)  # 二进制变为块块们
        ciphertext_bin_list = []  # 密文集合
        key_list = self.__get_key_list()  # 获取 16轮 密钥集
        for block in bin_plaintext_block:
            # 初代ip置换
            sub_ip = self.__substitution(block, self.ip)  # ip置换
            ite_result = self.__iteration(sub_ip, key_list)
            # 逆ip置换
            sub_ip1 = self.__substitution(ite_result, self.ip1)
            ciphertext_bin_list.append(sub_ip1)
        ciphertext_bin = ''.join(ciphertext_bin_list)
        result = self.__bin2int(ciphertext_bin)
        self.__cipher_text = bytes(result).hex().upper()  # 密文二进制转16进制，读取不出错
        return self.__cipher_text

    def decrypt(self, ciphertext):
        '''
        :param ciphertext: 密文字符串
        :return: 明文字符串
        '''

        b_ciphertext = binascii.a2b_hex(ciphertext)
        bin_ciphertext = self.__int2bin(list(b_ciphertext))
        bin_plaintext_list = []
        key_list = self.__get_key_list()
        key_list = key_list[::-1]  # 反向切片，置换密钥
        bin_ciphertext_block = [bin_ciphertext[i:i + 64] for i in range(0, len(bin_ciphertext), 64)]
        for block in bin_ciphertext_block:
            sub_ip = self.__substitution(block, self.ip)
            ite = self.__iteration(sub_ip, key_list)
            sub_ip1 = self.__substitution(ite, self.ip1)
            bin_plaintext_list.append(sub_ip1)
        bin_plaintext = ''.join(bin_plaintext_list).replace('00000000', '')
        self.__plain_text = self.bin2str(bin_plaintext)  # 密文 01 字符串转换
        return self.__plain_text

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
