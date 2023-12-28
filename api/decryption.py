# -*- coding:UTF-8 -*-
# -------------------------------------------------------------------------------
# 微信数据库采用的加密算法是256位的AES-CBC。数据库的默认的页大小是4096字节即4KB，其中每一个页都是被单独加解密的。
# 加密文件的每一个页都有一个随机的初始化向量，它被保存在每一页的末尾。
# 加密文件的每一页都存有着消息认证码，算法使用的是HMAC-SHA1（安卓数据库使用的是SHA512）。它也被保存在每一页的末尾。
# 每一个数据库文件的开头16字节都保存了一段唯一且随机的盐值，作为HMAC的验证和数据的解密。
# 用来计算HMAC的key与解密的key是不同的，解密用的密钥是主密钥和之前提到的16字节的盐值通过PKCS5_PBKF2_HMAC1密钥扩展算法迭代64000次计算得到的。而计算HMAC的密钥是刚提到的解密密钥和16字节盐值异或0x3a的值通过PKCS5_PBKF2_HMAC1密钥扩展算法迭代2次计算得到的。
# 为了保证数据部分长度是16字节即AES块大小的整倍数，每一页的末尾将填充一段空字节，使得保留字段的长度为48字节。
# 综上，加密文件结构为第一页4KB数据前16字节为盐值，紧接着4032字节数据，再加上16字节IV和20字节HMAC以及12字节空字节；而后的页均是4048字节长度的加密数据段和48字节的保留段。
# -------------------------------------------------------------------------------
import hashlib
import hmac

from Cryptodome.Cipher import AES

from lib import *
from lib import log

# from Crypto.Cipher import AES # 如果上面的导入失败，可以尝试使用这个


SQLITE_FILE_HEADER = "SQLite format 3\x00"  # SQLite文件头

KEY_SIZE = 32
DEFAULT_PAGESIZE = 4096
DEFAULT_ITER = 64000


# 通过密钥解密数据库
@log_func
def decrypt(key: str, db_path, output_path):
    """
    通过密钥解密数据库
    :param key: 密钥 64位16进制字符串
    :param db_path:  待解密的数据库路径(必须是文件)
    :param output_path:  解密后的数据库输出路径(必须是文件)
    :return:
    """
    if not os.path.exists(db_path) or not os.path.isfile(db_path):
        info = f'db_path: {db_path} File not found!'
        log.error(info, os.path.split(__file__)[-1], frame().f_code.co_name, frame().f_lineno - move)

    if not os.path.exists(os.path.dirname(output_path)):
        info = f'out_path: {output_path} Dir is error or the dir is disk!'
        log.error(info, os.path.split(__file__)[-1], frame().f_code.co_name, frame().f_lineno - move)

    # if len(key) != 64:
    #     info = f'[-] len({key}) != 64'
    #     log.error(info, os.path.split(__file__)[-1], frame().f_code.co_name, frame().f_lineno - move)
    #     return False

    password = bytes.fromhex(key.strip())
    with open(db_path, "rb") as file:
        blist = file.read()

    salt = blist[:16]
    byteKey = hashlib.pbkdf2_hmac("sha1", password, salt, DEFAULT_ITER, KEY_SIZE)
    first = blist[16:DEFAULT_PAGESIZE]
    if len(salt) != 16:
        info = f'db_path: {db_path} File Error!'
        log.error(info, os.path.split(__file__)[-1], frame().f_code.co_name, frame().f_lineno - move)

    mac_salt = bytes([(salt[i] ^ 58) for i in range(16)])
    mac_key = hashlib.pbkdf2_hmac("sha1", byteKey, mac_salt, 2, KEY_SIZE)
    hash_mac = hmac.new(mac_key, first[:-32], hashlib.sha1)
    hash_mac.update(b'\x01\x00\x00\x00')

    if hash_mac.digest() != first[-32:-12]:
        info = f'Key Error! (key: {key};db_path: {db_path};out_path: {output_path})'
        log.error(info, os.path.split(__file__)[-1], frame().f_code.co_name, frame().f_lineno - move)

    newblist = [blist[i:i + DEFAULT_PAGESIZE] for i in range(DEFAULT_PAGESIZE, len(blist), DEFAULT_PAGESIZE)]

    with open(output_path, "wb") as deFile:
        deFile.write(SQLITE_FILE_HEADER.encode())
        t = AES.new(byteKey, AES.MODE_CBC, first[-48:-32])
        decrypted = t.decrypt(first[:-48])
        deFile.write(decrypted)
        deFile.write(first[-48:])

        for i in newblist:
            t = AES.new(byteKey, AES.MODE_CBC, i[-48:-32])
            decrypted = t.decrypt(i[:-48])
            deFile.write(decrypted)
            deFile.write(i[-48:])

    return True, (db_path, output_path, key)


def main():
    decrypt('key', 'db_path', 'output_path')


if __name__ == '__main__':
    main()
