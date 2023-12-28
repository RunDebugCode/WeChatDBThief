# -*- coding:UTF-8 -*-
import ctypes
import hashlib
import hmac
import re

import psutil
import pymem
from pymem import Pymem
from win32com.client import Dispatch

from api import wechatKey
from lib import *
from lib import log

ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
void_p = ctypes.c_void_p
KEY_SIZE = 32
DEFAULT_PAGESIZE = 4096
DEFAULT_ITER = 64000


def validate_key(key, salt, first, mac_salt):
    byteKey = hashlib.pbkdf2_hmac("sha1", key, salt, DEFAULT_ITER, KEY_SIZE)
    mac_key = hashlib.pbkdf2_hmac("sha1", byteKey, mac_salt, 2, KEY_SIZE)
    hash_mac = hmac.new(mac_key, first[:-32], hashlib.sha1)
    hash_mac.update(b'\x01\x00\x00\x00')

    if hash_mac.digest() == first[-32:-12]:
        return True
    else:
        return False


def get_exe_version(file_path):
    """
    获取 PE 文件的版本号
    :param file_path:  PE 文件路径(可执行文件)
    :return: 如果遇到错误则返回
    """
    file_version = Dispatch("Scripting.FileSystemObject").GetFileVersion(file_path)
    return file_version


def find_all(c: bytes, string: bytes, base_address=0):
    """
    查找字符串中所有子串的位置
    :param base_address:
    :param c: 子串 b'123'
    :param string: 字符串 b'123456789123'
    :return:
    """
    return [base_address + m.start() for m in re.finditer(re.escape(c), string)]


class BiasAddress:
    def __init__(self, account, mobile, name, key, db_path):
        self.account = account.encode('utf-8')
        self.mobile = mobile.encode('utf-8')
        self.name = name.encode('utf-8')
        self.key = bytes.fromhex(key) if key else b""
        self.db_path = db_path if db_path and os.path.exists(db_path) else ""

        self.process_name = 'WeChat.exe'
        self.module_name = 'WeChatWin.dll'

        self.pm = None  # Pymem 对象
        self.is_WoW64 = None  # True: 32位进程运行在64位系统上 False: 64位进程运行在64位系统上
        self.process_handle = None  # 进程句柄
        self.pid = None  # 进程ID
        self.version = None  # 微信版本号
        self.process = None  # 进程对象
        self.exe_path = None  # 微信路径
        self.address_len = None  # 4 if self.bits == 32 else 8  # 4字节或8字节
        self.bits = 64 if sys.maxsize > 2 ** 32 else 32  # 系统：32位或64位

    def get_process_handle(self):
        try:
            self.pm = Pymem(self.process_name)
            self.pm.check_wow64()
            self.is_WoW64 = self.pm.is_WoW64
            self.process_handle = self.pm.process_handle
            self.pid = self.pm.process_id
            self.process = psutil.Process(self.pid)
            self.exe_path = self.process.exe()
            self.version = get_exe_version(self.exe_path)

            version_nums = list(map(int, self.version.split(".")))  # 将版本号拆分为数字列表
            if version_nums[0] <= 3 and version_nums[1] <= 9 and version_nums[2] <= 2:
                self.address_len = 4
            else:
                self.address_len = 8
            return True, ""
        except pymem.exception.ProcessNotFound:
            info = 'WeChat No Run'
            log.message(info, 'WARNING')
            return 0

    def search_memory_value(self, value: bytes, module_name="WeChatWin.dll"):
        # 创建 Pymem 对象
        module = pymem.process.module_from_name(self.pm.process_handle, module_name)
        ret = self.pm.pattern_scan_module(value, module, return_multiple=True)
        ret = ret[-1] - module.lpBaseOfDll if len(ret) > 0 else 0
        return ret

    def get_key_bias(self):
        try:
            byteLen = self.address_len  # 4 if self.bits == 32 else 8  # 4字节或8字节

            keyLenOffset = 0x8c if self.bits == 32 else 0xd0
            keyWindllOffset = 0x90 if self.bits == 32 else 0xd8

            module = pymem.process.module_from_name(self.process_handle, self.module_name)
            keyBytes = b'-----BEGIN PUBLIC KEY-----\n...'
            publicKeyList = pymem.pattern.pattern_scan_all(self.process_handle, keyBytes, return_multiple=True)

            key_address = []
            for address in publicKeyList:
                keyBytes = address.to_bytes(byteLen, byteorder="little", signed=True)  # 低位在前
                may_address = pymem.pattern.pattern_scan_module(self.process_handle, module, keyBytes,
                                                                return_multiple=True)
                if may_address != 0 and len(may_address) > 0:
                    for address2 in may_address:
                        keyLen = self.pm.read_uchar(address2 - keyLenOffset)
                        if keyLen != 32:
                            continue
                        key_address.append(address2 - keyWindllOffset)

            return key_address[-1] - module.lpBaseOfDll if len(key_address) > 0 else 0
        except Exception as e:
            log.message(e, 'WARNING')
            return 0

    def search_key(self, key: bytes):
        key = re.escape(key)  # 转义特殊字符
        key_address = self.pm.pattern_scan_all(key, return_multiple=False)
        key = key_address.to_bytes(self.address_len, byteorder='little', signed=True)
        result = self.search_memory_value(key, self.module_name)
        return result

    def run(self):
        self.get_process_handle()

        name_bias = self.search_memory_value(self.name, self.module_name)
        account_bias = self.search_memory_value(self.account, self.module_name)
        mobile_bias = self.search_memory_value(self.mobile, self.module_name)
        # email_bias = self.search_memory_value(self.email, self.module_name)
        key_bias = self.get_key_bias()
        key_bias = self.search_key(self.key) if key_bias <= 0 and self.key else key_bias
        key_bias = wechatKey.handle_key(self.db_path, self.address_len) if key_bias <= 0 and self.db_path else key_bias

        return name_bias, account_bias, mobile_bias, 0, key_bias, self.version,


@log_func
def get_address():
    account, mobile, name, key, db_path = 'test', 'test', 'test', None, r'test'
    bias_address = BiasAddress(account, mobile, name, key, db_path)
    return bias_address.run()


def main():
    print(get_address())


if __name__ == '__main__':
    main()
