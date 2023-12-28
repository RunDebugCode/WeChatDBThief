# -*- coding:UTF-8 -*-
import ctypes
import hashlib
import hmac
import winreg

import psutil
import pymem
from win32com.client import Dispatch

from api import addresses
from lib import *
from lib import log, version

ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
VOIP_P = ctypes.c_void_p
name = sys._getframe
_file_ = os.path.split(__file__)[1].split('.')[0]


# 获取exe文件的位数
def get_exe_bit(file_path):
    """
    获取 PE 文件的位数: 32 位或 64 位
    :param file_path:  PE 文件路径(可执行文件)
    :return: 如果遇到错误则返回 64
    """
    try:
        with open(file_path, 'rb') as f:
            dos_header = f.read(2)
            if dos_header != b'MZ':
                info = 'get exe bit error: Invalid PE file'
                log.message(info, 'WARNING')
                return 64
            # Seek to the offset of the PE signature
            f.seek(60)
            pe_offset_bytes = f.read(4)
            pe_offset = int.from_bytes(pe_offset_bytes, byteorder='little')

            # Seek to the Machine field in the PE header
            f.seek(pe_offset + 4)
            machine_bytes = f.read(2)
            machine = int.from_bytes(machine_bytes, byteorder='little')

            if machine == 0x14c:
                return 32
            elif machine == 0x8664:
                return 64
            else:
                info = 'get exe bit error: Unknown architecture: %s' % hex(machine)
                log.message(info, 'WARNING')
                return 64
    except IOError:
        info = 'get exe bit error: File not found or cannot be opened'
        log.message(info, 'WARNING')
        return 64


# 读取内存中的字符串(非key部分)
def get_info_without_key(h_process, address, n_size=64):
    array = ctypes.create_string_buffer(n_size)
    if ReadProcessMemory(h_process, VOIP_P(address), array, n_size, 0) == 0:
        return "None"
    array = bytes(array).split(b"\x00")[0] if b"\x00" in array else bytes(array)
    text = array.decode('utf-8', errors='ignore')
    return text.strip() if text.strip() != "" else "None"


def pattern_scan_all(handle, pattern, *, return_multiple=False, find_num=100):
    next_region = 0
    found = []
    user_space_limit = 0x7FFFFFFF0000 if sys.maxsize > 2 ** 32 else 0x7fff0000
    while next_region < user_space_limit:
        try:
            next_region, page_found = pymem.pattern.scan_pattern_page(
                handle,
                next_region,
                pattern,
                return_multiple=return_multiple
            )
        except Exception as e:
            log.error(e, os.path.split(__file__)[-1], frame().f_code.co_name, frame().f_lineno - move)
            break
        if not return_multiple and page_found:
            return page_found
        if page_found:
            found += page_found
        if len(found) > find_num:
            break
    return found


def get_wechat_id(h_process):
    find_num = 100
    addresses = pattern_scan_all(h_process, br'\\Msg\\FTSContact', return_multiple=True, find_num=find_num)
    wechat_ids = []
    for address in addresses:
        array = ctypes.create_string_buffer(80)
        if ReadProcessMemory(h_process, VOIP_P(address - 30), array, 80, 0) == 0:
            return 'None'
        array = bytes(array)  # .split(b'\\')[0]
        array = array.split(b'\\Msg')[0]
        array = array.split(b'\\')[-1]
        wechat_ids.append(array.decode('utf-8', errors='ignore'))
    wechat_id = max(wechat_ids, key=wechat_ids.count) if wechat_ids else 'None'
    return wechat_id


def get_filepath(wechat_id='all'):
    if not wechat_id:
        return 'None'
    try:
        user_profile = os.environ.get('USERPROFILE')
        path_3ebffe94 = os.path.join(user_profile, 'AppData', 'Roaming', 'Tencent', 'WeChat', 'All Users', 'config',
                                     '3ebffe94.ini')
        with open(path_3ebffe94, 'r', encoding='utf-8') as f:
            w_dir = f.read()
    except Exception as e:
        log.message(e, 'WARNING')
        w_dir = 'MyDocument:'

    if w_dir == 'MyDocument:':
        try:
            # 打开注册表路径
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')
            documents_path = winreg.QueryValueEx(key, 'Personal')[0]  # 读取文档实际目录路径
            winreg.CloseKey(key)  # 关闭注册表
            documents_paths = os.path.split(documents_path)
            if '%' in documents_paths[0]:
                w_dir = os.environ.get(documents_paths[0].replace('%', ''))
                w_dir = os.path.join(w_dir, os.path.join(*documents_paths[1:]))
            else:
                w_dir = documents_path
        except Exception as e:
            profile = os.environ.get('USERPROFILE')
            w_dir = os.path.join(profile, 'Documents')

            log.error(e, os.path.split(__file__)[-1], frame().f_code.co_name, frame().f_lineno - move)

    msg_dir = os.path.join(w_dir, 'WeChat Files')

    if wechat_id == 'all' and os.path.exists(msg_dir):
        return msg_dir

    filePath = os.path.join(msg_dir, wechat_id)
    return filePath if os.path.exists(filePath) else 'None'


class GetKey:
    def __init__(self):
        self.KEY_SIZE = 32
        self.DEFAULT_PAGESIZE = 4096
        self.DEFAULT_ITER = 64000

    @staticmethod
    def read_key_bytes(h_process, address, address_len=8):
        array = ctypes.create_string_buffer(address_len)
        if ReadProcessMemory(h_process, VOIP_P(address), array, address_len, 0) == 0:
            return 'None'
        address = int.from_bytes(array, byteorder='little')  # 逆序转换为int地址（key地址）
        key = ctypes.create_string_buffer(32)
        if ReadProcessMemory(h_process, VOIP_P(address), key, 32, 0) == 0:
            return 'None'
        key_bytes = bytes(key)
        return key_bytes

    def verify_key(self, key, wx_db_path):
        with open(wx_db_path, 'rb') as file:
            db_list = file.read(5000)
        salt = db_list[:16]
        byteKey = hashlib.pbkdf2_hmac('sha1', key, salt, self.DEFAULT_ITER, self.KEY_SIZE)
        first = db_list[16:self.DEFAULT_PAGESIZE]

        mac_salt = bytes([(salt[i] ^ 58) for i in range(16)])
        mac_key = hashlib.pbkdf2_hmac('sha1', byteKey, mac_salt, 2, self.KEY_SIZE)
        hash_mac = hmac.new(mac_key, first[:-32], hashlib.sha1)
        hash_mac.update(b'\x01\x00\x00\x00')

        if hash_mac.digest() != first[-32:-12]:
            return False
        return True


def handle_key(db_path, address_len):
    root = GetKey()

    phone_type1 = 'iphone\x00'
    phone_type2 = 'android\x00'
    phone_type3 = 'ipad\x00'

    pm = pymem.Pymem('WeChat.exe')
    module_name = 'WeChatWin.dll'

    MicroMsg_path = os.path.join(db_path, 'MSG', 'MicroMsg.db')

    type1_addresses = pm.pattern_scan_module(phone_type1.encode(), module_name, return_multiple=True)
    type2_addresses = pm.pattern_scan_module(phone_type2.encode(), module_name, return_multiple=True)
    type3_addresses = pm.pattern_scan_module(phone_type3.encode(), module_name, return_multiple=True)
    type_addresses = type1_addresses if len(type1_addresses) >= 2 else type2_addresses if len(type2_addresses) >= 2 \
        else type3_addresses if len(type3_addresses) >= 2 else 'None'
    # print(type_addresses)
    if type_addresses == 'None':
        return 'None'
    for i in type_addresses[::-1]:
        for j in range(i, i - 2000, -address_len):
            key_bytes = root.read_key_bytes(pm.process_handle, j, address_len)
            if key_bytes == 'None':
                continue
            if root.verify_key(key_bytes, MicroMsg_path):
                return key_bytes.hex()
    return 'None'


# 读取微信信息(account,mobile,name,mail,wechat_id,key)
@log_func
def read_info():
    wechat_process = []
    result = []
    for process in psutil.process_iter(['name', 'exe', 'pid', 'cmdline']):
        if process.name() == 'WeChat.exe':
            wechat_process.append(process)

    if len(wechat_process) == 0:
        info = 'WeChat No Run'
        log.error(info, os.path.split(__file__)[-1], frame().f_code.co_name, frame().f_lineno - move)

    for process in wechat_process:
        wechat_info = {'pid': process.pid,
                       'version': Dispatch("Scripting.FileSystemObject").GetFileVersion(process.exe())}

        wechat_base_address = 0
        for module in process.memory_maps(grouped=False):
            if module.path and 'WeChatWin.dll' in module.path:
                wechat_base_address = int(module.addr, 16)
                break
        if wechat_base_address == 0:
            info = f'WeChat WeChatWin.dll Not Found'
            log.error(info, os.path.split(__file__)[-1], frame().f_code.co_name, frame().f_lineno - move)

        Handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, process.pid)

        version_list = version.read_json()
        bias_list = version_list.get(wechat_info['version'], None)

        if not bias_list:
            info = f'WeChat Current Version Is Not Supported(maybe not get account,mobile,name,mail)'
            log.message(info, 'WARNING')
            bias_list = addresses.get_address()
            version_list[bias_list[5]] = bias_list[1:]
            version.write_json(version_list)

        name_base_address = wechat_base_address + bias_list[0]
        account_base_address = wechat_base_address + bias_list[1]
        mobile_base_address = wechat_base_address + bias_list[2]
        email_base_address = wechat_base_address + bias_list[3]
        # key_base_address = wechat_base_address + bias_list[4]

        wechat_info['account'] = get_info_without_key(Handle, account_base_address, 32) if bias_list[1] != 0 else "None"
        wechat_info['mobile'] = get_info_without_key(Handle, mobile_base_address, 64) if bias_list[2] != 0 else "None"
        wechat_info['name'] = get_info_without_key(Handle, name_base_address, 64) if bias_list[0] != 0 else "None"
        wechat_info['email'] = get_info_without_key(Handle, email_base_address, 64) if bias_list[3] != 0 else "None"

        address_len = get_exe_bit(process.exe()) // 8

        wechat_info['id'] = get_wechat_id(Handle)
        wechat_info['filepath'] = get_filepath(wechat_info['id']) if wechat_info['id'] != "None" else "None"
        wechat_info['key'] = handle_key(wechat_info['filepath'], address_len) if wechat_info['filepath'] != "None" \
            else "None"
        result.append(wechat_info)

    return result


def main():
    print(read_info())


if __name__ == '__main__':
    main()
