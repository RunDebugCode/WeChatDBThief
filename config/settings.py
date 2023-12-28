# -*- coding:UTF-8 -*-
import os
import sys


AUTHOR = r"""
███████╗ ██████╗ ██╗   ██╗██╗     
██╔════╝██╔═══██╗██║   ██║██║     
███████╗██║   ██║██║   ██║██║     
╚════██║██║   ██║██║   ██║██║     
███████║╚██████╔╝╚██████╔╝███████╗
╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝
"""
VERSION = '1.0.0'
PROJECT_NAME = 'WeChatDBThief'
URL = 'https://blog.csdn.net/SoulisProgrammer'
DESCRIPTION = 'a tiny exe handle WeChat database'
USER_PATH = os.environ.get('USERPROFILE')
ROOT_PATH = os.path.join(USER_PATH, 'AppData', 'Roaming', 'WechatDBThief')
LOG_PATH = os.path.join(ROOT_PATH, 'run.log')
ERROR_PATH = os.path.join(ROOT_PATH, 'error.log')
FILES_PATH = r'Files'
VERSION_LIST_PATH = os.path.join(FILES_PATH, 'version_list.json')
msg = f"""
      {PROJECT_NAME}: version v{VERSION}, {DESCRIPTION}
      usage: *.exe [OPTION]...

      optional arguments:
        --version         Print version and exit
        --help            Print this help message and exit

      Get options:
        --pid             Print WeChat pid and exit
        --account         Print WeChat account name which is logging and exit
        --mobile          Print mobile and exit
        --name            Print WeChat name and exit
        --email           Print WeChat email address and exit
        --id              Print WeChat id and exit
        --key             Print WeChat key and exit
        --info            Print all information about account and exit

      Handle options:
        -k KEY            The WeChat Key to decode db
        -t FILE           Turn .db which is already decode into .html
        -i FILE           Set db path
        -n NAME           Set output filename(Not must option)
        -o DIR            Set output directory

      Other option:
        --clean           Clean log in logfile

      Tips:
        The option only lowercase is supported
        -[OPTION]         Need value to suppose to setup WeChatDBThief
        --[OPTION]        Only print information and exit
"""

ONLY_PRINT_COMMAND_LIST = ['--version', '--help', '--clean']
WECHAT_COMMAND_LIST1 = ['--pid', '--account', '--mobile', '--name', '--email', '--id', '--key']
WECHAT_COMMAND_LIST2 = ['--info']
HANDLE_COMMAND_LIST = ['-k', '-t', '-i', '-n', '-o']
COMMAND_LIST = ONLY_PRINT_COMMAND_LIST + WECHAT_COMMAND_LIST1 + WECHAT_COMMAND_LIST2 + HANDLE_COMMAND_LIST

color_index = {
    'black': 30,
    'red': 31,
    'green': 32,
    'yellow': 33,
    'blue': 34,
    'magenta': 35,
    'cyan': 36,
    'white': 37,
}


def ResourcePath(relative_path):
    if getattr(sys, 'frozen', False):
        # noinspection PyProtectedMember
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


def f_color(text, font_color='cyan'):
    text = f'\033[1;;{color_index[font_color]}m{text}\033[0m'
    return text


def f_url(url, color='yellow', underline=False, blink=True):
    if underline:
        url = '\033[4m' + url
    if blink:
        url = '\033[5m' + url
    url = f'\033[1;{color_index[color]}m{url}\033[0m'
    return url


def author():
    for i in (n for n in AUTHOR.split('\n') if n):
        print(f_color(i))


def printf(*args, color='red', sep=' ', end='\n'):
    args = [*args]
    for i, value in enumerate(args):
        args[i] = f_color(value, color)
    print(*args, sep=sep, end=end)


def main():
    print(f_url('https://www.baidu.com/'))


if __name__ == '__main__':
    main()
