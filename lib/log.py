# -*- coding:UTF-8 -*-
import datetime

from config import settings
from lib import *


def run_exit(func):
    def wrapper(*args, **kwargs):
        if not os.path.exists(settings.ROOT_PATH):
            os.makedirs(settings.ROOT_PATH)
        func(*args, **kwargs)
    return wrapper


def GetTime():
    current_time = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')[:-3]
    # year = current_time.year
    # month = current_time.month
    # day = current_time.day
    # hour = current_time.hour
    # minute = current_time.minute
    # second = current_time.second
    # microsecond = current_time.microsecond
    # time = f'{year}/{month}/{day} {hour}:{minute}:{second}.{str(microsecond)[:3]}'
    return current_time


def clean(path):
    if os.path.exists(path):
        with open(path, 'w', encoding='UTF-8') as f:
            f.write('')
        return True
    return False


@run_exit
def error(info, file, func, line, console=True):
    """
    日志写入错误信息

    :param info: 信息
    :param file: 发生错误的文件
    :param func: 发生错误的函数
    :param line: 发生错误的行
    :param console: 是否输出到控制台
    :return:
    """
    info = str(info)
    if console:
        settings.printf(f'[-] {info}')
    msg = f'{GetTime()} [ERROR]: <{file}:{func}()-{line}>: {info}\n'
    with open(settings.ERROR_PATH, 'a', encoding='UTF-8') as f:
        f.write(msg)
    sys.exit(0)


@run_exit
def message(info, mode='SUCCESS', console=True):
    """
    日志写入信息

    :param info: 信息
    :param mode: 信息等级
    :param console: 是否输出到控制台
    :return:
    """
    info = str(info)
    if console:
        settings.printf(f'[-] {info}', color='yellow')
    msg = f'{GetTime()} [{mode}]: {info}\n'
    with open(settings.LOG_PATH, 'a', encoding='UTF-8') as f:
        f.write(msg)


def main():
    message('hello')


if __name__ == '__main__':
    main()
