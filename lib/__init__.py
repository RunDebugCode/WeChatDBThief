# -*- coding:UTF-8 -*-
import os
import sys

from lib import log

cwd = os.getcwd()
frame = sys._getframe
move = 0


def log_func(func):
    def wrapper(*args, **kwargs):
        log.message(f'Enter {func.__name__}()...', console=False)
        res = func(*args, **kwargs)
        log.message(f'Exit {func.__name__}() already.', console=False)
        return res
    return wrapper


def main():
    pass


if __name__ == '__main__':
    main()
