# -*- coding:UTF-8 -*-
import json

from config.settings import VERSION_LIST_PATH, ResourcePath
from lib import *


@log_func
def read_json() -> dict:
    with open(ResourcePath(VERSION_LIST_PATH), 'r', encoding='UTF-8') as f:
        data = f.read()
    return json.loads(data)


@log_func
def write_json(data: dict):
    with open(ResourcePath(VERSION_LIST_PATH), 'w', encoding='UTF-8') as f:
        f.write(json.dumps(data,
                           skipkeys=False,
                           ensure_ascii=False,
                           indent=4,
                           sort_keys=False))
    return True


def main():
    print(read_json())


if __name__ == '__main__':
    main()
