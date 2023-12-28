# -*- coding:UTF-8 -*-
import re
import argparse
import traceback

from api import wechatKey, addresses, merge_db
from api.decryption import decrypt
from config import settings
from lib import *
from lib import log, thief, rich_console


class Error:
    def __init__(self):
        self.mode = 'error'

    def init_parser(self, parser):
        info = parser.add_parser(self.mode, help='Create error')
        return info

    @staticmethod
    def run(args):
        raise FileNotFoundError(f'{settings.PROJECT_NAME} v{settings.VERSION}')


class Clean:
    def __init__(self):
        self.mode = 'clean'

    def init_parser(self, parser):
        info = parser.add_parser(self.mode, help='Clean log in logfile')
        return info

    @staticmethod
    def run(args):
        flag1 = log.clean(settings.LOG_PATH)
        flag2 = log.clean(settings.ERROR_PATH)
        if all((flag1, flag2)):
            print('Log file already cleaned!')
        else:
            print('Something wrong was happen.')


class Decrypt:
    def __init__(self):
        self.mode = 'decrypt'

    def init_parser(self, parser):
        info = parser.add_parser(self.mode, help='Decrypt the encrypted WeChat database')
        info.add_argument('-k', '--key', type=str, help='The key for WeChat database', required=True, metavar='')
        info.add_argument('-f', '--file', type=str, help='The abspath of WeChat database', required=True, metavar='')
        info.add_argument('-o', '--output', type=str,
                          help='The output dir of the decrypted file', required=True, metavar='')
        return info

    @staticmethod
    def run(args):
        key = args.key
        filepath = args.file
        output = args.output
        if not os.path.exists(output):
            os.makedirs(output)
        if os.path.isfile(filepath):
            output_path = os.path.join(output, os.path.split(filepath)[-1])
            print(decrypt(key, filepath, output_path))
        elif os.path.isdir(filepath):
            files_path = []
            for root, dirs, files in os.walk(filepath):
                for file in files:
                    if os.path.splitext(file)[-1] == '.db':
                        files_path.append(os.path.join(root, file))
            with rich_console.progress as progress:
                task = progress.add_task('[green]Processing...', total=len(files_path))
                for i in files_path:
                    output_path = os.path.join(output, os.path.split(i)[-1])
                    decrypt(key, i, output_path)
                    progress.update(task, advance=1)


class Bias:
    def __init__(self):
        self.mode = 'bias'

    def init_parser(self, parser):
        info = parser.add_parser(self.mode, help='Get WeChat base address offset')
        return info

    @staticmethod
    def run(args):
        name = ('name_bias', 'account_bias', 'mobile_bias', 'email_bias', 'key_bias', 'version')
        data = addresses.get_address()
        print('=' * 22)
        for i in zip(name, data):
            print(f'{i[0]: >12}: {i[1]}')
        print('=' * 22)


class Info:
    def __init__(self):
        self.mode = 'info'

    def init_parser(self, parser):
        info = parser.add_parser(self.mode, help='Print all information about WeChat')
        return info

    @staticmethod
    def run(*args):
        data = wechatKey.read_info()[0]
        print('=' * 74)
        for i in data:
            print(f'{i: >8}: {data[i]}')
        print('=' * 74)


class Merge:
    def __init__(self):
        self.mode = 'merge'

    def init_parser(self, parser):
        info = parser.add_parser(self.mode, help='Merge WeChat database')
        info.add_argument('-i', '--filepath', type=str,
                          help='The abspath of WeChat database', required=True, metavar='')
        info.add_argument('-o', '--output', type=str,
                          help='The output path of the merged file', required=True, metavar='')
        return info

    @staticmethod
    def run(args):
        db_path = []
        filepath = args.filepath
        output = args.output
        index = {
            'MSG': merge_db.merge_msg_db,
            'MediaMSG': merge_db.merge_media_msg_db,
            'NORMAL': merge_db.merge_db
        }
        flag = ''
        if not os.path.exists(output):
            os.makedirs(output)
        for root, dirs, files in os.walk(filepath):
            for file in files:
                if 'MediaMSG' in file:
                    flag = 'MediaMSG'
                elif 'MSG' in file:
                    flag = 'MSG'
                else:
                    flag = 'NORMAL'
                if os.path.splitext(file)[-1] == '.db':
                    db_path.append(os.path.join(root, file))
        res = index[flag](db_path, output)
        print(res)


class Export:
    def __init__(self):
        self.mode = 'export'

    def init_parser(self, parser):
        info = parser.add_parser(self.mode, help='Export chat records as HTML')
        info.add_argument('-d', '--dir', type=str, help='The abspath os WeChat MSG database', required=True, metavar='')
        info.add_argument('-n', '--name', type=str,
                          help='Copy a database with a specified name (Not required)', required=False, metavar='')
        info.add_argument('-o', '--output', type=str,
                          help='The output path of the decrypted file', required=True, metavar='')
        return info

    @staticmethod
    def run(args):
        pass


class Thief:
    def __init__(self):
        self.mode = 'thief'

    def init_parser(self, parser):
        info = parser.add_parser(self.mode, help='Copy all databases of WeChat to the specified folder')
        info.add_argument('-i', '--filepath', type=str, default=None,
                          help='WeChat dir path(like wxid_***) (Not required)', required=False, metavar='')
        info.add_argument('-o', '--output', type=str, default=None,
                          help='The output path of thief databases', required=False, metavar='')
        return info

    @staticmethod
    def run(args):
        filepath = args.filepath
        output = args.output
        if not filepath:
            filepath = wechatKey.read_info()[0]['filepath']
        if not output:
            output = settings.ROOT_PATH
        thief.Move(filepath, output).run()


class CustomArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        line_len = 70

        separator = settings.f_color(f"{' options ':-^{line_len}}")

        author_data = (f'{i: ^{line_len}}' for i in settings.AUTHOR.split('\n') if i)
        author_text = '\n'.join(map(settings.f_color, author_data))

        first_text = settings.f_color(f"{f' {settings.PROJECT_NAME} v{settings.VERSION} ':=^{line_len}}")
        function_text = f'{settings.PROJECT_NAME} 功能：获取账号信息、解密数据库、导出聊天记录为 html 等'
        help_text = super().format_help().strip()
        if re.findall(r'\[(-h)\]', help_text) != 1:
            # self.usage = None
            help_text = help_text.replace(' mode [-h] [-V] ...', '')
        other_text = f"更多详情请查看：{settings.f_url(settings.URL)}"

        text = '\n'.join(('', author_text, first_text, function_text, separator,
                          help_text, separator, other_text, first_text, ''))

        return text


def console_run():
    parser = CustomArgumentParser(
        usage='%(prog)s mode [-h] [-V] ...',
        description=settings.DESCRIPTION,
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-V', '--version', action='version', version=f'{settings.PROJECT_NAME} v{settings.VERSION}')

    subparsers = parser.add_subparsers(dest='mode', help='Operating mode', required=True, metavar='mode')

    modes = {}
    error_bias = Error()
    error_bias.init_parser(subparsers)
    modes[error_bias.mode] = error_bias

    clean_bias = Clean()
    clean_bias.init_parser(subparsers)
    modes[clean_bias.mode] = clean_bias

    decrypt_bias = Decrypt()
    decrypt_bias.init_parser(subparsers)
    modes[decrypt_bias.mode] = decrypt_bias

    bias = Bias()
    bias.init_parser(subparsers)
    modes[bias.mode] = bias

    info_bias = Info()
    info_bias.init_parser(subparsers)
    modes[info_bias.mode] = info_bias

    merge_bias = Merge()
    merge_bias.init_parser(subparsers)
    modes[merge_bias.mode] = merge_bias

    export_bias = Export()
    export_bias.init_parser(subparsers)
    modes[export_bias.mode] = export_bias

    thief_bias = Thief()
    thief_bias.init_parser(subparsers)
    modes[thief_bias.mode] = thief_bias

    if len(sys.argv) == 1:
        sys.argv.append('-h')

    console_args = parser.parse_args()
    if not any(vars(console_args).values()):
        parser.print_help()

    modes[console_args.mode].run(console_args)


def main():
    try:
        log.message(sys.argv, console=False)
        console_run()
    except Exception as e:
        log.message(e, 'ERROR')
        log.error(traceback.format_exc(), 'src.py', 'main', '207', False)


if __name__ == '__main__':
    main()
