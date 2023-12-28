# -*- coding:UTF-8 -*-
import hashlib
import re
import shutil

from lib import *
from lib import log, rich_console


def get_md5(filepath):
    md5_hash = hashlib.md5()
    with open(filepath, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b''):
            md5_hash.update(byte_block)
    return md5_hash.hexdigest()


def check(filepath, _dir):
    check_path = os.path.join(_dir, os.path.split(filepath)[1])
    if os.path.exists(check_path):
        if get_md5(filepath) != get_md5(check_path):
            os.remove(check_path)
            return True
        return False
    else:
        return True


def copy(filepath, _dir):
    info = f'copy {filepath} to {_dir} -> size:{os.path.getsize(filepath) / (1024 * 2):.2f} MB'
    log.message(info, console=False)

    return shutil.copy2(filepath, _dir)


@log_func
class Move:
    def __init__(self, wechat_filepath, output_dir):
        self.msg_path = os.path.join(wechat_filepath, 'Msg')
        self.multi_path = os.path.join(self.msg_path, 'Multi')
        self.output_path = output_dir

        self.emotion = os.path.join(self.msg_path, 'Emotion.db')
        self.favorite = os.path.join(self.msg_path, 'Favorite.db')
        self.misc = os.path.join(self.msg_path, 'Misc.db')
        self.sns = os.path.join(self.msg_path, 'Sns.db')
        self.media = os.path.join(self.msg_path, 'Media.db')
        self.micro_msg = os.path.join(self.msg_path, 'MicroMsg.db')
        self.msg_list = (self.emotion, self.favorite, self.misc, self.sns, self.media, self.micro_msg)

        self.media_msg = os.path.join(self.multi_path, 'MediaMSG{}.db')
        self.msg = os.path.join(self.multi_path, 'MSG{}.db')
        self.multi_list = (self.media_msg, self.msg)

    def count(self, rule):
        count = 0
        for root, dirs, files in os.walk(self.multi_path):
            for file in files:
                if re.match(rule, file):
                    count += 1
        return count

    def run(self):
        if any((not self.output_path, not os.path.exists(self.output_path))):
            os.makedirs(self.output_path)
        msg_path = os.path.join(self.output_path, 'msg')
        multi_path = os.path.join(self.output_path, 'multi')

        if not os.path.exists(msg_path):
            os.makedirs(msg_path)
        if not os.path.exists(multi_path):
            os.makedirs(multi_path)

        count_media = self.count(r"^(MediaMSG)\d(.db)$")
        count_msg = self.count(r"^(MSG)\d(.db)$")
        count = (count_media, count_msg)
        name = ('MediaMSG', 'MSG')
        # multi_list = zip(count, name)

        with rich_console.progress as progress1:
            task = progress1.add_task('[green]Progressing...', total=len(self.msg_list))
            for i in self.msg_list:
                copy(i, msg_path)
                progress1.update(task, advance=1)

        with rich_console.progress as progress2:
            task = progress2.add_task('[green]Progressing...', total=len(self.multi_list))
            for i, value in enumerate(self.multi_list):
                path = os.path.join(multi_path, name[i])
                os.makedirs(path)
                for j in range(count[i]):
                    copy(value.format(j), path)
                    progress2.update(task, advance=1)


def main():
    Move(r'').run()


if __name__ == '__main__':
    main()
