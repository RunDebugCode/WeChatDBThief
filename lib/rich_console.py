# -*- coding:UTF-8 -*-
from rich.console import Console
from rich.progress import Progress, BarColumn, SpinnerColumn, TimeRemainingColumn, TimeElapsedColumn


console = Console(color_system='256', style=None)
progress = Progress(
    '[progress.description]{task.description}({task.completed}/{task.total})',
    SpinnerColumn(finished_text='[green]✔'),
    BarColumn(),
    '[progress.percentage]{task.percentage:>3.2f}%',
    '[yellow]⏰',
    TimeElapsedColumn(),
    '[cyan]⏳',
    TimeRemainingColumn()
)


def main():
    pass


if __name__ == '__main__':
    main()
