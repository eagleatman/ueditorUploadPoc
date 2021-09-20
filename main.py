import ueditor143Poc


def print_hi(name):
    # 在下面的代码行中使用断点来调试脚本。
    print(f'Hi, {name}')  # 按 ⌘F8 切换断点。
    return 'hello', 'world'


# 按间距中的绿色按钮以运行脚本。
if __name__ == '__main__':
    h, w = print_hi('hello world!!!')
    print(h, w, type(h), type(w))
    ueditor143Poc._print();
