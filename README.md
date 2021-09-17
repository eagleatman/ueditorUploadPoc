# 1. ueditorUploadPoc
1.4.3没有私有地址检测，就是source[]字段，1.4.3.3会对shell address做检查，如果发现是本地环回地址、10开头地址、192.168、169.等地址都不行
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
