import urllib.request, urllib.parse, urllib.error
import re
import http.cookiejar
from Crypto.Cipher import AES
import math
import random
import base64
import json

# URL
GET_URL = 'https://authserver.szpt.edu.cn/authserver/login'
POST_URL = 'https://authserver.szpt.edu.cn/authserver/login?service=https%3A%2F%2Fehall.szpt.edu.cn%3A443%2Fpublicappinternet%2Fsys%2Fszptpubxsjkxxbs%2F*default%2Findex.do#/'
EHALL_URL = 'https://ehall.szpt.edu.cn/publicappinternet/sys/szptpubxsjkxxbs/*default/index.do'
GET_INFO_POST_URL = 'https://ehall.szpt.edu.cn/publicappinternet/sys/szptpubxsjkxxbs/mrxxbs/getSaveReportInfo.do'
SAVE_INFO_POST_URL = 'https://ehall.szpt.edu.cn/publicappinternet/sys/szptpubxsjkxxbs/mrxxbs/saveReportInfo.do'
GET_COOKIE_URL = 'https://authserver.szpt.edu.cn/authserver/login?service=https%3A%2F%2Fehall.szpt.edu.cn%3A443%2Fpublicappinternet%2Fsys%2Fszptpubxsjkxxbs%2F*default%2Findex.do'
SAVE_COOKIE_URL = ''
SET_COOKIES_URL = "https://authserver.szpt.edu.cn/authserver/login"
UPDATE_COOKIE_URL = 'https://ehall.szpt.edu.cn/publicappinternet/sys/itpub/MobileCommon/getMenuInfo.do'

# 请求头
header = {
    'User-Agent':'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.116 Mobile Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Host': 'ehall.szpt.edu.cn',

}
header_getinfo = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.116 Mobile Safari/537.36',

}
# 'Accept-Encoding': 'gzip, deflate, br',
# 'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
# 'Connection': 'keep-alive',
# 'Sec-Fetch-Dest': 'document',
# 'Sec-Fetch-Mode': 'navigate',
# 'Sec-Fetch-Site': 'none',
# 'Upgrade-Insecure-Requests': '1'

# 参数
APPID = ""
APPNAME = ""

# cookiejar
cookie = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie))

# 用户名与密码
username = ''
password = ''

lt = ''
execution = ''


# 禁止302重定向处理
class NoRedirHandle(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        return fp
    http_error_301 = http_error_302


# AES
class AESCipher:

    def __init__(self, key):
        self.key = key[0:16].encode('utf-8')  # 只截取16位
        self.iv = self.random_string(16).encode()  # 16位字符，用来填充缺失内容，可固定值也可随机字符串，具体选择看需求。

    def __pad(self, text):
        """填充方式，加密内容必须为16字节的倍数，若不足则使用self.iv进行填充"""
        text_length = len(text)
        amount_to_pad = AES.block_size - (text_length % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        pad = chr(amount_to_pad)
        return text + pad * amount_to_pad

    def __unpad(self, text):
        pad = ord(text[-1])
        return text[:-pad]

    def encrypt(self, text):
        """加密"""
        raw = self.random_string(64) + text
        raw = self.__pad(raw).encode()
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(cipher.encrypt(raw))

    def decrypt(self, enc):
        """解密"""
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self.__unpad(cipher.decrypt(enc).decode("utf-8"))

    @staticmethod
    def random_string(length):
        aes_chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
        aes_chars_len = len(aes_chars)
        retStr = ''
        for i in range(0, length):
            retStr += aes_chars[math.floor(random.random() * aes_chars_len)]
        return retStr


# 密码AES加密
def pwdEncrypt(aes_key):
    pc = AESCipher(aes_key)
    password_aes = pc.encrypt(password)
    return password_aes


# 登录
def login():
    # 登录请求
    request = urllib.request.Request(url=GET_URL,
                                     method='GET')
    response = opener.open(request)
    html = response.read().decode('utf-8')

    # 获取登录参数
    lt = re.search('name="lt" value="(.*?)"/>', html, re.S).group(1)
    execution = re.search('name="execution" value="(.*?)"/>', html, re.S).group(1)
    aes_key = re.search('pwdDefaultEncryptSalt = "(.*?)";', html, re.S).group(1)
    password_aes = pwdEncrypt(aes_key)
    # print(password_aes)
    params = {
        'username': username,
        'password': password_aes,
        'lt': lt,
        'dllt': 'userNamePasswordLogin',
        'execution': execution,
        '_eventId': 'submit',
        'rmShown': '1'
    }

    # 登录提交
    request = urllib.request.Request(url=POST_URL, data=urllib.parse.urlencode(params).encode(encoding='UTF-8'), method='POST')
    response = opener.open(request)

    # 登录判断
    if "安全退出" in response.read().decode('utf-8'):
        return True
    return False


# 设置cookies
def set_cookies():
    # 重新定义opener（保留cookie，新增处理302重定向）
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie), NoRedirHandle)
    request = urllib.request.Request(url=GET_COOKIE_URL,        # 获取ticket参数
                                     method='GET')
    response = opener.open(request)
    cookie.clear()  # 清除无用的cookie
    html = response.read().decode('utf-8')
    SAVE_COOKIE_URL = re.search('href="(.*?)">', html, re.S).group(1)
    # print(SAVE_COOKIE_URL)
    request = urllib.request.Request(url=SAVE_COOKIE_URL,
                                     method='GET',headers=header)   # 获取Cookie: MOD_AUTH_CAS
    opener.open(request)
    request = urllib.request.Request(url=EHALL_URL,
                                     method='GET', headers=header)  # 获取Cookie: _WEU,route
    response = opener.open(request)
    html = response.read().decode('utf-8')
    # 获取js中的APPID与APPNAME参数
    APPID = re.search("APPID='(.*?)';", html, re.S).group(1)
    APPNAME = re.search("APPNAME='(.*?)';", html, re.S).group(1)
    params_data = {}
    params_data["APPID"] = APPID
    params_data["APPNAME"] = APPNAME
    # 转换成json参数
    params = {
        'data': json.dumps(params_data)
    }
    # 更新Cookie: _WEU
    request = urllib.request.Request(url=UPDATE_COOKIE_URL,
                                     data=urllib.parse.urlencode(params).encode(encoding='UTF-8'),
                                     method='POST', headers=header) # 获取Cookie: _WEU
    opener.open(request)
    # print(cookie)


def send_info():
    # 设置cookies
    set_cookies()

    # 获取个人信息json数据
    params = {
        'USER_ID': username
    }
    request = urllib.request.Request(url=GET_INFO_POST_URL,
                                     data=urllib.parse.urlencode(params).encode(encoding='UTF-8'),
                                     method='POST', headers=header_getinfo)
    # 保存的参数
    response = opener.open(request)
    data = json.loads(response.read().decode('utf-8'))

    # 提交信息
    params = {
        'formData': data["datas"]
    }
    request = urllib.request.Request(url=SAVE_INFO_POST_URL,
                                     data=urllib.parse.urlencode(params).encode(encoding='UTF-8'),
                                     method='POST', headers=header_getinfo)
    response = opener.open(request)

    # 判断是否提交成功
    result_json = json.loads(response.read().decode('utf-8'))
    if result_json["code"] == "0":
        return True
    return False


def main():
    if login():
        if send_info():
            print("提交成功")
        else:
            print("提交失败")
    else:
        print("登录失败")


if __name__ == '__main__':
    main()
