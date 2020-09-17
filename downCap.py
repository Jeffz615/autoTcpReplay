import requests
import re
import os
import time

burp0_url = "http://172.20.1.12:80/7cfb54c585b86956/4e3978ce-f77f-11ea-bee4-0242ac1d0505/"
burp0_headers = {"Pragma": "no-cache", "Cache-Control": "no-cache", "Authorization": "Basic dG9rZW43YTNhMTIzYjYyYzpFdHJHYnNuUQ==", "DNT": "1", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36 Edg/85.0.564.51", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://172.20.1.12/7cfb54c585b86956/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6", "Connection": "close"}
r=requests.get(burp0_url, headers=burp0_headers)
a=re.findall(r'<a href="([0-9]+?.cap)">',r.text)
caps = a
while True:
    try:
        time.sleep(10)
        burp0_url = "http://172.20.1.12:80/7cfb54c585b86956/4e3978ce-f77f-11ea-bee4-0242ac1d0505/"
        burp0_headers = {"Pragma": "no-cache", "Cache-Control": "no-cache", "Authorization": "Basic dG9rZW43YTNhMTIzYjYyYzpFdHJHYnNuUQ==", "DNT": "1", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36 Edg/85.0.564.51", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://172.20.1.12/7cfb54c585b86956/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6", "Connection": "close"}
        r=requests.get(burp0_url, headers=burp0_headers)
        a=re.findall(r'<a href="([0-9]+?.cap)">',r.text)
        for i in a:
            if i not in caps:
                file = requests.get(burp0_url + i,headers=burp0_headers)
                with open('./cap/' + i,'wb') as f:
                    f.write(file.content)
                print('Download file ' + i)
                caps.append(i)
    except Exception as e:
        print(e)
        pass