# 这个模块是为了检测一个域名是否是恶意的。

import requests
import random
import time
import copy
from requests.adapters import HTTPAdapter

from common.scrawer_tools import get_proxy_from_redis
from common.scrawer_tools import VER_DOMAIN_URL, ERROR_SLEEP, API_KEYS, USER_AGENTS, HEADERS


batch_num = 1


def write_error_domains(domain, file="502_domains.txt"):
    with open(file, "a+") as f_in:
        line = domain + "\n"
        f_in.write(line)


def scan_url(domain):
    """
    :param domain: 待检测的域名
    :return: 返回一个dict domain:被检测的域名 flag:该域名是否是恶意的
    """
    key_index = random.choice(range(0, len(API_KEYS)))
    api_key = API_KEYS[key_index]
    params = {
        "resource": domain,
        "apikey": api_key
    }
    while True:
        pro = get_proxy_from_redis()
        try:
            proxy = {
                'http': 'http://' + pro,
                # 'https': 'https://' + pro
            }
            user_agent = random.choice(USER_AGENTS)
            headers = copy.deepcopy(HEADERS)
            headers["User-Agent"] = user_agent
            # response = requests.get(url, params=params, headers=headers, timeout=1, proxies=proxy)
            s = requests.Session()
            s.mount('https://', HTTPAdapter(max_retries=1))
            s.keep_alive = False
            response = s.get(VER_DOMAIN_URL, params=params, headers=headers, timeout=1, proxies=proxy)
            # print(response.status_code)
            if response.status_code != 200:
                # write_error_domains(domain)
                time.sleep(ERROR_SLEEP)
                return False
            print("pro: %s, url: %s, successfully get domain_name: %s" % (pro, response.url, domain))
            d = response.json()
            response.close()
            if d['response_code'] == 0:
                # 如出现了response.status_code == 0时：Resource does not exist in the dataset
                print("response.json(): %s" % (response.json(),))
                break
            for item in d["scans"].items():
                if item[1]["detected"]:
                    return True
            # 成功返回，当该域名不是恶意域名
            return False
        except Exception as e:
            # write_error_domains(domain)
            print("domain_name: %s, error: %s, pro: %s" % (domain, e, pro))
            time.sleep(ERROR_SLEEP)


if __name__ == "__main__":
    domain = "walycorp.com"
    bad_flag = scan_url(domain)
    print("bad_flag: %s" % bad_flag)
    if bad_flag:
        print("badbad")
    else:
        print("good")
