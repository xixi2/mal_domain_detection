# 这个模块是为了检测一个域名是否是恶意的。

import requests


def scan_url(domain):
    """
    :param domain: 待检测的域名
    :return: 返回一个dict domain:被检测的域名 flag:该域名是否是恶意的
    """
    api_key = "a2c4c89637e57dc27bdb3048989da16c530c2dfffc4783c62fa95ea936e19d80"
    url = "http://www.virustotal.com/vtapi/v2/url/report"
    params = {
        "resource": domain,
        "apikey": api_key
    }
    response = requests.get(url, params=params)
    try:
        print("successfully get domain_name: %s" % (domain,))
        d = response.json()
        # for item in d:
        #     print("key: %s, val: %s" % (item, d[item]))
        # print(type(d["scans"]))
        # print(d["scans"])
        response.close()
        bad_flag = False
        for item in d["scans"].items():
            # print("scans key: %s" % (item,))
            # for each in item:
            if item[1]["detected"] == True:
                bad_flag = True
                break
                # print("each: %s, each: %s" % (item[0], item[1]))
        return bad_flag
    except Exception as e:
        print("domain_name: %s, error: %s" % (domain, e))
        return False


if __name__ == "__main__":
    domain = "qq.com"
    scan_url(domain)
