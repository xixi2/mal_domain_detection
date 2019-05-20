import requests
import random
import time
import copy
from requests.adapters import HTTPAdapter
from pymongo import MongoClient

from common.scrawer_tools import WHOIS_URL, ERROR_SLEEP, API_KEYS, USER_AGENTS, HEADERS
from common.scrawer_tools import get_proxy_from_redis
from common.mongodb_op import query_mongodb_by_body, save_domain_subdomains2mongodb
from common.mongodb_op import MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, DOMAIN_IP_RESOLUTION_MONGO_INDEX, \
    DOMAIN_WHOIS_MONGO_INDEX, GOOD_DOMAINS_MONGO_DB, GOOD_DOMAINS_MONGO_INDEX, DOMAIN_WHOIS_MONGO_INDEX, \
    DOMAIN_SUBDOMAIN_MONGO_INDEX, DOMAIN_IP_RESOLUTION_MONGO_INDEX
from common.mongodb_op import mongo_url
from common.other_common import COLLECT_WHOIS_OF_BAD_DOMAINS, COLLECT_WHOIS_OF_GOOD_DOMAINS

client = MongoClient(mongo_url)
db_subdomain = client[MAL_DOMS_MONGO_DB]
db_ip = client[MAL_DOMS_MONGO_DB]
db_whois = client[MAL_DOMS_MONGO_DB]
db_subdomain_good = client[GOOD_DOMAINS_MONGO_DB]
db_ip_good = client[GOOD_DOMAINS_MONGO_DB]
db_whois_good = client[GOOD_DOMAINS_MONGO_DB]


def get_whois_info(domain):
    """
    :param domain: 待检测的域名
    :return: 返回一个dict domain:被检测的域名 flag:该域名是否是恶意的
    """
    key_index = random.choice(range(0, len(API_KEYS)))
    api_key = API_KEYS[key_index]
    params = {
        "domain": domain,
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
            s = requests.Session()
            s.mount('https://', HTTPAdapter(max_retries=1))
            s.keep_alive = False
            response = s.get(WHOIS_URL, params=params, headers=headers, timeout=1, proxies=proxy)
            # print(response.status_code)
            if response.status_code != 200:
                time.sleep(ERROR_SLEEP)
                return False
            print("pro: %s, url: %s, successfully get domain_name: %s" % (pro, response.url, domain))
            d = response.json()
            response.close()
            return d
        except Exception as e:
            # write_error_domains(domain)
            print("domain_name: %s, error: %s, pro: %s" % (domain, e, pro))
            time.sleep(ERROR_SLEEP)


def save_whois_info2mongodb(domain, whois_info, db, mongo_index=DOMAIN_WHOIS_MONGO_INDEX):
    """
    :param whois_info:
    :return:
    """
    query_body = {"domain": domain}
    if not db[mongo_index].find(query_body).count():
        db[mongo_index].insert(whois_info)


def get_old_whois_info(mongo_index=DOMAIN_WHOIS_MONGO_INDEX, choice=COLLECT_WHOIS_OF_GOOD_DOMAINS):
    if choice == COLLECT_WHOIS_OF_GOOD_DOMAINS:
        rec = db_whois_good[mongo_index].find()
    else:
        rec = db_whois[mongo_index].find()
    domain_set = set()
    for item in rec:
        domain = item["domain"]
        domain_set.add(domain)
    return domain_set


def save_domain_ip_resolutions2mongodb(domain, ips, db, mongo_index=DOMAIN_IP_RESOLUTION_MONGO_INDEX):
    """
    :param domain:
    :param ips:
    :return:
    """
    # 如何做到不适用for循环一次向一个数组中添加多个元素: addtoset与each结合
    db[mongo_index].update({"domain": domain}, {"$addToSet": {"ips": {"$each": ips}}}, True)


def resolve_whois_info(domain, ip_mongo_index=None, subdomain_mongo_index=None, whois_mongo_index=None):
    domain_info = get_whois_info(domain)
    assert isinstance(domain_info, dict)  # 请求结果可能为False
    if domain_info["response_code"] == 0:  # 请求成功，但是域名不在virustotal数据库中
        print("%s" % (domain_info["verbose_msg"]))
        return
    bitdefender_category = domain_info.get("BitDefender category", None)  # 网站类别，如portals为门户网站
    alexa_category = domain_info.get("Alexa category", "")
    trend_micro_category = domain_info.get("TrendMicro category", None)
    categories = []
    if bitdefender_category:
        categories.append(bitdefender_category)
    if alexa_category:
        categories.append(alexa_category)
    if trend_micro_category:
        categories.append(trend_micro_category)

    subdomains = domain_info.get("subdomains", [])  # 子域名
    resolution_ips = [item.get("ip_address") for item in domain_info.get("resolutions", [])]
    if subdomains:
        # print(subdomains)
        print("save_domain_subdomains2mongodb, len of subdomains: %s" % len(subdomains))
        if not subdomain_mongo_index:
            save_domain_subdomains2mongodb(domain, subdomains, db_subdomain)
        else:
            save_domain_subdomains2mongodb(domain, subdomains, db_subdomain_good, subdomain_mongo_index)
    if resolution_ips:
        # print(resolution_ips)
        print("save_domain_ip_resolutions2mongodb, len of ips: %s" % len(resolution_ips))
        if not ip_mongo_index:
            save_domain_ip_resolutions2mongodb(domain, resolution_ips, db_ip)
        else:
            save_domain_ip_resolutions2mongodb(domain, resolution_ips, db_ip_good, ip_mongo_index)

    whois_info = domain_info["whois"]
    print("type of whois_info : %s" % type(whois_info))
    if whois_info:
        whois_list = whois_info.split("\n")
        whois_dict = {item.split(":")[0]: ''.join(item.split(":")[1:]) for item in whois_list}
        create_date = whois_dict.get("Creation Date", None)  # 注册日期
        update_date = whois_dict.get("Updated Date", None)  # 更新日期
        expiry_date = whois_dict.get("Expiry Date", None)  # 过期日期
        registrant_country = whois_dict.get("Registrant Country", None)  # 注册国家
        admin_country = whois_dict.get("Admin Country", "")  # 管理国家
        admin_region = whois_dict.get("Admin State/Province", "")  # state或者province

        whois_info = {"domain": domain}
        if create_date:
            whois_info["create_date"] = create_date
        if update_date:
            whois_info["update_date"] = update_date
        if expiry_date:
            whois_info["expiry_date"] = expiry_date
        if registrant_country:
            whois_info["registrant_country"] = registrant_country
        if admin_country:
            whois_info["admin_country"] = admin_country
        if admin_region:
            whois_info["admin_region"] = admin_region
        if categories:
            whois_info["categories"] = categories
        if whois_info:
            print("save_whois_info2mongodb")
            if not whois_mongo_index:
                save_whois_info2mongodb(domain, whois_info, db_whois)
            else:
                save_whois_info2mongodb(domain, whois_info, db_whois_good, whois_mongo_index)
        print("type of whois_dict : %s" % type(whois_dict))


if __name__ == "__main__":
    choice = int(input("please a number: 1 for collect whois of good domains, 2 for collect whois of bad domains"))
    domain_list = []
    fields = ["domain"]
    if choice == COLLECT_WHOIS_OF_GOOD_DOMAINS:
        # 从mongodb中取出所有的正常域名
        domain_list = query_mongodb_by_body(client, GOOD_DOMAINS_MONGO_DB, GOOD_DOMAINS_MONGO_INDEX, fields)
    elif choice == COLLECT_WHOIS_OF_BAD_DOMAINS:
        # 取出mongodb中所有的恶意域名
        domain_list = query_mongodb_by_body(client, MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, fields)
    count = 0

    domain_old_set = get_old_whois_info()
    domain_list = list(set(domain_list) - domain_old_set)
    print("len of domain_list: %s" % (len(domain_list, )))
    for domain in domain_list:
        # count仅仅用于显示现在处理到多少条，后面可以删除
        if count > 0 and not count % 500:
            print(count)
        count += 1

        try:
            print("domain: %s resolve_whois_info" % (domain,))
            if choice == COLLECT_WHOIS_OF_GOOD_DOMAINS:
                resolve_whois_info(domain, DOMAIN_IP_RESOLUTION_MONGO_INDEX, DOMAIN_SUBDOMAIN_MONGO_INDEX,
                                   DOMAIN_WHOIS_MONGO_INDEX)
            elif choice == COLLECT_WHOIS_OF_BAD_DOMAINS:
                resolve_whois_info(domain)
        except AssertionError as e:
            print("AssertionError: %s" % (e,))
