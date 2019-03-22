import requests
import random
import time
import copy
from requests.adapters import HTTPAdapter
from common.scrawer_tools import WHOIS_URL, ERROR_SLEEP, API_KEYS, USER_AGENTS, HEADERS
from common.scrawer_tools import get_proxy_from_redis
from common.mongodb_op import query_mongodb_by_body
from common.mongodb_op import MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, DOMAIN_IP_RESOLUTION_MONGO_INDEX, \
    DOMAIN_SUBDOMAIN_MONGO_INDEX, DOMAIN_WHOIS_MONGO_INDEX
from common.mongodb_op import mongo_url
from pymongo import MongoClient

client = MongoClient(mongo_url)


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


def save_whois_info2mongodb(domain, whois_info, db_name=MAL_DOMS_MONGO_DB, mongo_index=DOMAIN_WHOIS_MONGO_INDEX):
    """
    :param whois_info:
    :return:
    """
    db = client[db_name]
    query_body = {"domain": domain}
    if not db[mongo_index].find(query_body).count():
        db[mongo_index].insert(whois_info)


def save_domain_ip_resolutions2mongodb(domain, ips, db_name=MAL_DOMS_MONGO_DB,
                                       mongo_index=DOMAIN_IP_RESOLUTION_MONGO_INDEX):
    """
    :param domain:
    :param ips:
    :return:
    """
    db = client[db_name]
    for ip in ips:
        db[mongo_index].update({"domain": domain}, {"$addToSet": {"ips": ip}}, True)


def save_domain_subdomains2mongodb(domain, subdomains, db_name=MAL_DOMS_MONGO_DB,
                                   mongo_index=DOMAIN_SUBDOMAIN_MONGO_INDEX):
    """
    :param domain:
    :param subdomains:
    :return:
    """
    db = client[db_name]
    db[mongo_index].update({"domain": domain}, {"$addToSet": {"subdomains": subdomains}}, True)


def resolve_whois_info(domain):
    domain_info = get_whois_info(domain)
    assert isinstance(domain_info, dict)            # 请求结果可能为False
    if domain_info["response_code"] == 0:          # 请求成功，但是域名不在virustotal数据库中
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
        print(subdomains)
        print("save_domain_subdomains2mongodb, len of subdomains: %s" % len(subdomains))
        save_domain_subdomains2mongodb(domain, subdomains)
    if resolution_ips:
        print(resolution_ips)
        print("save_domain_ip_resolutions2mongodb, len of ips: %s" % len(resolution_ips))
        save_domain_ip_resolutions2mongodb(domain, resolution_ips)

    # print("=======================================================")
    # print("bitdefender_category： %s" % (bitdefender_category))
    # print("alexa_category：%s" % (alexa_category))
    # print("trend_micro_category：%s" % (trend_micro_category))
    # print("subdomains：%s" % (subdomains,))
    # for ip in resolution_ips:
    #     print("ip: %s" % ip)
    # print("==========================================================")

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

        whois_info = {}
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
            save_whois_info2mongodb(domain, whois_info)

        print("type of whois_dict : %s" % type(whois_dict))
        # if create_date:
        #     print("create_date :%s" % (create_date,))
        # if update_date:
        #     print("update_date :%s" % (update_date,))
        # if expiry_date:
        #     print("expiry_date:%s" % (expiry_date,))
        # if registrant_country:
        #     print("registrant_country : %s" % (registrant_country))
        # if admin_country:
        #     print("admin_country:%s" % (admin_country))
        # if admin_region:
        #     print("admin_region:%s" % (admin_region))


if __name__ == "__main__":
    # domain = "027.ru"
    # domain = "y.qq.com"
    # domain = "hyr1h3.bid"

    recs_list = query_mongodb_by_body(client, MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, ["domain"])  # 取出mongodb中所有的恶意域名
    for domain in recs_list:
        try:
            print("domain: %s resolve_whois_info" % (domain,))
            resolve_whois_info(domain)
        except AssertionError as e:
            print("AssertionError: %s" % (e,))
