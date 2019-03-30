from pymongo import MongoClient

Host = '192.168.105.140'
Port = 27017
User = 'mongo123'
Password = 'mongo123'
database = 'test'

mongo_url = 'mongodb://%s:%s@%s:%s' % (User, Password, Host, Port)

# 恶意域名
MAL_DOMS_MONGO_DB = "malicious_domains"
MAL_DOMS_MONGO_INDEX = "mal_domains"


# 主动结点
ACTIVE_MONGO_DB = "active_domain_ip_resolutions"
ACTIVE_DOM_TO_IP_MONGO_INDEX = "active_domain2ip"
ACTIVE_DOM_TTL_TO_MONGO_INDEX = "active_domain2ip_ttl"
ACTIVE_DOM_NAMESERVER_MONGO_INDEX = "active_domain2nameserver"
ACTIVE_DOM_NAMERSERVER_TTL_MONGO_INDEX = "active_domain2namerserver_ttl"
ACTIVE_NAMESERVER_TO_IP_MONGO_INDEX = "active_nameserver2ip"
ACTIVE_NAMERSER_TO_IP_TTL_MONGO_INDEX = "active_nameserver2ip_ttl"

# niclog访问记录
NIC_LOG_MONGO_DB = "nic_log_visiting"
NIC_LOG_FULL_NAME_VISITING_MONGO_INDEX = "full_domains_visiting_records"
NIC_LOG_GOOD_DOMAIN_SUBDOMAINS_MONGO_INDEX = "good_domain_subdomain"
NIC_LOG_GOOD_FULL_NAME_VISITING_MONGO_INDEX = "good_full_domains_visiting_records"

BAD_DOMAINS_COUNTER2ND_MONGO_INDEX = "bad_domains_counter_2nd"  # 统计niclog恶意域名的访问次数，以提取时间特征==》二级域名
BAD_DOMAINS_COUNTER3TH_MONGO_INDEX = "bad_domains_counter_3th"  # 统计niclog恶意域名的访问次数，以提取时间特征==》三级域名

# 正常域名
GOOD_DOMAINS_MONGO_DB = "good_domains"
GOOD_DOMAINS_MONGO_INDEX = "good_domains"

# 正常域名和恶意域名均有这些集合,
DOMAIN_IP_RESOLUTION_MONGO_INDEX = "domain_ips"
DOMAIN_SUBDOMAIN_MONGO_INDEX = "domain_subdomains"
DOMAIN_WHOIS_MONGO_INDEX = "domain_whois"

# 域名和IP解析结果
DOMAIN_IP_RESOLUTION_MONGO_DB = "domain_ip_resolution"
BAD_DOMAIN_IP_MONGO_INDEX = "bad_domain2ip"
GOOD_DOMAIN_IP_MONGO_INDEX = "good_domain2ip"
GOOD_IPS_MONGO_INDEX = "good_ips"       # 正常域名解析得到的ip
BAD_IPS_MONGO_INDEX = "bad_ips"         # 恶意域名解析得到的ip


def query_mongodb_by_body(client, db_name, mongo_index, fields=None, query_body=None):
    recs_list = []
    db = client[db_name]
    if query_body:
        recs = db[mongo_index].find(query_body)
    else:
        recs = db[mongo_index].find()
    # print("files: %s" % fields)

    for item in recs:
        temp = []
        if fields:
            if len(fields) > 1:
                for field in fields:
                    temp.append(item[field])
                recs_list.append(tuple(temp))
            else:
                recs_list.append(item[fields[0]])
        else:
            temp = [val for key, val in item.items()]
            recs_list.append(tuple(temp))
    return recs_list


def save_domain_subdomains2mongodb(domain, subdomains, db, mongo_index=DOMAIN_SUBDOMAIN_MONGO_INDEX):
    """
    :param domain:
    :param subdomains:
    :return:
    """
    # 这里使用addset有问题，addset只能将一个元素加入到已有数组中，无法将多个元素加入到原始数组中
    db[mongo_index].update({"domain": domain}, {"$addToSet": {"subdomains": {"$each": subdomains}}}, True)
