# 准备数据：将dig收集到的恶意域名和IP的对应关系，以及virustotal中收集到的域名和IP的对应关系做相应处理后存入到mongodb中
from pymongo import MongoClient
from common.mongodb_op import mongo_url

from common.mongodb_op import ACTIVE_MONGO_DB, ACTIVE_DOM_TO_IP_MONGO_INDEX, DOMAIN_IP_RESOLUTION_MONGO_INDEX, \
    DOMAIN_IP_RESOLUTION_MONGO_DB, BAD_DOMAIN_IP_MONGO_INDEX, GOOD_DOMAIN_IP_MONGO_INDEX, GOOD_DOMAINS_MONGO_DB, \
    MAL_DOMS_MONGO_DB, GOOD_IPS_MONGO_INDEX, BAD_IPS_MONGO_INDEX
from common.mongo_common_fields import IP_FIELD, IPS_FIELD, DOMAIN_2ND_FIELD

client = MongoClient(mongo_url)
db_active_node = client[ACTIVE_MONGO_DB]
db_good_doamin = client[GOOD_DOMAINS_MONGO_DB]
db_bad_domain = client[MAL_DOMS_MONGO_DB]
target_db = client[DOMAIN_IP_RESOLUTION_MONGO_DB]


def get_active_domain2ip(db, src_index, target_db, target_index):
    """
            查询dig收集器采集到的域名和解析IP的对应关系存入到domain_ip_resolution数据库中
    :param db:
    :param src_index:
    :param target_db: domain_ip_resolution数据库
    :param target_index: 对于恶意域名，存入到bad_domain2ip集合中，正常域名存入到good_domain2ip集合中
    :return:
    """
    recs = db[src_index].find()
    ip_pool = set({})
    print(recs.count())
    for rec in recs:
        domain = rec.get(DOMAIN_2ND_FIELD).strip(".")
        mongo_query_body = {DOMAIN_2ND_FIELD: domain}
        basic_body = {"$addToSet": {IPS_FIELD: {"$each": rec.get(IP_FIELD, [])}}}
        target_db[target_index].update(mongo_query_body, basic_body, True)
        ip_pool = ip_pool | set(rec.get(IP_FIELD, []))
    print("len of ip_pool: %s" % (len(ip_pool)))
    return ip_pool


def get_whois_domain2ip(db, src_index, target_db, target_index):
    """
        查询从virustotal中爬取的域名与ip解析结果存入到domain_ip_resolution数据库中
    :param db: 从这个数据库中取出virustotal中爬取的域名与ip解析结果，对应恶意域名是malicious_domains数据库，
            对于正常域名是good_domains数据库
    :param target_db: domain_ip_resolution数据库
    :param target_index: 对于恶意域名，存入到bad_domain2ip集合中，正常域名存入到good_domain2ip集合中
    :return:
    """
    ip_pool = set({})
    recs = db[src_index].find()
    print("db: %s, len of recs: %s" % (db, recs.count()))
    for rec in recs:
        # print(rec)
        mongo_query_body = {DOMAIN_2ND_FIELD: rec[DOMAIN_2ND_FIELD]}
        basic_body = {"$addToSet": {IPS_FIELD: {"$each": rec[IPS_FIELD]}}}
        target_db[target_index].update(mongo_query_body, basic_body, True)
        ip_pool = ip_pool | set(rec.get(IPS_FIELD, []))
    print("len of ip_pool: %s" % (len(ip_pool)))
    return ip_pool


def save_ips_2mongo(ips, db_ips, ip_mongo_index):
    """
    :param ips: 将ip存入到MongoDB数据库中
    :param db_ips: 要存入的MongoDB数据库
    :param ip_mongo_index: 要存入的mongdb集合，对于正常域名映射到的ip是good_ips， 对于恶意域名映射到的ip是bad_ips
    :return:
    """
    for ip in ips:
        mongo_query_body = {IP_FIELD: ip}
        basic_body = {IP_FIELD: ip}
        db_ips[ip_mongo_index].update(mongo_query_body, basic_body, True)


def combine_domain_ip_resolutions():
    active_ip_pool_bad = get_active_domain2ip(db_active_node, ACTIVE_DOM_TO_IP_MONGO_INDEX, db_bad_domain,
                                              BAD_DOMAIN_IP_MONGO_INDEX)
    passive_ip_pool_good = get_whois_domain2ip(db_good_doamin, DOMAIN_IP_RESOLUTION_MONGO_INDEX, target_db,
                                               GOOD_DOMAIN_IP_MONGO_INDEX)
    passive_ip_pool_bad = get_whois_domain2ip(db_bad_domain, DOMAIN_IP_RESOLUTION_MONGO_INDEX, target_db,
                                              BAD_DOMAIN_IP_MONGO_INDEX)
    good_ips = passive_ip_pool_good
    save_ips_2mongo(good_ips, target_db, GOOD_IPS_MONGO_INDEX)
    print("len of good_ips: %s" % (len(good_ips)))
    bad_ips = passive_ip_pool_bad | active_ip_pool_bad
    print("len of bad_ips: %s" % (len(bad_ips)))
    save_ips_2mongo(bad_ips, target_db, BAD_IPS_MONGO_INDEX)


def ip2domain_resolution(db_ips, ip_mongo_index, db_domain, domain_mongo_index):
    """
    :param db_ips: domain_ip_resolution数据库
    :param ip_mongo_index:存储ip的mongdb集合，对于正常域名映射到的ip是good_ips， 对于恶意域名映射到的ip是bad_ips
    :param db_domain: domain_ip_resolution数据库
    :param domain_mongo_index:对于恶意域名是bad_domain2ip集合，正常域名是good_domain2ip集合
    :return:
    """
    recs = db_ips[ip_mongo_index].find()
    print("resc.count: %s" % (recs.count()))

    for rec in recs:
        ip = rec[IP_FIELD]
        print("handlering ip: %s" % (ip, ))
        query_body = {IPS_FIELD: ip}
        if db_domain == db_active_node:
            query_body = {IP_FIELD: ip}
        resolutions = db_domain[domain_mongo_index].find(query_body)
        domains = [resolution[DOMAIN_2ND_FIELD] for resolution in resolutions]
        mongo_query_body = {IP_FIELD: ip}
        if domains:
            basic_body = {"$addToSet": {DOMAIN_2ND_FIELD: {"$each": domains}}}
            db_ips[ip_mongo_index].update(mongo_query_body, basic_body)


if __name__ == '__main__':
    # combine_domain_ip_resolutions()

    # 将恶意ip与恶意域名关联
    # ip2domain_resolution(target_db, BAD_IPS_MONGO_INDEX, db_bad_domain, DOMAIN_IP_RESOLUTION_MONGO_INDEX)
    # ip2domain_resolution(target_db, BAD_IPS_MONGO_INDEX, db_active_node, ACTIVE_DOM_TO_IP_MONGO_INDEX)

    # 将正常ip与正常域名关联
    ip2domain_resolution(target_db, GOOD_IPS_MONGO_INDEX, db_good_doamin, DOMAIN_IP_RESOLUTION_MONGO_INDEX)
