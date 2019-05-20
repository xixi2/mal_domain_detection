import os
from pymongo import MongoClient

from common.domains_op import VER_DOM_DIR
from common.domains_op import read_ver_bad_domain_file
from common.mongodb_op import mongo_url, MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX

client = MongoClient(mongo_url)
domain_type_dict = {
    "abuse": "urlhaus.abuse.ch",
    "cybercrime": "cybercrime",
    "feodo": "abuse.ch",
    "zeus": "zeustracker.abuse.ch",
    "malwaredomains": "malwaredomains.com",
    "malwaredomainlist": "malwaredomains.com",
    "phishtank": "phishing",
    "spyeye": "unknow",
    "palevo": "unknow",
    "ransomware": "ransomwaretracker.abuse.ch",
    "es": "non-dga"  # 后面需要继续处理
}


def read_ver_domains2database(dir):
    """
    将已经确认过的恶意域名存入mongodb数据库
    :param dir:
    :return:
    """
    files = os.listdir(dir)
    for file in files:
        ver_file = VER_DOM_DIR + file
        print(ver_file)
        domains = read_ver_bad_domain_file(ver_file)
        source = file.split("_")[0]
        type = domain_type_dict.get(source, "unknow")
        print("%s domains save2mongodb" % (len(domains)))
        save2mongodb(domains, source, type)


def save2mongodb(domains, source, type, db_name=MAL_DOMS_MONGO_DB, mongo_index_name=MAL_DOMS_MONGO_INDEX):
    """
    :param domains: 要存入mangodb的域名集合
    :param source: 每个域名的来源
    :param type: 每个域名的恶意类型，如钓鱼网站，垃圾邮件
    :param db_name: mongodb数据库名
    :param mongo_index_name: mongodb数据库索引名
    :return:
    """
    db = client[db_name]
    for domain in domains:
        rec_body = {"domain": domain, "source": source, "type": type}
        query_body = {"domain": domain}
        if not db[mongo_index_name].find(query_body).count():
            db[mongo_index_name].insert(rec_body)


def update_es_domains_source():
    """
    修改来自es_non_dga.txt文件中的域名的source字段和type字段
    :return:
    """
    pass


if __name__ == "__main__":
    domains = read_ver_domains2database(VER_DOM_DIR)
