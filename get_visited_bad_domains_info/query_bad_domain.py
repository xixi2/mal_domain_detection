# 本文件夹的作用：从ES中寻找访问过恶意域名的记录。
# 从ES中的niclog日志中找到正常域名数据集中域名的访问记录。
import time
from elasticsearch import helpers, Elasticsearch
from pymongo import MongoClient

from common.date_op import generate_day_seq
from common.mongodb_op import MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, NIC_LOG_MONGO_DB, \
    NIC_LOG_FULL_NAME_VISITING_MONGO_INDEX, GOOD_DOMAINS_MONGO_DB, GOOD_DOMAINS_MONGO_INDEX, \
    NIC_LOG_GOOD_DOMAIN_SUBDOMAINS_MONGO_INDEX, NIC_LOG_GOOD_FULL_NAME_VISITING_MONGO_INDEX
from common.mongodb_op import mongo_url
from common.mongodb_op import query_mongodb_by_body, save_domain_subdomains2mongodb
from common.other_common import COLLECT_WHOIS_OF_BAD_DOMAINS, COLLECT_WHOIS_OF_GOOD_DOMAINS

client = MongoClient(mongo_url)
db_nic_log = client[NIC_LOG_MONGO_DB]

HOST = "10.1.1.201:9200"
VIS_DOMAIN_INDEX_NAME_PREFIX = "niclog-4th-"
VIS_DOM_DOC_TYPE = 'logs4th'


def save_full_domains_visiting_records2mongodb(full_domain, ip=None, db=db_nic_log,
                                               mongo_index=NIC_LOG_FULL_NAME_VISITING_MONGO_INDEX):
    if ip:
        db[mongo_index].update({"full_domain": full_domain}, {"$addToSet": {"ips": ip}, "$inc": {"counter": 1}}, True)
    else:
        db[mongo_index].update({"full_domain": full_domain}, {"$inc": {"counter": 1}}, True)


def search(domains, query_start_date="2019.03.19", choice=COLLECT_WHOIS_OF_BAD_DOMAINS):
    """
    :param domains:
    :param query_start_date: 从这一天往前（日期减少）查询
    :return:
    """
    dt_str_seq = generate_day_seq(query_start_date, day_range=20, forward=-1)
    for index_name_suffix in dt_str_seq:
        index_name = VIS_DOMAIN_INDEX_NAME_PREFIX + index_name_suffix
        print('index_name: {0}'.format(index_name))
        print('len of domains: {0}'.format(len(domains)))
        doc_type = VIS_DOM_DOC_TYPE
        es = Elasticsearch(hosts=HOST)
        # query_body = {"query": {"bool": {"must": [{"match_phrase": {"content": ""}}]}}}
        query_body = {"query": {"regexp": {"content": ""}}}
        for index in range(len(domains)):
            # query_body["query"]["bool"]["must"][0]["match_phrase"]["content"] = domains[index]      # 匹配规则需要完善，详见PPT
            pattern = "([A-Za-z0-9-]?[A-Za-z0-9]+\.)?" + domains[index]
            query_body["query"]["regexp"]["content"] = pattern
            # query_body["query"]["bool"]["must"][0]["match"]["content"] = domains[index]
            # print("query_body: %s" % (query_body))
            if es.indices.exists(index_name):
                gen = helpers.scan(es, index=index_name, doc_type=doc_type, query=query_body)
                total = 0
                for item in gen:
                    item = item['_source']
                    full_domain = item['content']
                    # print("domain_name: %s, item: %s" % (domain_name, item))
                    if total == 0:
                        print("domain_name: %s, domains[index]: %s" % (full_domain, domains[index]))
                    total += 1

                    if choice == COLLECT_WHOIS_OF_BAD_DOMAINS:
                        save_domain_subdomains2mongodb(domains[index], [full_domain, ], db_nic_log)
                        save_full_domains_visiting_records2mongodb(full_domain)
                    elif choice == COLLECT_WHOIS_OF_GOOD_DOMAINS:
                        save_domain_subdomains2mongodb(domains[index], [full_domain, ], db_nic_log,
                                                       NIC_LOG_GOOD_DOMAIN_SUBDOMAINS_MONGO_INDEX)
                        save_full_domains_visiting_records2mongodb(full_domain=full_domain,
                                                                   mongo_index=NIC_LOG_GOOD_FULL_NAME_VISITING_MONGO_INDEX)

                if total:
                    print("total: %s" % total)
        time.sleep(20)


if __name__ == "__main__":
    choice = int(input("please a number: 1 for query good domains, 2 for query bad domains"))
    domain_list = []
    fields = ["domain"]
    if choice == COLLECT_WHOIS_OF_GOOD_DOMAINS:
        # 从mongodb中取出所有的正常域名
        domain_list = query_mongodb_by_body(client, GOOD_DOMAINS_MONGO_DB, GOOD_DOMAINS_MONGO_INDEX, fields)
    elif choice == COLLECT_WHOIS_OF_BAD_DOMAINS:
        # 取出mongodb中所有的恶意域名
        domain_list = query_mongodb_by_body(client, MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, fields)
    print("len of domains: %s" % len(domain_list))

    # 恶意域名目前已经测试到了2018.11.11，下一次从这一天开始
    query_start_date = input("please enter a date(format: 2019.03.19")
    search(domain_list, query_start_date, choice)
