# 本文件夹的作用：从ES中寻找访问过恶意域名的记录。
from elasticsearch import helpers, Elasticsearch
from common.date_op import generate_day_seq
from common.mongodb_op import query_mongodb_by_body
from common.mongodb_op import MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX
from common.mongodb_op import mongo_url
from pymongo import MongoClient

HOST = "10.1.1.201:9200"
VIS_DOMAIN_INDEX_NAME_PREFIX = "niclog-4th-"
VIS_DOM_DOC_TYPE = 'logs4th'


def search(domains, query_start_date="2019.03.19"):
    """
    :param domains:
    :param query_start_date: 从这一天往前（日期减少）查询
    :return:
    """
    dt_str_seq = generate_day_seq(query_start_date, day_range=200, forward=-1)
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
            pattern = "([A-Za-z0-9-]+\.)?" + domains[index]
            query_body["query"]["regexp"]["content"] = pattern
            # query_body["query"]["bool"]["must"][0]["match"]["content"] = domains[index]
            # print("query_body: %s" % (query_body))
            if es.indices.exists(index_name):
                gen = helpers.scan(es, index=index_name, doc_type=doc_type, query=query_body)
                total = 0
                for item in gen:
                    item = item['_source']
                    domain_name = item['content']
                    # print("domain_name: %s, item: %s" % (domain_name, item))
                    if total == 0:
                        print("domain_name: %s, domains[index]: %s" % (domain_name, domains[index]))
                    total += 1
                if total:
                    print("total: %s" % total)


if __name__ == "__main__":
    # choice = int(input("please enter 2 or 3"))
    choice = 2
    client = MongoClient(mongo_url)
    domains = query_mongodb_by_body(client, MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, ["domain"])  # 取出mongodb中所有的恶意域名
    print("len of domains: %s" % len(domains))
    query_start_date = input("please enter a date(format: 2019.03.19")
    search(domains, query_start_date)
