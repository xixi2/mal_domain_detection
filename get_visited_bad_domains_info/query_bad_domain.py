# 本文件夹的作用：从ES中寻找访问过恶意域名的记录。

import os
from elasticsearch import helpers, Elasticsearch
from common.date_op import generate_day_seq
from get_visited_bad_domains_info.hanlde_bad_domains import DST_DIR
from common.bad_domain_files_common import FILE_CHOICE


HOST = "10.1.1.201:9200"
VIS_DOMAIN_INDEX_NAME_PREFIX = "niclog-4th-"
VIS_DOM_DOC_TYPE = 'logs4th'


def read_bad_domains_list(file):
    domains = []
    with open(file) as f_in:
        lines = f_in.readlines()
        for line in lines:
            domain = line.strip("\n")
            domains.append(domain)
    return domains


def search(domains):
    start_date = "2019.03.04"
    dt_str_seq = generate_day_seq(start_date, day_range=200, forward=-1)
    for index_name_suffix in dt_str_seq:
        index_name = VIS_DOMAIN_INDEX_NAME_PREFIX + index_name_suffix
        print('index_name: {0}'.format(index_name))
        print('len of domains: {0}'.format(len(domains)))
        doc_type = VIS_DOM_DOC_TYPE
        es = Elasticsearch(hosts=HOST)
        query_body = {
            "query": {
                "bool": {
                    "must": [{
                        "match_phrase": {
                        # "match":{
                            "content": ""
                        }
                    }]
                }
            }
        }
        for index in range(len(domains)):
            query_body["query"]["bool"]["must"][0]["match_phrase"]["content"] = domains[index]
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
                        print("domain_name: %s, domains[index]: %s" % (domain_name,domains[index]))
                    total += 1
                if total:
                    print("total: %s" % total)


if __name__ == "__main__":
    # choice = int(input("please enter 2 or 3"))
    choice = 2
    file = "../" + FILE_CHOICE[choice]
    domains = read_bad_domains_list(file)
    # print("len of domains: %s" % len(domains))
    search(domains)
