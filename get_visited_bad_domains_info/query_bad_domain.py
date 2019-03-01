# 本文件夹的作用：从ES中寻找访问过恶意域名的记录。

from elasticsearch import helpers, Elasticsearch
from common.date_op import generate_day_seq
from get_visited_bad_domains_info.hanlde_bad_domains import DST_DIR

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
    start_date = "2019.02.11"
    dt_str_seq = generate_day_seq(start_date, day_range=200, forward=-1)
    for index_name_suffix in dt_str_seq:
        index_name = VIS_DOMAIN_INDEX_NAME_PREFIX + index_name_suffix
        print('index_name: {0}'.format(index_name))
        doc_type = VIS_DOM_DOC_TYPE
        es = Elasticsearch(hosts=HOST)
        query_body = {
            "query": {
                "bool": {
                    "must": [{
                        "match_phrase": {
                            "content": ""
                        }
                    }]
                }
            }
        }
        while len(domains) > 0:
            # print("len of domains: %s" % len(domains))
            # number = 50
            # if len(domains) < 50:
            #     number = len(domains)
            # query_body["query"]["bool"]["must"][0]["match"]["content"].extend(domains[(-1 * number):])
            # for i in range(number):
            #     domains.pop()

            query_body["query"]["bool"]["must"][0]["match_phrase"]["content"] = domains[-1]
            domain_before = domains[-1]
            domains.pop()
            # print("domains[-1]: %s" % (domains[-1],))
            if es.indices.exists(index_name):
                # print("len of domains: %s" % len(domains))
                gen = helpers.scan(es, index=index_name, doc_type=doc_type, query=query_body)
                total = 0
                for item in gen:
                    item = item['_source']
                    domain_name = item['content']
                    # print("domain_name: %s, item: %s" % (domain_name, item))
                    if total == 0:
                        print("domains[-1]: %s, domain_name: %s" % (domain_before, domain_name,))
                    total += 1
                if total:
                    print("total: %s" % total)


if __name__ == "__main__":
    choice = int(input())
    if choice == 2:
        file = DST_DIR + "domains2.txt"
    if choice == 3:
        file = DST_DIR + "domains3.txt"
    print(file)
    domains = read_bad_domains_list(file)
    # print("len of domains: %s" % len(domains))
    search(domains)
