"""
从给定时间内(如三个月)的niclog网络中心日志中提取访问过的域名；
提取出后再进行一个筛选：选出3000个
保留一个域名的三级域名
"""
import random
from datetime import datetime, timedelta
import redis
from elasticsearch import helpers, Elasticsearch
import tldextract
from get_visited_bad_domains_info.test_nic_mal_domains import get_niclog_mal_domains

PERIOD_START = '2018.10.1'  # 开始日期
PERIOD_LENGTH = 5  # 持续时间：100天
HOST = "10.1.1.201:9200"
VIS_DOMAIN_INDEX_NAME_PREFIX = "niclog-4th-"
VIS_DOM_DOC_TYPE = 'logs4th'
NUM_OF_DOAMINS = 5000  # 目前准备取5000个域名做数据集
r1 = redis.Redis(host='127.0.0.1', port=6379, db=2)  # 提取访问域名时使用数据库2
r2 = redis.Redis(host='127.0.0.1', port=6379, db=3)  # 统计域名的DNS查询次数时使用这个
r3 = redis.Redis(host='127.0.0.1', port=6379, db=4)  # 以每个域名的domain_3th作为键，原始domain作为值


def keep_3th_dom_name(domain_name):
    """
    只保留三级域名
    :param domain_name:
    :return:
    """
    sub_domain, domain, suffix = tldextract.extract(domain_name)
    sub_domain_list = sub_domain.split('.')
    if len(sub_domain_list) > 1:
        sub_domain = sub_domain_list[-1]
    return (sub_domain, domain, suffix)


def format_domain_name(domain_name):
    domain_name = domain_name.lower()
    sub_domain, domain, suffix = keep_3th_dom_name(domain_name)
    return (sub_domain, domain, suffix)


def get_all_domains(es, index_name, doc_type, query_body=None):
    domain_set = set()
    # print(index_name)
    domain_3th_set = set()
    if es.indices.exists(index_name):
        if query_body is None:
            query_body = {"query": {"match_all": {}}}
        gen = helpers.scan(es, index=index_name, doc_type=doc_type, query=query_body)
        for item in gen:
            if len(domain_3th_set) >= NUM_OF_DOAMINS:
                break

            # 随机生成一个数，如果该数大于5，就当前域名加入到redis，否则就不加
            random_state = random.randint(0, 10)
            if random_state < 5:
                continue
            item = item['_source']
            domain_name = item['content']
            domain_tuple = format_domain_name(domain_name)
            domain_set.add((domain_name, domain_tuple))
            domain_3th_set.add(domain_tuple)
            # print('domain_name: {0}, dom_name: {1}'.format(domain_name, dom_name))
        return list(domain_set), len(domain_set)


def get_domain_query_numbers(es, index_name, doc_type, query_body=None):
    """查询一个域名在一天内的DNS查询次数"""
    domain_3th = query_body["query"]["bool"]["must"][0]["term"]["content"]
    print("index_name: %s, domain_3th: %s" % (index_name, domain_3th))
    suffix = "".join(index_name.split('-')[-1].split("."))
    if es.indices.exists(index_name):
        if query_body is None:
            query_body = {"query": {"match_all": {}}}
        gen = helpers.scan(es, index=index_name, doc_type=doc_type, query=query_body)
        # count = 0
        key = domain_3th + "_" + suffix
        val_dict = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0,
                    12: 0, 13: 0, 14: 0, 15: 0, 16: 0, 17: 0, 18: 0, 19: 0, 20: 0, 21: 0, 22: 0, 23: 0}
        r2.hmset(key, val_dict)
        for item in gen:
            item = item['_source']
            timestamp = item['time-stamp']
            dt_str = timestamp_str2ymdh(timestamp)
            index = int(dt_str[-2:])
            r2.hincrby(key, index, 1)
            # count += 1
        # print("count: %s" % count)


def timestamp_str2ymdh(timestamp_str, date_format="%Y%m%d%H"):
    """把字符串类型的时间戳转换为年月日时组成的字符串，形如：2018100207"""
    timestamp_str = timestamp_str.split(".")[0]
    timestamp = int(timestamp_str)
    dt = datetime.fromtimestamp(timestamp)
    dt_str = dt.strftime(date_format)
    return dt_str


def generate_day_seq(day_range=1, date_format="%Y.%m.%d"):
    """
    获取100个如2018.10.01的日期字符串组成的列表
    :param date_format:
    :return:
    """
    dt_str_seq = []
    dt = datetime.strptime(PERIOD_START, date_format)
    # for i in range(PERIOD_LENGTH):        # 后面换成常量，现在使用参数
    for i in range(day_range):
        # print(dt.strftime(date_format))
        dt_str = dt.strftime(date_format)
        dt_str_seq.append(dt_str)
        dt = dt + timedelta(days=1)
    return dt_str_seq


def set_vis_domain_index_params(index_name_suffix, query_body=None, func=get_all_domains):
    index_name = VIS_DOMAIN_INDEX_NAME_PREFIX + index_name_suffix
    print('index_name: {0}'.format(index_name))
    doc_type = VIS_DOM_DOC_TYPE
    es = Elasticsearch(hosts=HOST)
    if func == get_all_domains:
        domain_list, total_len = func(es, index_name, doc_type, query_body)
        return domain_list, total_len
    else:
        func(es, index_name, doc_type, query_body)


def get_every_day_vis_doms():
    # dt_str_seq = generate_day_seq()
    dt_str_seq = generate_day_seq(5)
    # print(dt_str_seq)
    query_body = {
        "query": {
            "match": {
                "operation": "dnsquery3"
            }
        }
    }
    for dt_str in dt_str_seq:
        domain_list, dom_len = set_vis_domain_index_params(dt_str, query_body)
        for domain_name, domain_tuple in domain_list:
            domain_3th = ".".join(domain_tuple)
            if not r1.exists(domain_3th):
                value_dict = {
                    "tld": domain_tuple[2],
                    "2nd": domain_tuple[1],
                    "3th": domain_tuple[0]
                }
                r1.hmset(domain_3th, value_dict)

            # 以domain_3th为键，保存该三层域名对应的原始访问域名
            r3.sadd(domain_3th, domain_name)
        print('dom_len= {0}'.format(dom_len))


def count_domain_queries_per_window(domain_3th):
    """查询每个域名在每个时间窗口内被查询的次数"""
    dt_str_seq = generate_day_seq(5)
    # print(dt_str_seq)
    query_body = {
        "query": {
            "bool": {
                "must": [{
                    "term": {
                        "content": domain_3th
                    }
                },
                    {
                        "term": {
                            "operation": "dnsquery3"
                        }
                    }
                ]
            }
        }
    }
    for dt_str in dt_str_seq:
        set_vis_domain_index_params(dt_str, query_body, get_domain_query_numbers)


def count_domains_queries():
    """从redis中读取出所有访问过的域名，查询这5000个域名每个小时被查询的次数"""
    keys = r1.keys()
    for domain_3th in keys:
        domain_3th = str(domain_3th, encoding="utf-8")
        # print(domain_3th)
        count_domain_queries_per_window(domain_3th)


def set_vis_bad_domain_index_params(index_name_suffix, domain_2nd, ver_sub_domains):
    index_name = VIS_DOMAIN_INDEX_NAME_PREFIX + index_name_suffix
    print('index_name: {0}'.format(index_name))
    doc_type = VIS_DOM_DOC_TYPE
    es = Elasticsearch(hosts=HOST)
    pattern = "([A-Za-z0-9-]?[A-Za-z0-9]+\.)?" + domain_2nd
    query_body = {"query": {"bool": {"must": [{"regexp": {"content": pattern}}, {"term": {"operation": "dnsquery3"}}]}}}
    if es.indices.exists(index_name):
        if query_body is None:
            query_body = {"query": {"match_all": {}}}
        gen = helpers.scan(es, index=index_name, doc_type=doc_type, query=query_body)
        # count = 0
        # key = domain_3th + "_" + suffix
        # val_dict = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0,
        #             12: 0, 13: 0, 14: 0, 15: 0, 16: 0, 17: 0, 18: 0, 19: 0, 20: 0, 21: 0, 22: 0, 23: 0}
        # r2.hmset(key, val_dict)
        for item in gen:
            item = item['_source']
            timestamp = item['time-stamp']
            dt_str = timestamp_str2ymdh(timestamp)
            index = int(dt_str[-2:])
            domain_3th = item['content']
            if domain_3th.find(domain_2nd) >= 0 and domain_3th in ver_sub_domains:
                print("domain_2nd: %s, domain_3th: %s, dt_str: %s" % (domain_2nd, domain_3th, dt_str))



def count_bad_domain_queries_per_window(domain_2nd, ver_sub_domains, day_range=5):
    """查询每个域名在每个时间窗口内被查询的次数"""
    dt_str_seq = generate_day_seq(day_range)
    # print(dt_str_seq)
    for dt_str in dt_str_seq:
        set_vis_bad_domain_index_params(dt_str, domain_2nd, ver_sub_domains)


def count_bad_domains_queries():
    """从mongodb中读取出niclog中出现过的恶意域名，查询这400个恶意域名每个小时被查询的次数"""
    recs = get_niclog_mal_domains()
    for domain_dict in recs:
        domain_2nd = domain_dict["domain"]
        sub_domains = domain_dict["subdomains"]
        ver_sub_domains = domain_dict.get("ver_mal_sub_domains", [])
        count_bad_domain_queries_per_window(domain_2nd, ver_sub_domains, 1)


if __name__ == '__main__':
    # 提取访问的域名
    # get_every_day_vis_doms()

    # 统计每个域名在时间窗口内的DNS查询次数
    start = datetime.now()
    # count_domains_queries()
    count_bad_domains_queries()
    end = datetime.now()
    time_cost = (end - start).seconds
    print("time_cost: %s" % time_cost)
