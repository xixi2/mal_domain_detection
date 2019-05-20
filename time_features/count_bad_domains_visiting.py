"""
从给定时间内(如三个月)的niclog网络中心日志中提取访问过的域名；
提取出后再进行一个筛选：选出3000个
保留一个域名的三级域名
"""
from datetime import datetime, timedelta
from elasticsearch import helpers, Elasticsearch
from pymongo import MongoClient

from get_visited_bad_domains_info.test_nic_mal_domains import get_niclog_mal_domains
from common.date_op import timestamp_str2ymdh
from common.domains_op import keep_3th_dom_name
from common.mongodb_op import mongo_url
from common.mongodb_op import NIC_LOG_MONGO_DB, BAD_DOMAINS_COUNTER2ND_MONGO_INDEX, BAD_DOMAINS_COUNTER3TH_MONGO_INDEX
from common.mongo_common_fields import DOMAIN_2ND_FIELD, DOMAIN_3TH_FIELD, DATE_FIELD

PERIOD_START = '2018.3.28'  # 开始日期
PERIOD_LENGTH = 5  # 持续时间：100天
HOST = "10.1.1.201:9200"
VIS_DOMAIN_INDEX_NAME_PREFIX = "niclog-4th-"
VIS_DOM_DOC_TYPE = 'logs4th'

client = MongoClient(mongo_url)
db_nic_bad_visiting = client[NIC_LOG_MONGO_DB]
mongo_index_2nd = BAD_DOMAINS_COUNTER2ND_MONGO_INDEX
mongo_index_3th = BAD_DOMAINS_COUNTER3TH_MONGO_INDEX


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
        dt = dt + timedelta(days=-1)
    return dt_str_seq


def set_vis_bad_domain_index_params(index_name_suffix, domain_2nd, ver_sub_domains):
    index_name = VIS_DOMAIN_INDEX_NAME_PREFIX + index_name_suffix
    print('domain_2nd: {0}, index_name: {1}'.format(domain_2nd, index_name))
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
            dt_srt_day = dt_str[:-2]
            full_domain = item['content']
            domain_3th = keep_3th_dom_name(full_domain)
            if domain_3th.find(domain_2nd) >= 0 and domain_3th in ver_sub_domains:
                # print("domain_2nd: %s, domain_3th: %s, dt_str: %s" % (domain_2nd, domain_3th, dt_srt_day))
                mongo_query_body = {DOMAIN_2ND_FIELD: domain_2nd, DATE_FIELD: dt_srt_day}
                basic_body = {"$inc": {str(index): 1}}
                db_nic_bad_visiting[mongo_index_2nd].update(mongo_query_body, basic_body, True)
                mongo_query_body = {DOMAIN_3TH_FIELD: domain_3th, DATE_FIELD: dt_srt_day, DOMAIN_2ND_FIELD: domain_2nd}
                basic_body = {"$inc": {str(index): 1}}
                db_nic_bad_visiting[mongo_index_3th].update(mongo_query_body, basic_body, True)


def count_bad_domain_queries_per_window(domain_2nd, ver_sub_domains, day_range=7):
    """查询每个域名在每个时间窗口内被查询的次数"""
    dt_str_seq = generate_day_seq(day_range)
    print(dt_str_seq)
    for dt_str in dt_str_seq:
        set_vis_bad_domain_index_params(dt_str, domain_2nd, ver_sub_domains)


def count_bad_domains_queries():
    """从mongodb中读取出niclog中出现过的恶意域名，查询这400个恶意域名每个小时被查询的次数"""
    recs = get_niclog_mal_domains()
    for domain_dict in recs:
        domain_2nd = domain_dict["domain"]
        sub_domains = domain_dict["subdomains"]
        ver_sub_domains = domain_dict.get("ver_mal_sub_domains", [])
        count_bad_domain_queries_per_window(domain_2nd, ver_sub_domains)


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
