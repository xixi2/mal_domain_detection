import time
import random
from active_node.remove_duplicate import remove_double
from pymongo import MongoClient
from common.database_op import connect_db, insert_db
from active_node.model import DnsAnswer, AuthAnswer, AddAnswer
from common.mysql_config import DBSession
from active_node.domain_dig_class import DomainDigger
from common.mongodb_op import mongo_url
from pymongo import MongoClient
from common.mongodb_op import query_mongodb_by_body
from common.mongodb_op import MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, ACTIVE_MONGO_DB, \
    ACTIVE_DOM_TO_IP_MONGO_INDEX, ACTIVE_DOM_TTL_TO_MONGO_INDEX, ACTIVE_DOM_NAMESERVER_MONGO_INDEX, \
    ACTIVE_DOM_NAMERSERVER_TTL_MONGO_INDEX, ACTIVE_NAMESERVER_TO_IP_MONGO_INDEX, ACTIVE_NAMERSER_TO_IP_TTL_MONGO_INDEX

conn = connect_db()
session = DBSession()
domain_digger = DomainDigger()
client = MongoClient(mongo_url)
db_mal_domains = client[MAL_DOMS_MONGO_INDEX]
db_active_node = client[ACTIVE_MONGO_DB]
ans_keys = ("domain", "ttl", "ip")
auth_keys = ("domain", "ttl", "name_server")
add_keys = ("name_server", "ttl", "ip")

IP_INDEX = 2
TTL_INDEX = 1
NAME_SERVER_INDEX = 2


def list2objs(data_list, model, keys):
    objs = []
    for item in data_list:
        params = {keys[0]: item[0], keys[1]: item[1], keys[2]: item[2]}
        obj = model(params)
        objs.append(obj)
    return objs


def save2mysql(answer_list, authority_list, additional_list):
    """
    将dig结果存入mysql数据库
    :param answer_list:
    :param authority_list:
    :param additional_list:
    :return:
    """
    dns_answer_objs = list2objs(answer_list, DnsAnswer, ans_keys)
    dns_auth_objs = list2objs(authority_list, AuthAnswer, auth_keys)
    dns_add_objs = list2objs(additional_list, AddAnswer, add_keys)
    session.add_all(dns_answer_objs)
    session.add_all(dns_auth_objs)
    session.add_all(dns_add_objs)
    session.commit()


def list2record(data_list, keys, key_index, mongo_index):
    """
    将dig采集到的响应存入到mongodb数据库中
    :param data_list: 可以是answer_list, authority_list, additional_list
    :param keys:
    :return:
    """
    for item in data_list:
        rec_unique = {"$addToSet": {keys[key_index]: item[key_index]}}
        rec_basic = {keys[0]: item[0]}
        db_active_node[mongo_index].update(rec_basic, rec_unique)


def save2mongodb(answer_list, authority_list, additional_list):
    """
    1. 将域名和ip的映射存入mongodb数据库；域名和ttl的映射存入mongodb数据库
    2. 将域名和权威域名服务器的映射存入到mongodb数据库中；域名和权威域名服务器的TTL存入mongodb中
    3. 将权威域名服务器和ip的映射存入mongodb数据库；权威域名服务器和ttl的映射存入mongodb数据库
    :param answer_list:
    :param authority_list:
    :param additional_list:
    :return:
    """
    list2record(answer_list, ans_keys, IP_INDEX, ACTIVE_DOM_TO_IP_MONGO_INDEX)
    list2record(answer_list, ans_keys, TTL_INDEX, ACTIVE_DOM_TTL_TO_MONGO_INDEX)
    list2record(authority_list, auth_keys, NAME_SERVER_INDEX, ACTIVE_DOM_NAMESERVER_MONGO_INDEX)
    list2record(authority_list, auth_keys, TTL_INDEX, ACTIVE_DOM_NAMERSERVER_TTL_MONGO_INDEX)
    list2record(additional_list, add_keys, IP_INDEX, ACTIVE_NAMESERVER_TO_IP_MONGO_INDEX)
    list2record(additional_list, add_keys, TTL_INDEX, ACTIVE_NAMERSER_TO_IP_TTL_MONGO_INDEX)


def save2database(domains):
    count_zero = 0
    for domain in domains:
        if not domain_digger.dig_domain(domain):
            print("dig nothing")
            continue
        answer_list, authority_list, additional_list = domain_digger.dig_domain(domain)
        print("handlering domain: %s, len of answer_list: %s" % (domain, len(answer_list)))
        if len(answer_list) == 0:
            count_zero += 1
            continue
        # save2mysql(answer_list, authority_list, additional_list)
        save2mongodb(answer_list, authority_list, additional_list)
    print("total query %s domains, %s has not any results" % (len(domains), count_zero))


if __name__ == "__main__":
    # iter_counter = int(input("please enter iteration counter "))
    iter_counter = 10
    for i in range(iter_counter):
        # choice = int(input())
        choice = 2
        # 取出mongodb中所有的恶意域名
        v_domains = query_mongodb_by_body(client, MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, ["domain"])
        # v_domains = read_from_bad_domain_list(choice)  # 获取恶意域名
        save2database(v_domains)
        random_num = random.randint(60, 7200)  # 随机睡眠一段时间继续查看
        time.sleep(random_num)
    session.close()
