import time
import random
from active_node.remove_duplicate import remove_double
from common.database_op import connect_db, insert_db
from active_node.model import DnsAnswer, AuthAnswer, AddAnswer
from common.mysql_config import DBSession
from common.bad_domain_files_common import read_from_bad_domain_list
from active_node.domain_dig_class import DomainDigger

conn = connect_db()
session = DBSession()
domain_digger = DomainDigger()


def list2objs(data_list, model, keys):
    objs = []
    for item in data_list:
        params = {keys[0]: item[0], keys[1]: item[1], keys[2]: item[2]}
        obj = model(params)
        objs.append(obj)
    return objs


def save2database(domains):
    count_zero = 0
    for domain in domains:
        answer_list, authority_list, additional_list = domain_digger.dig_domain(domain)
        print("handlering domain: %s, len of answer_list: %s" % (domain, len(answer_list)))
        if len(answer_list) == 0:
            count_zero += 1
            continue

        ans_keys = ("domain_name", "ttl", "ip")
        auth_keys = ("domain_name", "ttl", "name_server")
        add_keys = ("name_server", "ttl", "ip")
        dns_answer_objs = list2objs(answer_list, DnsAnswer, ans_keys)
        dns_auth_objs = list2objs(authority_list, AuthAnswer, auth_keys)
        dns_add_objs = list2objs(additional_list, AddAnswer, add_keys)
        session.add_all(dns_answer_objs)
        session.add_all(dns_auth_objs)
        session.add_all(dns_add_objs)
        session.commit()
    print("total query %s domains, %s has not any results" % (len(domains), count_zero))


if __name__ == "__main__":
    for i in range(10):
        # choice = int(input())
        choice = 2
        v_domains = read_from_bad_domain_list(choice)
        save2database(v_domains)

        # 随机睡眠一段时间继续查看
        random_num = random.randint(60, 7200)
        time.sleep(random_num)

    session.close()
