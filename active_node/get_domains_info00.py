import time
import random
from active_node.dig_domain import dig_one_domain
from active_node.remove_duplicate import remove_double
from common.database_op import connect_db, insert_db
from active_node.model import DnsAnswer, AuthAnswer, AddAnswer
from common.mysql_config import DBSession

DST_DIR = "../data_set/extrated_bad_domains/"

conn = connect_db()
session = DBSession()


def read_from_domain_list(choice):
    v_domains = []
    file = DST_DIR + "v_domains" + str(choice) + ".txt"
    with open(file) as f_out:
        lines = f_out.readlines()
        for line in lines:
            domain = line.strip("\n")
            v_domains.append(domain)

    return v_domains


def list2objs(data_list, model, keys):
    objs = []
    for item in data_list:
        params = {keys[0]: item[0], keys[1]: item[1], keys[2]:item[2]}
        obj = model(params)
        objs.append(obj)
    return objs


def save2database(domains):
    count_zero = 0
    for domain in domains:
        answer_list, authority_list, additional_list = dig_one_domain(domain)
        print("handlering domain: %s, len of answer_list: %s" % (domain, len(answer_list)))
        if len(answer_list) == 0:
            count_zero += 1

        dns_answer_objs = []
        for answer in answer_list:
            dns_answer = DnsAnswer(domain, answer[1], answer[2])
            dns_answer_objs.append(dns_answer)
        for auth in authority_list:
            if not domain == auth[0]:
                print("domain: %s, auth_domain_name: %s" % (domain, auth[0]))
            auth_answer = AuthAnswer(auth[0], auth[1], auth[2])
        for add_info in additional_list:
            add_answer = AddAnswer(add_info[0], add_info[1], add_info[2])

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
        v_domains = read_from_domain_list(choice)
        save2database(v_domains)

        # 随机睡眠一段时间继续查看
        random_num = random.randint(60, 7200)
        time.sleep(random_num)

    session.close()

