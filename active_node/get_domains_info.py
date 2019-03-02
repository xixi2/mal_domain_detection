import time
import random
from active_node.dig_domain import dig_one_domain
from active_node.remove_duplicate import remove_double
from common.database_op import connect_db, insert_db

DST_DIR = "../data_set/extrated_bad_domains/"

conn = connect_db()


def read_from_domain_list(choice):
    v_domains = []
    file = DST_DIR + "v_domains" + str(choice) + ".txt"
    with open(file) as f_out:
        lines = f_out.readlines()
        for line in lines:
            domain = line.strip("\n")
            v_domains.append(domain)

    return v_domains


def save2database(domains):
    for domain in domains:
        print("handlering domain: %s" % domain)
        answer_list, authority_list, additional_list = dig_one_domain(domain)
        ans_sql = ""
        for index, answer in enumerate(answer_list):
            if index == 0:
                ans_sql += "insert into dns_answer (domain_name,TTL , ip) VALUES ('%s',%s, '%s')" % (
                    domain, answer[1], answer[2])
            else:
                ans_sql += ", ('%s',%s, '%s')" % (domain, answer[1], answer[2])

        auth_sql = ""
        for index, auth in enumerate(authority_list):
            if index == 0:
                auth_sql += "insert into dns_auth_answer (domain_name, TTL, nameserver) VALUES ('%s', %s, '%s')" % (
                    auth[0], auth[1], auth[2])
            else:
                auth_sql += ",('%s', %s, '%s')" % (auth[0], auth[1], auth[2])

        add_sql = ""
        for index, add_info in enumerate(additional_list):
            if index == 0:
                add_sql += "insert into dns_add_answer (nameserver, TTL, ip) VALUES ('%s', %s, '%s')" % (
                    add_info[0], add_info[1], add_info[2])
            else:
                add_sql += ", ('%s', %s, '%s')" % (add_info[0], add_info[1], add_info[2])
        if ans_sql:
            insert_db(conn, ans_sql)
        if auth_sql:
            insert_db(conn, auth_sql)
        if add_sql:
            insert_db(conn, add_sql)


if __name__ == "__main__":
    for i in range(10):
        remove_double()
        # choice = int(input())
        choice = 2
        v_domains = read_from_domain_list(choice)
        save2database(v_domains)

        # 随机睡眠一段时间继续查看
        random_num = random.randint(60, 7200)
        time.sleep(random_num)
