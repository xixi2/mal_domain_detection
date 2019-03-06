"""
这个文件是为了验证恶意域名中存在badwords.txt中出现的常见恶意域名中出现的一些短语的情况
"""
from elasticsearch import Elasticsearch
import pandas as pd
import jieba
from domain_name.database_op import connect_db, query_db, insert_db, update_db
from common.index_op_mal_dom import HOST, MAL_DOMAIN_DOC_TYPE, MAL_DOMAIN_INDEX_NAME, get_all_domains

conn = connect_db()


def is_meaningful(sub_str):
    pass


def get_longest_meaningful_sub_string(string):
    meaningful_sub_strs = []
    for i in range(len(string)):
        for j in range(i + 1, len(string)):
            sub_str = string[i:j]
            if is_meaningful(sub_str):
                meaningful_sub_strs.append(sub_str)
    max_len = 0
    max_item = -1
    for item in meaningful_sub_strs:
        l = len(item)
        if l > max_len:
            max_len = l
            max_item = item
    return max_len


def get_numbers_of_number(string):
    total = 0
    for c in string:
        if c >= '0' and c <= '9':
            # print('c: {0}'.format(c), end=' ')
            total += 1
        # try:
        #     c = int(c)
        #     total += 1
        # except Exception as e:
        #     print('can not convert to number: {0}'.format(e))
    return total


def get_number_ration_in_domain_names(domain_list):
    splitters = ["/", "."]
    number_ratio = 0
    for item in domain_list:
        l_str = len(item)
        total = get_numbers_of_number(item)  # 获得每一个域名中数字的个数
        number_ratio = total / l_str
    return number_ratio


def set_index_params():
    index_name = MAL_DOMAIN_INDEX_NAME
    doc_type = MAL_DOMAIN_DOC_TYPE
    es = Elasticsearch(hosts=HOST)
    domain_list = get_all_domains(es, index_name, doc_type)
    return domain_list


def set_sql_params():
    table_name = "domain2ip"
    sql = "select count(*) from {0}".format(table_name)
    total_num = query_db(conn, sql)[0][0]
    # print('res: {0}'.format(total_num))
    sql = "select * from {0}".format(table_name)
    res = query_db(conn, sql)
    domain_set = set({})
    for item in res:
        # print('item: {0}'.format(item))
        domain_name = item[0]
        # print('domain_name: {0}'.format(domain_name))
        domain_set.add(domain_name)
    return list(domain_set), total_num


def get_bad_words():
    bad_words = []
    with open("badwords.txt") as f:
        for line in f.readlines():
            line = line.strip()
            bad_words.append(line)
    return bad_words


def exist_common_bad_substring(domain_list):
    """
    域名中是否存在类似free,loging等词
    :return:
    """
    print('enter exist_common_bad_substring')
    print('len of domain_list: {0}'.format(len(domain_list)))
    bad_words = get_bad_words()
    bad_dict = {}
    for domain_name in domain_list:
        for item in bad_words:
            pos = domain_name.find(item)
            if pos >= 0:
                bad_dict[domain_name] = item
    return bad_dict


def bad_dict2csv(bad_dict):
    for domain_name, bad_word in bad_dict.items():
        print('domain_name: {0}, bad_word: {1}'.format(domain_name, bad_word))
    bad_word_list = []
    domain_name_list = []
    for domain_name, bad_word in bad_dict.items():
        domain_name_list.append(domain_name)
        bad_word_list.append(bad_word)
    df = pd.DataFrame({"domain_name": domain_name_list, "bad_word": bad_word_list})
    index_list = [item for item in range(len(bad_dict))]
    df.to_csv('bad_dict.csv', index=index_list)
    print('len of bad_dict: {0}'.format(len(bad_dict)))


def check_all_bad_domain_names():
    # domain_list, total_num = set_sql_params()
    domain_list, total_num = set_index_params()
    bad_dict = exist_common_bad_substring(domain_list)
    bad_dict2csv(bad_dict)
    get_number_ration_in_domain_names(domain_list)


if __name__ == "__main__":
    check_all_bad_domain_names()
    # get_bad_words()
