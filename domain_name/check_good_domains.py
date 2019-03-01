"""
这个文件是为了从alexa_top1m正常域名符串中提取特征，具体特征提取方法见：恶意域名字符串(pdf文件)
"""
import csv
from domain_name.domain_name_word_segment import word_segment, get_longest_meaningful_substring_v0
from common.database_op import connect_db, insert_db

conn = connect_db()

good_domain_table = "good_domains"


def extract2level_domain(good_domain):
    name_list = good_domain.split('.')
    # print('name_list: {0}'.format(name_list[-2]))
    return name_list[-2]


def save2database(domain_info_list):
    sql = ""
    for i in range(len(domain_info_list)):
        good_domain, sld, n_digits, n_groups_of_digits, n_group_of_word_segs, longest_len, longest_substring = \
            domain_info_list[i]
        if i == 0:
            sql = 'insert into {0} (domain_name, sld, digit_numbers, digit_groups, word_groups, ' \
                  'longest_len,longest_substring) values("{1}","{2}",{3},{4},{5},{6},"{7}")' \
                .format(good_domain_table, good_domain, sld, n_digits, n_groups_of_digits,
                        n_group_of_word_segs, longest_len, longest_substring)
        else:
            sql += ',("{1}","{2}",{3},{4},{5},{6},"{7}")' \
                .format(good_domain_table, good_domain, sld, n_digits, n_groups_of_digits,
                        n_group_of_word_segs, longest_len, longest_substring)
    # print('sql: {0}'.format(sql))
    insert_db(conn, sql)


def check1m_good_domains(batch_num=50):
    good_domains = get1m_good_domains()
    domain_info_list = []
    i = 0
    for good_domain in good_domains:
        i += 1
        second_level_domain = extract2level_domain(good_domain)
        n_digits, digit_segs, word_segs = word_segment(second_level_domain)
        n_groups_of_digits = len(digit_segs)  # 整个二级域名字符串可以被多少组数字分隔开
        n_group_of_word_segs = len(word_segs)  # 整个二级域名中字符串最为被分为了多少组如w3cschool最后被分为三组：w, c,school
        longest_len, longest_substring = get_longest_meaningful_substring_v0(word_segs)
        # print('==============================================================')
        # print('good_domain: {0}, second_level_domain: {1}, digit_segs: {2}, word_segs:{3}'
        #       .format(good_domain, second_level_domain, digit_segs, word_segs))
        # print('second_level_domain: {0}, n_digits: {1}, n_groups_digits: {2}, n_group_word_segs: {3}'
        #       .format(second_level_domain, n_digits, n_groups_of_digits, n_group_of_word_segs))
        # print('second_level_domain: {0}, longest_len:{1},longest_substring: {2}'
        #       .format(second_level_domain, longest_len, longest_substring))
        domain_info_list.append((good_domain, second_level_domain, n_digits, n_groups_of_digits, n_group_of_word_segs,
                                 longest_len, longest_substring))
        if i % batch_num == 0 or i == len(good_domains):
            save2database(domain_info_list)
            domain_info_list = []
            print('第{0}个域名正在统计'.format(i))


def get1m_good_domains():
    good_domains = []
    with open("top-1m.csv") as f:
        f_csv = csv.reader(f)
        headers = next(f_csv)
        for line in f_csv:
            # print('line: {0}'.format(line[1]))
            domain_name = line[1]
            good_domains.append(domain_name)
    return good_domains


if __name__ == '__main__':
    check1m_good_domains()
    # get1m_good_domains()
