"""
这个文件是为了验证恶意域名的后缀是否同passive DNS检测那篇论文中提到的结论一致：后缀是：.info， .org，.biz
"""
import csv
import pandas as pd
import operator
from domain_name.domain_name_word_segment import word_segment, get_longest_meaningful_substring_v0
from common.database_op import connect_db, insert_db
from common.index_op_mal_dom import set_mal_domain_index_params
from common.draw_picture import draw_pie

conn = connect_db()
bad_suffix_list = ['info', 'org', 'biz']


def count_domain_suffix(bad_domains):
    bad_suffix_counter = {}
    # for domain_suffix in bad_suffix_list:
    #     bad_suffix_counter[domain_suffix] = 0
    for bad_domain in bad_domains:
        domain_string_list = bad_domain.split('.')
        domain_suffix = domain_string_list[-1]
        counter = bad_suffix_counter.get(domain_suffix, 0)
        bad_suffix_counter[domain_suffix] = counter + 1
        print('domain_suffix: {0}'.format(domain_suffix))
    for bad_domain, counter in bad_suffix_counter.items():
        print('bad_domain: {0}， counter: {1}'.format(bad_domain, counter))
    bad_suffix_list, counter_list = [], []
    for bad_domain, counter in bad_suffix_counter.items():
        bad_suffix_list.append(bad_domain)
        counter_list.append(counter)
    df = pd.DataFrame({"suffix": bad_suffix_list, "counter": counter_list})
    df.to_csv('suffix_stat.csv', index=False)


def is_digit(suffix):
    for c in suffix:
        if not (c >= '0' and c <= '9'):
            return False
    return True


def visual_suffix_stat(sorted_suffix_counter, most_common_num=10):
    label_list, label_counter = [], []
    colors = ['yellowgreen', 'gold', 'lightskyblue', 'lightcoral', 'blue',
              'gray', 'white', 'purple', 'red', 'Orange']
    explode = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for suffix, counter in sorted_suffix_counter[:most_common_num]:
        label_list.append(suffix)
        label_counter.append(counter)
    draw_pie(label_list, label_counter, colors, explode)
    print(label_list)
    print(label_counter)


def count_suffix_stat():
    suffix_counter = {}
    with open("suffix_stat.csv") as f:
        f_csv = csv.reader(f)
        headers = next(f_csv)
        for line in f_csv:
            suffix = line[0]
            counter = int(line[1])
            # print(line)
            if is_digit(suffix):
                continue
            suffix_counter[suffix] = counter

    sorted_suffix_counter = sorted(suffix_counter.items(), key=operator.itemgetter(1), reverse=True)
    return sorted_suffix_counter


if __name__ == '__main__':
    # bad_domains = set_mal_domain_index_params()
    # count_domain_suffix(bad_domains)
    sorted_suffix_counter = count_suffix_stat()
    visual_suffix_stat(sorted_suffix_counter)
