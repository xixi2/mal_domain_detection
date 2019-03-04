"""
此文件是为了处理恶意域名，提取出其中的两层域名。如baidu.com
"""
import os
import re
from _datetime import datetime
import random
import time
import tldextract
import csv

from common.verify_domain_bad.test_domain import scan_url

ROOT_DIR = "../data_set/bad_domains/"
DST_DIR = "../data_set/extrated_bad_domains/"


def keep_2nd_dom_name(domain_name):
    """
    只保留两层域名
    :param domain_name:
    :return:
    """
    sub_domain, domain, suffix = tldextract.extract(domain_name)
    return domain + "." + suffix


def keep_3th_dom_name(domain_name):
    """
    只保留两层域名
    :param domain_name:
    :return:
    """
    sub_domain, domain, suffix = tldextract.extract(domain_name)
    sub_domain_list = sub_domain.split(".")
    if len(sub_domain_list) > 1:
        sub_domain = sub_domain_list[-1]
    if sub_domain != "":
        new_domain = ".".join((sub_domain, domain, suffix))
    else:
        new_domain = ".".join((domain, suffix))
        # print("domain_name: %s, sub: %s, dom: %s, suffix: %s, new_domain: %s" % (domain_name, sub_domain, domain, suffix, new_domain))
    return new_domain


def is_domain_ip(domain):
    # 检测域名是否是IP，如果是，返回None
    pattern = "[\d]+\.[\d]+\.[\d]+\.[\d]"
    if re.match(pattern, domain):
        return True
    else:
        return False


def handle_domain(domain):
    """处理从文件中读出的每个域名"""
    domain = domain.strip("\n")
    pos = domain.find(" ")
    if pos >= 0:
        domain = domain[:pos]

    pos = domain.find(":")
    if pos >= 0:
        domain = domain[:pos]

    while domain.find("/") >= 0:
        pos = domain.find("/")
        domain = domain[:pos]

    if is_domain_ip(domain):
        return None
    if domain.find("(") >= 0:
        return None
    return domain


def read_file(file, choice=2):
    domains_set = set()
    with open(file, "r") as f:
        lines = f.readlines()
        # thread_hold = get_thread_hold(len(lines))
        # thread_hold = 5
        for line in lines:
            # if len(domains_set) >= 5000:
            #     break
            # random_state = random.randint(0, 10)
            # if random_state < thread_hold:
            #     continue
            domain = handle_domain(line)
            if domain:
                if choice == 2:
                    # print("keep_2nd_dom_name")
                    domain = keep_2nd_dom_name(domain)
                if choice == 3:
                    # print("keep_3th_dom_name")
                    domain = keep_3th_dom_name(domain)
                domains_set.add(domain)
    return domains_set


def read_file_list(dir, choice):
    files = os.listdir(dir)
    domains_set = set()
    number_of_bad = 20000
    for file in files:
        file_dir = ROOT_DIR + "/" + file
        print(file_dir)
        domains = read_file(file_dir, choice)
        domains_set = domains_set | domains

        print("len(domains_set): %s" % (len(domains_set)))
        if len(domains_set) >= number_of_bad:
            break

    file = DST_DIR + "domains" + str(choice) + ".txt"
    if os.path.exists(file):
        os.remove(file)
    print("os.path.exists(file): %s" % (os.path.exists(file),))
    print("write to file：%s" % file)
    write2file(file, domains_set)


def write2file(file, domains_set):
    with open(file, "a+") as f_in:
        for domain in domains_set:
            line = domain + "\n"
            f_in.write(line)


def csv2txt():
    """把hosts_phishtank.csv文件转为txt文件"""
    src_file = "hosts_phishtank.csv"
    dst_file = ROOT_DIR + "/" + "hosts_phishtank.txt"
    http_phrase = "http://"
    domains_set = set({})
    with open(src_file, "r") as f_out:
        f_csv = csv.reader(f_out)
        for row in f_csv:
            url = row[1]
            if url.find(http_phrase) >= 0:
                pos = url.find(http_phrase) + len(http_phrase)
                url = url[pos:]
                pos = url.find("/")
                if pos >= 0:
                    url = url[:pos]
                if not is_domain_ip(url):
                    # print("url %s, row[1]: %s" % (url, row[1]))
                    domains_set.add(url)
    write2file(dst_file, domains_set)


def find_last_checked_lines(dst_file):
    with open(dst_file) as f_out1:
        last_line = f_out1.readlines()[-1]
    return last_line


def test_domains_list(choice):
    file = DST_DIR + "domains" + str(choice) + ".txt"
    dst_file1 = DST_DIR + "v_domains" + str(choice) + ".txt"
    dst_file2 = DST_DIR + "unc_domains" + str(choice) + ".txt"
    bad_domains = []
    uncertain_domains = []
    try:
        with open(file, "r") as f_out:
            lines = f_out.readlines()
            print("lines len: %s, id lines: %s" % (len(lines), id(lines)))

            v_last_line = find_last_checked_lines(dst_file1)
            u_last_line = find_last_checked_lines(dst_file2)
            pos1 = lines.index(v_last_line)
            pos2 = lines.index(u_last_line)
            if pos1 <= pos2:
                pos1 = pos2
            lines = lines[pos1+1:]
            # print("v_last_line:%s u_last_line: %s" % (v_last_line, u_last_line))
            # print("pos1:%s pos2: %s" % (pos1, pos2))
            print("lines len: %s, id lines: %s" % (len(lines), id(lines)))

            for line in lines:
                if len(bad_domains) >= 50:
                    print("bad_domains write to file")
                    write2file(dst_file1, bad_domains)
                    bad_domains = []
                if len(uncertain_domains) >= 50:
                    print("uncertain_domains write to file")
                    write2file(dst_file2, uncertain_domains)
                    uncertain_domains = []
                domain = line.strip("\n")
                bad_flag = scan_url(domain)
                if bad_flag == True:
                    bad_domains.append(domain)
                else:
                    uncertain_domains.append(domain)
                time.sleep(60)
    except Exception as e:
        print("error: %s" % e)
    finally:
        print("totally %s domains are bad!" % len(bad_domains))
        print("totally %s domains are uncertain!" % len(uncertain_domains))
        if bad_domains:
            write2file(dst_file1, bad_domains)
        if uncertain_domains:
            write2file(dst_file2, uncertain_domains)



if __name__ == '__main__':
    # csv2txt()
    choice = int(input("please enter a choice from 2,3 "))
    # print("choice: %s, type: %s" % (choice, type(choice)))
    # read_file_list(ROOT_DIR, choice)
    start = datetime.now()
    test_domains_list(choice)
    end = datetime.now()
    time_cost = (end - start).seconds
    print("time_cost: %s" % time_cost)
