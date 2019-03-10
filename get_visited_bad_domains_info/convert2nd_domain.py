"""
此文件是为了处理恶意域名，提取出其中的两层域名。如baidu.com
并验证提取出的恶意域名是否真的是恶意的，形成最终的恶意域名数据集
"""
import os
import re
import time
import tldextract
from get_visited_bad_domains_info.test_domain import scan_url

ROOT_DIR = "../data_set/bad_domains_txt/"
DST_DIR = "../data_set/extrated_bad_domains/"
DST_DIR1 = "../data_set/verified_bad_domains/"


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


DOMAIN_LEVEL_CHOICE = {
    2: keep_2nd_dom_name,
    3: keep_3th_dom_name
}


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
    """
    :param file: 原始域名文件，其中的域名为全限定域名
    :param choice: choice用于选择提取域名的级数，2为提取两级域名，3为提取三级域名
    :return:
    """
    domains_set = set()
    with open(file, "r") as f:
        lines = f.readlines()
        for line in lines:
            domain = handle_domain(line)
            if domain:
                func = DOMAIN_LEVEL_CHOICE[choice]
                func(domain)
                domains_set.add(domain)
    return domains_set


def read_file_list(dir, choice):
    """
    :param dir:
    :param choice:
    :return:
    """
    files = os.listdir(dir)
    count = 0
    for file in files:
        domains_set = set()
        file_dir = ROOT_DIR + file
        # print(file)
        domains = read_file(file_dir, choice)
        domains_set = domains_set | domains
        count += len(domains_set)
        file_prefix = file.split(".")[0]
        file = DST_DIR + file_prefix + "_" + str(choice) + ".txt"
        if os.path.exists(file):
            os.remove(file)
        print("write to file：%s" % file)
        write2file(file, domains_set)

    print("totally %s bad domains" % count)


def write2file(file, domains_set):
    with open(file, "a+") as f_in:
        for domain in domains_set:
            line = domain + "\n"
            f_in.write(line)


def find_last_checked_lines(dst_file):
    with open(dst_file) as f_out1:
        last_line = f_out1.readlines()[-1]
    return last_line


def test_domains(file, dst_file, choice=2):
    """
    测试恶意域名是否真的是恶意的
    """
    print("file: %s, dst_file: %s" % (file, dst_file))

    bad_domains = []
    try:
        with open(file, "r") as f_out:
            lines = f_out.readlines()
            if os.path.exists(dst_file):
                v_last_line = find_last_checked_lines(dst_file)
                pos1 = lines.index(v_last_line)
                if pos1 < len(lines):
                    lines = lines[pos1 + 1:]
            print("there is %s left to be handled" % (len(lines),))
            for line in lines:
                if len(bad_domains) >= 50:
                    print("bad_domains write to file")
                    write2file(dst_file, bad_domains)
                    bad_domains = []
                domain = line.strip("\n")
                bad_flag = scan_url(domain)
                if bad_flag:
                    bad_domains.append(domain)
                time.sleep(120)
    except Exception as e:
        print("error: %s" % e)
    finally:
        print("totally %s domains are bad!" % len(bad_domains))
        if bad_domains:
            write2file(dst_file, bad_domains)


def test_domains_list(dir):
    for file in os.listdir(dir):
        dst_file = DST_DIR1 + file
        file = DST_DIR + file
        test_domains(file, dst_file)


if __name__ == '__main__':
    # read_file_list(ROOT_DIR, choice=2)
    test_domains_list(DST_DIR)
