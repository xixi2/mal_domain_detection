"""
此文件是为了将URL或者全限定域名转换成二级域名，如将27lelchgcvs2wpm7.b7mciu.top转换为b7mciu.top
"""
import os
import re
import tldextract
from common.common_domains_op import write2file
from common.common_domains_op import FULL_DOM_DIR, UVER_DOM_DIR

# 暂时这么写
from common.common_domains_op import keep_2nd_dom_name, keep_3th_dom_name

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
    """
    处理从文件中读出的每个域名: 因为源文件中是url，而不是域名，因此需要一定的处理才能提取出正确的全限定域名
    """
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
                domain = func(domain)
                domains_set.add(domain)
    return domains_set


def read_file_list(dir, choice):
    """
    :param dir: 从指定目录下读取一些文件，这些文件中都是不同类型的恶意域名（全限定域名），将这些文件中的域名转换成
                两级或者三级域名后重新写入新的文件
    :param choice:choice=2表示保留2级域名，3表示保留3级域名
    :return:
    """
    files = os.listdir(dir)
    count = 0
    for file in files:
        domains_set = set()
        file_dir = FULL_DOM_DIR + file
        # print(file)
        domains = read_file(file_dir, choice)
        domains_set = domains_set | domains
        count += len(domains_set)
        file_prefix = file.split(".")[0]
        file = UVER_DOM_DIR + file_prefix + "_" + str(choice) + ".txt"
        if os.path.exists(file):
            os.remove(file)
        write2file(file, domains_set)
        print("write to file：%s" % file)

    print("totally %s domains converted to %s level domain" % (count, choice))


if __name__ == '__main__':
    read_file_list(FULL_DOM_DIR, choice=2)
