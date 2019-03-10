# 验证alexa域名是否都是二级域名
# alexa_2nd都是二级域名

ALEXA_DOMAIN_FILE_DIR = "../data_set/good_domains/"
from get_visited_bad_domains_info.convert2nd_domain import keep_2nd_dom_name, write2file


def test_alexa_domains():
    domain_set = set()
    file = ALEXA_DOMAIN_FILE_DIR + "alexa.txt"
    with open(file, "r") as f:
        for line in f.readlines():
            domain = line.strip("\n")
            # print("line: %s" % domain)
            domain_2nd = keep_2nd_dom_name(domain)
            if domain_2nd != domain:
                print("notnonot %s" % domain)
            domain_set.add(domain_2nd)
    print("len of domain_set: %s" % len(domain_set))
    return domain_set


if __name__ == '__main__':
    domain_set = test_alexa_domains()
    file = ALEXA_DOMAIN_FILE_DIR + "alexa_2nd.txt"
    write2file(file, domain_set)