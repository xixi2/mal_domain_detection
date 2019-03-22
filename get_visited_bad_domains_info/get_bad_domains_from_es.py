"""
此文件是为了从ES索引malicious-domains中获取976个非DGA恶意域名
"""

from common.index_op_mal_dom import set_mal_domain_index_params
from common.common_domains_op import write2file
from common.common_domains_op import FULL_DOM_DIR


def get_non_dga_domains():
    query_body = {"query": {"bool": {"must_not": [{"query_string": {"default_field": "info.Desc", "query": "DGA"}}]}}}
    bad_domains = set_mal_domain_index_params(query_body)
    print("len of bad_domains: %s" % len(bad_domains))
    file = FULL_DOM_DIR + "es_non_dga.txt"
    write2file(file, bad_domains)


if __name__ == '__main__':
    get_non_dga_domains()
