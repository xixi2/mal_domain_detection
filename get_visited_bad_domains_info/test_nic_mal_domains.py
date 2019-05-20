"""
验证从niclong中匹配的二级域名的完整域名是否是恶意的。
这些完整域名对应的二级域名是恶意的。
"""
from pymongo import MongoClient
from common.mongodb_op import NIC_LOG_MONGO_DB, DOMAIN_SUBDOMAIN_MONGO_INDEX
from common.mongodb_op import mongo_url
from get_visited_bad_domains_info.test_one_domain import scan_url

client = MongoClient(mongo_url)
db_nic_sub_domains = client[NIC_LOG_MONGO_DB]


def get_niclog_mal_domains(query_body=None):
    recs = []
    if not query_body:
        rec = db_nic_sub_domains[DOMAIN_SUBDOMAIN_MONGO_INDEX].find()
        print("ans: %s" % (rec.count(),))
    else:
        rec = db_nic_sub_domains[DOMAIN_SUBDOMAIN_MONGO_INDEX].find(query_body)
    for item in rec:
        del item["_id"]
        recs.append(item)
    return recs


def save_mal_domains2mongodb(db, domain_2nd, sub_domains):
    db[DOMAIN_SUBDOMAIN_MONGO_INDEX].update({"domain": domain_2nd}, {"$addToSet": {"ver_mal_sub_domains": {"$each": sub_domains}}}, True)


def test_mal_domains(mal_domain_dict):
    for domain_dict in mal_domain_dict:
        domain_2nd = domain_dict["domain"]
        sub_domains = domain_dict["subdomains"]
        ver_sub_domains = domain_dict.get("ver_mal_sub_domains", [])
        print("domain_2nd: %s" % (domain_2nd,))
        if scan_url(domain_2nd):
            sub_domains = list(set(sub_domains) - set(ver_sub_domains))
            for sub_domain in sub_domains:
                if not scan_url(sub_domain):
                    sub_domains.remove(sub_domain)
                    print("domain_2nd: %s, sub_domain: %s" % (domain_2nd, sub_domain))
            save_mal_domains2mongodb(db_nic_sub_domains, domain_2nd, sub_domains)


if __name__ == "__main__":
    recs = get_niclog_mal_domains()
    print(recs[0])
    test_mal_domains(recs)
