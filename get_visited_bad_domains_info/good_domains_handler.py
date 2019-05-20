from common.mongodb_op import GOOD_DOMAINS_MONGO_DB, GOOD_DOMAINS_MONGO_INDEX
from common.mongodb_op import mongo_url
from pymongo import MongoClient

client = MongoClient(mongo_url)
db = client[GOOD_DOMAINS_MONGO_DB]

GOOD_DOMAINS_FILE = "../data_set/good_domains/alexa_2nd.txt"


def save_good_domains2mongodb():
    with open(GOOD_DOMAINS_FILE) as f_out:
        for line in f_out.readlines():
            good_domain = line.strip("\n")
            print(good_domain)
            query_body = {"domain": good_domain}
            rec_counter = db[GOOD_DOMAINS_MONGO_INDEX].find(query_body).count()
            if not rec_counter:
                db[GOOD_DOMAINS_MONGO_INDEX].insert(query_body)


if __name__ == "__main__":
    save_good_domains2mongodb()
