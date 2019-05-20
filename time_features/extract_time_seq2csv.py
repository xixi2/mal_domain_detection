# 分析提取出的访问频率，检测异常点
import pandas as pd
import matplotlib.pyplot as plt
from pymongo import MongoClient
from common.mongodb_op import mongo_url
from common.mongodb_op import NIC_LOG_MONGO_DB, BAD_DOMAINS_COUNTER2ND_MONGO_INDEX, BAD_DOMAINS_COUNTER3TH_MONGO_INDEX
from time_features.count_bad_domains_visiting import DOMAIN_2ND_FIELD, DATE_FIELD

TIME_SEQ_FIELD = "time_seq"
TIME_SEQ_FILE = TIME_SEQ_FIELD + ".csv"
client = MongoClient(mongo_url)
db_nic_bad_visiting = client[NIC_LOG_MONGO_DB]
mongo_index_2nd = BAD_DOMAINS_COUNTER2ND_MONGO_INDEX


def csv2df():
    df = pd.read_csv(TIME_SEQ_FILE)
    print(len(df))
    # for i in range(len(df)):
    #     print("aaa%s, %s" % (i, df.loc[i]))
    


def get_visiting_frequency():
    recs = db_nic_bad_visiting[mongo_index_2nd].find()
    vis_dict_list = []
    for rec in recs:
        domain = rec[DOMAIN_2ND_FIELD]
        date_str = rec[DATE_FIELD]
        vis_dict = {
            DOMAIN_2ND_FIELD: domain,
            DATE_FIELD: date_str
        }
        for index in range(24):
            index_counter = rec.get(str(index), 0)
            vis_dict[index] = index_counter
        vis_dict_list.append(vis_dict)
    columns_fields = [DOMAIN_2ND_FIELD, DATE_FIELD]
    for index in range(24):
        columns_fields.append(index)
    df = pd.DataFrame(vis_dict_list, columns=columns_fields)
    df.sort_values(by=DOMAIN_2ND_FIELD).sort_values(by=DATE_FIELD)
    df.to_csv(TIME_SEQ_FILE, index=True)
    print(df.loc[0])


if __name__ == '__main__':
    # get_visiting_frequency()
    csv2df()
