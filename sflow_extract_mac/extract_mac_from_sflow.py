import json
import redis
from elasticsearch import Elasticsearch, helpers
import pandas as pd


HOST = "10.1.1.205:9200"
INDEX_NAME_PREFIX = "sflow-multi-"
DOC_TYPE = 'sflow'
es = Elasticsearch(hosts=HOST)
r = redis.Redis(host='127.0.0.1', port=6379, db=1)
src_ip_key = "src_ip"
dst_ip_key = "dst_ip"
eth_src_key = "eth_src"
eth_dst_key = "eth_dst"


def add_ip_mac_to_mac_dict(mac_dict, ip, mac):
    if not mac in mac_dict:
        mac_dict[mac] = []
    mac_dict[mac].append(ip)


def add_ip_mac_to_redis(mac, ip):
    n_of_mems = r.scard(mac)
    r.sadd(mac, ip)


def get_mac_maps():
    """
    从一个sflow索引中中读取出所有的mac-ip
    形如： mac_dict = {
        mac1 : [ip0],
        mac2: [ip0, ip1, ip2]
    }
    :return:
    """
    index_name = INDEX_NAME_PREFIX + "2018.12.13"

    print(index_name)
    if es.indices.exists(index_name):
        query_body = {"query": {"match_all": {}}}
        print('query_body:{0}'.format(query_body))
        gen = helpers.scan(es, index=index_name, doc_type=DOC_TYPE, query=query_body)
        for item in gen:
            doc_content = item['_source']
            if src_ip_key in doc_content and eth_src_key in doc_content:
                src_ip = doc_content["src_ip"]
                eth_src = doc_content["eth_src"]
                print("src_ip: {0}, eth_src:{1}".format(src_ip, eth_src))
                # add_ip_mac_to_mac_dict(mac_dict, src_ip, eth_src)
                add_ip_mac_to_redis(eth_src,src_ip)

            if dst_ip_key in doc_content and eth_dst_key in doc_content:
                dst_ip = doc_content["dst_ip"]
                eth_dst = doc_content["eth_dst"]
                print("dst_ip: {0}, eth_dst:{1}".format(dst_ip, eth_dst))
                # add_ip_mac_to_mac_dict(mac_dict, dst_ip, eth_dst)
                add_ip_mac_to_redis(eth_dst, dst_ip)
    print('finish checking index: %s' % index_name)


def check_single_mac():
    mac_list = r.keys()
    print('len of keys: {0}'.format(len(mac_list)))
    for mac in mac_list:
        n_of_ips = r.scard(mac)
        if n_of_ips > 1:
            # print(n_of_ips)
            r.delete(mac)
        # else:
        #     ip_of_mac = r.smembers(mac)
        #     print(ip_of_mac)
    mac_list = r.keys()
    print('len of keys: {0}'.format(len(mac_list)))


def save_mac_ip_to_csv():
    mac_list = r.keys()
    ip_list = []
    for mac in mac_list:
        ip = r.smembers(mac)
        ip_list.append(ip)
    df = pd.DataFrame({"mac": mac_list, "ip": ip_list})
    df.to_csv('mac_ip.csv')


if __name__ == "__main__":
    get_mac_maps()
    check_single_mac()
    save_mac_ip_to_csv()