import socket
import threading
import subprocess
from elasticsearch import Elasticsearch, helpers
from es_data_analysis.database_op import connect_db, insert_db, update_db

HOST = "10.1.1.205:9200"
INDEX_NAME = "malicious-domains"
DOC_TYPE = 'logs'
table_name = 'domain2ip'
es = Elasticsearch(hosts=HOST)
conn = connect_db()


def get_domains():
    index_name = INDEX_NAME
    domain_set = set()
    # print(index_name)
    if es.indices.exists(index_name):
        query_body = {"query": {"match_all": {}}}
        # print('query_body:{0}'.format(query_body))
        gen = helpers.scan(es, index=index_name, doc_type=DOC_TYPE, query=query_body)
        for item in gen:
            item = item['_source']
            domain_name = item['domain']
            # print('item: {0}'.format(item))
            print('domain_name: {0}'.format(domain_name))
            domain_set.add(domain_name)
        # print(len(domain_set))
        return domain_set


def save_domains2database(domain_set):
    batch_num = 100
    sql = "insert into {0} (domain, ip) values".format(table_name)
    for index, domain in zip(range(len(domain_set)), domain_set):
        if index % batch_num == batch_num - 1:      # 执行sql并重新初始化sql
            insert_db(conn, sql)
            sql = "insert into {0} (domain, ip) values".format(table_name)
        elif index % batch_num == 0:
            # sql = "insert into {0} (domain, ip) values ('{1}', '')".format()
            sql += " ('{0}','')".format(domain)
        else:
            sql += ",('{0}','')".format(domain)


def save_domains_ip2database(domain, ip, mode=1):
    # print('enter save_domains_ip2database')
    print('domain: {0}, ip: {1}'.format(domain, ip))
    if mode == 1:
        # sql = "update {0} set ip='{1}' where domain ='{2}'".format(table_name, ip, domain)
        sql = "update {0} set ip='{1}' where domain ='{2}' and ip !=''".format(table_name, ip, domain)
    else:       # 记录主机名、域名、ip列表（可能有多个）
        # sql = "update {0} set ip='{1}' where domain ='{2}'".format(table_name, ip, domain)
        sql = "update {0} set ip='{1}' where domain ='{2}' and ip != ''".format(table_name, ip, domain)
    update_db(conn, sql)


def parsing_domain_name(domain):      # parsing domain names
    host_ip = None
    try:
        host_ip = socket.gethostbyname(domain)  # 解析百度的域名所对应的ip，gethostbyname主要解析单个域名
    except socket.error as e:
        pass
        # print("gethostbyname failed")                   # 函数返回值为解析完的ip
    return host_ip


def parsing_domain_name02(domain_list):
    for domain in domain_list:
        host_ip = parsing_domain_name(domain)
        if host_ip:
            print('domain: {0}, ip: {1}'.format(domain, host_ip))
            save_domains_ip2database(domain, host_ip)


def multi_thread(domain_list):
    l = len(domain_list)
    print('len of domain_list: {0}'.format(len(domain_list)))
    domain_sub_lists = []
    for i in range(10):
        start = i * (l // 10)
        end = (i+1) * (l // 10)
        if i == 9:
            end = l
        # print('start: {0}, end:{1}'.format(start, end))
        domain_sub_lists.append(domain_list[start: end])
    t_list =[]
    for i in range(10):
        t_list.append(threading.Thread(target=parsing_domain_name02, args=(domain_sub_lists[i],)))


def run_system_command(domain_name):
    # 执行一个指定的命令并将执行结果以一个字节字符串的形式返回。
    # 如果需要文本形式返回，加一个解码步骤。如果返回非零码，就会抛出异常。
    try:
        # out_bytes = subprocess.check_output(['nslookup', domain_name])
        out_bytes = subprocess.check_output(['dig', '+short', domain_name])
        # print(out_bytes.decode('ascii'))
        print(out_bytes.decode('utf-8'))
        # print(out_bytes.decode('utf-8', errors='ignore'))
    except subprocess.CalledProcessError as e:      # 捕获错误并获取返回码
        out_bytes = e.output
        code = e.returncode


if __name__ == '__main__':
    # 使用socket.gethostbyname解析域名对应的ip
    domain_set = get_domains()
    domain_list = list(domain_set)
    save_domains2database(domain_set)
    domain_dict = parsing_domain_name02(domain_set)
    multi_thread(domain_list)
    domain_sub_set1 = [domain for domain in domain_dict]        # 通过scoket.gethostbyname能够找到IP的域名组成的集合
    print('len of domain_dict: {0}'.format(len(domain_dict)))

    # 使用dig命令查询域名对应的ip，未成功，需要在Linux上运行
    # run_system_command('www.baidu.com')