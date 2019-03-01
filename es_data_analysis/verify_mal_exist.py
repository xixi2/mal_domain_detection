from elasticsearch import Elasticsearch
from elasticsearch import helpers

from es_data_analysis.constants import generate_date_str, str2timestamp
from es_data_analysis.database_op import connect_db, insert_db

HOST = '10.1.1.201:9200'
MAL_IP_HOST = '10.1.1.205:9200'
MAL_DOMAIN_HOST = '10.1.1.205:9200'
DOC_TYPE = 'logs4th'
MAL_IP_DOC_TYPE = 'logs'
MAL_DOMAIN_DOC_TYPE = 'logs'
es = Elasticsearch(hosts=HOST)
es_mal_ip = Elasticsearch(hosts=MAL_IP_HOST)

OUTER_IPS_FILE = 'outer_ips.txt'
INDEX_NAME_PREFIX = 'niclog-4th-'
MAL_IP_INDEX_NAME_PREFIX = 'malicious-ip-'
MAL_DOMAIN_INDEX_NAME_PREFIX = 'malicious-domain-'

VISIT_TABLE_NAME = 'visited_servers_30_3'
conn = connect_db()

MAL_IP_INDEX = "malicious-ips"
MAL_DOMAIN_INDEX = "malicious-ips"


def get_all_mal_ips():
    mal_ips = set()
    query_body = {"query": {"match_all":{}}}
    gen = helpers.scan(es_mal_ip, index=MAL_IP_INDEX, doc_type=MAL_IP_DOC_TYPE, query=query_body)
    for item in gen:
        mal_ip = item['_source']['ip']
        mal_ips.add(mal_ip)
    print('len of mal_ips: {0}'.format(len(mal_ips)))
    return mal_ips


def get_outer_ips():
    outer_ips = []
    with open(OUTER_IPS_FILE) as f:
        for line in f.readlines():
            if line.find('len') != -1:
                continue
            outer_ips.append(line.strip('\n'))
    return outer_ips


def get_visited_info_tuple(doc_content):
    """
    :param doc_content: es中的任一文档
    :return: 五元组(内部主机的转换后IP，内部主机的mac， 内部主机访问的外部IP， 内部主机访问的域名， 访问的时间)
    """
    source_ip = doc_content["source-IP"]
    source_mac = doc_content["source-mac"]
    server_ip = doc_content["server-IP"]
    domain_name = doc_content["content"]
    time_stamp = doc_content["time-stamp"]
    time_stamp = str2timestamp(time_stamp)
    info_per_visited = (source_ip, source_mac, server_ip, domain_name, time_stamp)
    return info_per_visited


def get_docs(index_name):
    """
    每天获取实验访问过的外部IP及域名信息
    :param index_name:
    :return:
    """
    source_ips_info = set()
    # print('index_name: {0}'.format(index_name))
    outer_ips = get_outer_ips()
    terms_conditions = []
    for ip in outer_ips:
        terms_conditions.append(ip)
    # print('len of terms_condition：{0}'.format(len(terms_conditions)))

    if es.indices.exists(index_name):
        query_body = {"query": {"terms": {"source-IP": terms_conditions}}}
        # print('query_body:{0}'.format(query_body))
        gen = helpers.scan(es, index=index_name, doc_type=DOC_TYPE, query=query_body)
        for item in gen:
            doc_content = item['_source']
            conn_info_tuple = get_visited_info_tuple(doc_content)
            # print('conn_info_tuple: {0}'.format(conn_info_tuple))
            source_ips_info.add(conn_info_tuple)

    # 这里是否可以考虑返回一个生成器
    # 返回的是在每天的日志中act*中的63个source-IP访问过的所有域名和IP信息及使用source-IP的内部主机信息
    return source_ips_info


def term_doc(field_name, field_val_list, es_info_tuple):
    terms_condition = [field_val for field_val in field_val_list]
    query_body = {"query": {"terms": {field_name: terms_condition}}}
    es, index_name, doc_type = (item for item in es_info_tuple)
    # print('es: {0}, index_name: {1}, doc_type: {2}'.format(es, index_name, doc_type))
    if es.indices.exists(index_name):
        # gen = helpers.scan(es, index_name, doc_type, query_body)   # 这种写法会出错，str object has not copy method
        gen = helpers.scan(es, index=index_name, doc_type=doc_type, query=query_body)

        # 如找到了恶意IP或者恶意域，则将server_ip是这些恶意IP或者domain_name是这些恶意域的连接的相应字段标记为1
        for item in gen:
            print('item: {0}'.format(item))
        return gen


def label_mal_conn(gen, flag=1):
    if not gen:
        return
    sql = ""
    if flag == 1:
        for item in gen:
            server_ip = item['_source']["ip"]
            sql ="update {0} set is_mal_ip=1 where server_ip={1}".format(VISIT_TABLE_NAME, server_ip)
    else:
        for item in gen:
            domain_name = item['_source']['domain']
            sql ="update {0} set is_mal_domain=1 where domain_name={1}".format(VISIT_TABLE_NAME, domain_name)
    if sql:
        insert_db(conn, sql)


def record_mal_conn_to_file(gen, flag=1):
    if not gen:
        return
    with open('res.txt', "w+") as f:
        for item in gen:
            item = item + "\n"
            f.write(item)


def check_ip_or_domain(temp_ips, ip_index_list,dom_index_list):
    server_ip_list = [item[2] for item in temp_ips]
    domain_list = [item[3] for item in temp_ips]
    for index in ip_index_list:
        es_info_tuple = (es_mal_ip, index, MAL_IP_DOC_TYPE)
        gen = term_doc("ip", server_ip_list, es_info_tuple)
        label_mal_conn(gen)
        record_mal_conn_to_file(gen)

    for index in dom_index_list:
        es_info_tuple = (es_mal_ip, index, MAL_IP_DOC_TYPE)
        gen = term_doc("domain", domain_list, es_info_tuple)
        label_mal_conn(gen, 2)
        record_mal_conn_to_file(gen)


def find_mal_server_ip_or_domain(source_ips_info, ip_index_list, dom_index_list):
    """
    :param source_ips_info:
    :param ip_index_name_list:
    :param dom_index_name_list:
    :return:
    """
    print('len of source_ips_info: {0}'.format(len(source_ips_info)))
    while source_ips_info:  # 批量查询，每次查询10个,直到source_ips_info为空
        batch_num = 50
        # temp_ips = source_ips_info[-batch_num:]
        i = 0
        temp_ips = []
        while source_ips_info and i < batch_num:
            temp_ips.append(source_ips_info[-1])
            source_ips_info.pop()
            i += 1
        # flag_list = is_server_ip_or_domain_mal(temp_ips, batch_num, ip_index_name_list, dom_index_name_list)
        check_ip_or_domain(temp_ips, ip_index_list, dom_index_list)


def save_visited_ips_info_into_database(source_ips_info):
    print('save_visited_ips_info_into_database len of source_ips_info: {0}'.format(len(source_ips_info_per_index)))
    sql = "insert into {0} (source_ip, mac, server_ip, domain_name, time_stamp, is_mal_ip, is_mal_domain) VALUES".format(
        TABLE_NAME)
    i = 0
    for item in source_ips_info:
        source_ip = item[0]
        mac = item[1]
        server_ip = item[2]
        domain_name = item[3]
        time_stamp = item[4]
        # domain_name可能有',"
        # if domain_name.find('\'') != -1:
        #     domain_name = domain_name.replace("'", "\'")
        if i % 10 == 0:
            sql += ' ("{0}", "{1}", "{2}", "{3}", "{4}",{5},{6})'.format(source_ip, mac, server_ip, domain_name,
                                                                         time_stamp, 0, 0)

        if i % 10 == 9:
            sql += ',("{0}", "{1}", "{2}", "{3}", "{4}",{5},{6})'.format(source_ip, mac, server_ip, domain_name,
                                                                         time_stamp, 0, 0)
            insert_db(conn, sql)
            sql = "insert into {0} (source_ip, mac, server_ip, domain_name, time_stamp, is_mal_ip, is_mal_domain) VALUES".format(
                TABLE_NAME)
        else:
            # sql += ",('{0}', '{1}', '{2}', '{3}', {4}, {5})".format(source_ip, mac, server_ip, domain_name, 0, 0)
            sql += ',("{0}", "{1}", "{2}", "{3}", "{4}", {5}, {6})'.format(source_ip, mac, server_ip, domain_name,
                                                                           time_stamp, 0, 0)
        i += 1
        # print('insert {0} sql'.format(i))


def insert_mal_ip_tuple_into_database(mal_ip_tuple):
    table_name = "mal_ips_confirmed"
    sql = "insert into {0} (source_ip, mac, server_ip, domain_name, time_stamp, is_mal_ip, is_mal_domain) VALUES".format(table_name)
    source_ip = mal_ip_tuple[0]
    mac = mal_ip_tuple[1]
    server_ip = mal_ip_tuple[2]
    domain_name = mal_ip_tuple[3]
    time_stamp = mal_ip_tuple[4]
    sql += ' ("{0}", "{1}", "{2}", "{3}", "{4}",{5},{6})'.format(source_ip, mac, server_ip, domain_name,time_stamp, 0, 0)
    insert_db(conn, sql)


if __name__ == '__main__':
    # get_outer_ips()
    date_format = '%Y.%m.%d'
    date_str_list = generate_date_str(5, date_format)
    # date_str_list = date_str_list[78:]
    date_format = '%Y.%m.%d'
    # date_str_lists = generate_date_str(30, date_format)
    # ip_index_name_list = [MAL_IP_INDEX_NAME_PREFIX + date_str for date_str in
    #                       date_str_lists]  # 查看过去一段时间内（如30天）的恶意域名记录，比较得出实验室是否有人访问过恶意域名
    # dom_index_name_list = [MAL_DOMAIN_INDEX_NAME_PREFIX + date_str for date_str in
    #                        date_str_lists]  # 查看过去一段时间内（如30天）的恶意域名记录，比较得出实验室是否有人访问过恶意域名
    visiteded_servers_index_name_list = [INDEX_NAME_PREFIX + date_str for date_str in date_str_list]
    mal_ips_index = ["malicious-ips", ]
    mal_domains_index = ["malicious-ips", ]

    # 将所有的恶意IP从恶意IP库中取出，放入内存的一个集合中。
    # mal_ips = get_all_mal_ips()

    for index_name in visiteded_servers_index_name_list:
        print('visited index name: {0}'.format(index_name))
        source_ips_info_per_index = get_docs(index_name)
        source_ips_info_per_index = list(source_ips_info_per_index)

        # 查看source_ips_info_per_index是否在mal_ips（恶意IP集合）中，即访问过的server_ip是否是恶意IP
        # print('len of source_ips_info_per_index: {0}'.format(len(source_ips_info_per_index)))
        # for item in source_ips_info_per_index:
        #     server_ip = item[2]
        #     if server_ip in mal_ips:
        #         insert_mal_ip_tuple_into_database(item)

        # 将每天的访问信息存入到
        save_visited_ips_info_into_database(source_ips_info_per_index)
        # find_mal_server_ip_or_domain(source_ips_info_per_index, mal_ips_index, mal_domains_index)

        # 把恶意IP直接放进内存，和每天的访问IP做交集
        # only_ips = [ip_tuple[2] for ip_tuple in source_ips_info_per_index]
        # only_ips_set = set(only_ips)
        # intersect_ips = only_ips_set.intersection(mal_ips)
        # print('len of intersect_ips: {0}'.format(len(intersect_ips)))
        # for item in list(intersect_ips):
            # pos = only_ips.index(item)
            # mal_ip_tuple = source_ips_info_per_index[pos]
            # insert_mal_ip_tuple_into_database(mal_ip_tuple)
