from es_data_analysis.database_op import connect_db, query_db, insert_db, update_db
from es_data_analysis.constants import CONNECTION_TABLE_NAME, EXTERNAL_IPS_TABLE_NAME
# EX_IPS_TABLE_NAME = 'external_ips'

conn = connect_db()


def extract_enternal_ips_from_connection_table():
    """
    1）从connection*数据表中找到在这段时间内所有与内部主机相连的外部IP
    2）将这些外部IP插入到external_ips*（记录每个外部IP连接的内部主机个数的数据库表），将is_malicious和counter字段默认设为0
    :return:
    """
    sql = "select distinct(external_ip) FROM {0} GROUP BY external_ip".format(CONNECTION_TABLE_NAME)
    print("sql: {0}".format(sql))
    query_num = -1
    res = query_db(conn, sql, query_num)  # 返回的结果是一个元组
    sql = "insert into {0} (ip, is_malicious, counter) VALUES".format(EXTERNAL_IPS_TABLE_NAME)
    i = -1
    print('total: {0}'.format(len(res)))
    for item in res:
        i += 1
        if i % 50 == 49:
            sql += ",('{0}',{1},{2})".format(item[0], 0, 0)
            # print("sql: {0}".format(sql))
            # print('{0} line: process================================'.format(i))
            insert_db(conn, sql)
            sql = "insert into {0} (ip, is_malicious, counter) VALUES".format(EXTERNAL_IPS_TABLE_NAME)
        else:
            ip = item[0]
            if i % 50 == 0:
                sql += " ('{0}',{1},{2})".format(ip, 0, 0)
            else:
                sql += ",('{0}',{1},{2})".format(ip, 0, 0)


def mal_detector():
    """
    对于external_ips数据表中的每个ip，查询它是否在恶意IP库ip_list中，
    若在，说明该ip是恶意IP，则修改external_ips数据表中该IP对应的is_malicious字段。
    :return:
    """
    query_num = -1
    sql = "select ip from {0} where ip not in (select ip from external_ips where ip not in (select ip from ip_list))".format(EXTERNAL_IPS_TABLE_NAME)
    print("sql: {0}".format(sql))
    res = query_db(conn, sql, query_num)  # 返回的结果是一个元组
    print('len of res: {0}'.format(len(res)))
    i = 0
    for item in res:
        i += 1
        if i % 100 == 0:
            print('i: {0}'.format(i))
        ip = item[0]
        sql = "update {0} set is_malicious = {1} where ip = '{2}'".format(EXTERNAL_IPS_TABLE_NAME, 1, ip)
        update_db(conn, sql)


def set_counter_for_per_ip():
    """
    统计每个外部IP连接的内部主机数目
    :return:
    """
    query_num = -1
    # sql = "select ip from {0}".format(EXTERNAL_IPS_TABLE_NAME)
    sql = "select ip from {0} where counter=0".format(EXTERNAL_IPS_TABLE_NAME)
    # print("sql: {0}".format(sql))
    res = query_db(conn, sql, query_num)  # 返回的结果是一个元组
    print('len of res:{0}'.format(len(res)))
    i = 0
    for item in res:
        i += 1
        if i % 1000 == 0:
            print('i: {0} process'.format(i))
        ip = item[0]
        # 最早时间这一项是否有必要统计
        # sql = "select count(*)，min(start_time) from {0} where external_ip = '{1}'".format(CONNECTION_TABLE_NAME, ip)
        sql = "select count(*) from {0} where external_ip = '{1}'".format(CONNECTION_TABLE_NAME, ip)
        res = query_db(conn, sql)
        # start_time = res[0][1]
        counter = res[0][0]
        # print('res: {0}, counter:{1}, start_time:{2}'.format(res, start_time, counter))
        # print('res: {0}, counter:{1}'.format(res, counter))
        # sql = "update external_ips set start_time='{0}',counter={1} where ip={2}".format(start_time, counter, ip)
        sql = "update external_ips set counter={0} where ip='{1}'".format(counter, ip)
        # print("sql: {0}".format(sql))
        update_db(conn, sql)


if __name__ == "__main__":
    # extract_enternal_ips_from_connection_table()
    # mal_detector()
    set_counter_for_per_ip()