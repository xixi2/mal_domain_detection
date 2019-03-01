from es_data_analysis.database_op import connect_db, query_db, insert_db, update_db

TABLE_NAME = 'connections_copy2'


conn = connect_db()


def extract_enternal_ips_from_connection_table():
    """
    1）找到在这段时间内所有与内部主机相连的外部IP
    2）
    :return:
    """
    sql ="select distinct(external_ip) FROM {0} GROUP BY external_ip".format(TABLE_NAME)
    print("sql: {0}".format(sql))
    query_num = -1
    res = query_db(conn, sql, query_num)  # 返回的结果是一个元组
    sql = "insert into external_ips (ip, is_malicious, counter) VALUES"
    i = -1
    for item in res:
        i += 1
        if i % 50 == 9:
            sql += ",('{0}',{1},{2})".format(item[0], 0, 0)
            # print("sql: {0}".format(sql))
            print('{0} line: process================================'.format(i))
            insert_db(conn, sql)
            sql = "insert into external_ips (ip, is_malicious, counter) VALUES"
        else:
            ip = item[0]
            if i % 50 == 0:
                sql += " ('{0}',{1},{2})".format(ip, 0, 0)
            else:
                sql += ",('{0}',{1},{2})".format(ip, 0, 0)


def mal_detector():
    """
    对于external_ips数据表中的每个ip，查询它是否在恶意IP库ip_list中，
    若在，说明该ip是恶意IP。
    :return:
    """
    query_num = 100
    sql = ""
    print("sql: {0}".format(sql))
    res = query_db(conn, sql, query_num)  # 返回的结果是一个元组
    for item in res:
        ip = item[0]
        sql = "select * from ip_list where ip = '{0}'".format(ip)
        res = query_db(conn, sql)
        if len(res) > 0:
            sql = "update external_ips set is_malicious = {0} where ip = '{1}'".format(1, ip)
            print("sql: {0}".format(sql))
            update_db(conn, sql)


if __name__ == "__main__":
    # extract_enternal_ips_from_connection_table()
    mal_detector()
