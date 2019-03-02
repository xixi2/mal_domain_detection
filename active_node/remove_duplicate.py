import time
from common.database_op import connect_db, query_db, delete_db

conn = connect_db()


def remove_double():
    sql = "select DISTINCT(domain_name) from dns_answer"
    res = query_db(conn, sql)
    affected_ids = []
    for item in res:
        domain =item[0]
        sql = 'select id from (select id from dns_answer where domain_name = "{0}" and ip in  ' \
              '(SELECT ip FROM dns_answer where domain_name = "{0}" group by ip having count(*) >=1)) ta ' \
              'where id != (select MIN(id) from dns_answer where domain_name = "{0}" and ip in  ' \
              '(SELECT ip FROM dns_answer where domain_name = "{0}" group by ip having count(*) >1))'\
            .format(domain)
        res = query_db(conn, sql)
        if len(res) == 0:
            continue
        print("domain: %s, duplicate_ids:%s" % (domain, affected_ids))
        for index, item in enumerate(res):
            affected_id = int(item[0])
            affected_ids.append(affected_id)
    return affected_ids


if __name__ == "__main__":
    affected_ids = remove_double()
    if len(affected_ids) > 0:
        del_sql = "delete from dns_answer where id in ("
        for index, affected_id in enumerate(affected_ids):
            if index == 0:
                del_sql += "%s" % (affected_id,)
            else:
                del_sql += ", %s" % (affected_id)
        del_sql += ")"
        print(del_sql)
        delete_db(conn, del_sql)
    conn.close()