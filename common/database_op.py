import pymysql

HOST = '192.168.1.167'
USER_NAME = 'root'
PASS_WORD = '123456'
DATABASE = 'bp'


def connect_db():
    conn = pymysql.connect(HOST, USER_NAME, PASS_WORD, DATABASE)
    return conn


def insert_db(conn, sql):
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        cursor.close()
        conn.commit()
    except Exception as e:
        print('error {0}; sql: {1}'.format(e, sql))
        conn.rollback()


def query_db(conn, sql, query_num=-1):
    cursor = conn.cursor()
    cursor.execute(sql)
    if query_num == -1:
        res = cursor.fetchall()
    elif query_num == 1:
        res = cursor.fetchone()
    else:
        res = cursor.fetchmany(query_num)
    cursor.close()
    return res


def update_db(conn, sql):
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        cursor.close()
        conn.commit()
    except Exception as e:
        print('Error: {0}, sql: {1}'.format(e, sql))
        conn.rollback()


def delete_db(conn, sql):
    try:
        cursor = conn.cursor()
        res = cursor.execute(sql)
        print("res: %s" % res)
        cursor.close()
        conn.commit()
    except Exception as e:
        print('Error: {0}, sql: {1}'.format(e, sql))
        conn.rollback()




if __name__ == '__main__':
    conn = connect_db()
    sql = "delete from dns_answer where id in (137)"
    delete_db(conn, sql)
