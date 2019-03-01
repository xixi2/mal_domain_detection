import pymysql

HOST = 'localhost'
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
    return res


def update_db(conn, sql):
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        conn.commit()
    except Exception as e:
        print('Error: {0}, sql: {1}'.format(e, sql))
        conn.rollback()


if __name__ == '__main__':
    conn = connect_db()
    table_name = 'feature'
    values = ('vvvv',)
