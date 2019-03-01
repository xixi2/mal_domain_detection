"""
这个文件是为了统计ttl的变化及绘图显示
"""
from common.database_op import connect_db, insert_db, query_db
import matplotlib.pyplot as plt


conn = connect_db()


def count_ttl(table_name="loc_ip_ttl"):
    sql = "SELECT *,count(*) FROM {0} group by ttl".format(table_name)
    res = query_db(conn, sql)
    ttl_counter_list = []
    ttl_list = []
    for item in res:
        ttl = item[3]
        ttl_counter = item[-1]
        ttl_list.append(ttl)
        ttl_counter_list.append(ttl_counter)
        #     print(item)
        print('ttl: {0}, ttl_counter: {1}'.format(ttl, ttl_counter))
    return ttl_list, ttl_counter_list

def draw_bar(ttl_list, ttl_counter_list):
    plt.bar(ttl_list, ttl_counter_list, fc='g')
    # plt.bar([1,2,3,4],[1,2,3,4],fc='r')
    plt.show()


def draw_pie(ttl_list, ttl_counter_list):
    # labels = 'Frogs', 'Hogs', 'Dogs', 'Logs'
    # sizes = [15, 30, 45, 10]

    colors = ['yellowgreen', 'gold', 'lightskyblue', 'lightcoral', 'blue']
    # explode = (0, 0.1, 0, 0, 0.05)  # only "explode" the 2nd slice (i.e. 'Hogs')
    explode = (0, 0, 0, 0, 0)  # only "explode" the 2nd slice (i.e. 'Hogs')

    # plt.pie(sizes, explode=explode, labels=labels, colors=colors,
    #         autopct='%1.1f%%', shadow=True, startangle=90)
    plt.pie(ttl_counter_list, explode=explode, labels=ttl_list, colors=colors,
            autopct='%1.1f%%', shadow=True, startangle=90)
    # Set aspect ratio to be equal so that pie is drawn as a circle.
    plt.axis('equal')

    plt.show()



if __name__ == "__main__":
    ttl_list, ttl_counter_list = count_ttl()
    number_of_different_ttl = len(ttl_list)     # ttl不同取值的总数
    draw_pie(ttl_list, ttl_counter_list)