from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from bs4 import BeautifulSoup
import pandas as pd
import time
from es_data_analysis.database_op import connect_db, query_db, insert_db, update_db
import os

conn = connect_db()


def test():
    caps = webdriver.DesiredCapabilities().FIREFOX
    caps["marionette"] = True
    binary = FirefoxBinary(r'D:\Program Files\Mozilla Firefox\firefox.exe')
    # 把上述地址改成你电脑中Firefox程序的地址
    driver = webdriver.Firefox(firefox_binary=binary, capabilities=caps)
    driver.get("http://www.santostang.com/2018/07/04/hello-world/")


def get_one_url_page(url, domain_name):
    # 打开浏览器
    options = webdriver.FirefoxOptions()
    options.add_argument('-headless')
    driver = webdriver.Firefox(options=options)

    # driver = webdriver.Firefox()
    # driver.set_window_size(100, 100)
    driver.get(url)  # driver.page_source可以获取当前源码，用BeautifulSoup解析网页
    page = BeautifulSoup(driver.page_source, 'html5lib')
    search(page, domain_name)
    driver.get(url)
    time.sleep(5)
    driver.close()


def get_many_pages():
    raw_url = "https://tool.chinaz.com/dns/"
    # url = raw_url + "?type="+ str(type) + "&host=" + host +  "&ip="
    sql = "select domain from domain2ip where domain not in (select domain_name from loc_ip_ttl)"
    res = query_db(conn, sql)
    i = 0
    for item in res:
        i += 1
        # file_name = 'loc_ip_ttl_' + str(i) + '.csv'
        domain_name = item[0]
        url = raw_url + "?type=1" + "&host=" + domain_name + "&ip="
        print('crawing domain: {0}'.format(domain_name))
        try:
            get_one_url_page(url, domain_name)
        except Exception as e:
            print('52 get domain {0} error: {1}'.format(domain_name, e))


def save_to_database(loc_ip_ttl):
    sql = ''
    table_name = 'loc_ip_ttl'
    for i in range(len(loc_ip_ttl)):
        # print('0000000',loc_ip_ttl[i])
        domain_name, location, ip, ttl, service_provider, ip_loc = loc_ip_ttl[i]
        if i == 0:
            sql += 'insert into {0} (domain_name, dns_loc, ip, ttl, service_provider, ip_loc) VALUES ("{1}", "{2}","{3}", {4}, "{5}", "{6}")'.format(
                table_name, domain_name, location, ip, ttl, service_provider, ip_loc)
        else:
            sql += ',("{0}", "{1}","{2}", {3}, "{4}", "{5}")'.format(domain_name, location, ip, ttl, service_provider,
                                                                     ip_loc)
    # print('len of loc_ip_ttl: {0}'.format(len(loc_ip_ttl)))
    # print('sql: {0}'.format(sql))
    insert_db(conn, sql)


def search(page, domain_name):
    """
    必须确认查出来的数据是正确的，这一点存疑
    :param page:
    :return:
    """
    # # 查找语句就跟用requests+beautifulsoup一样的
    class_value1 = 'w23-0'
    class_value2 = 'w60-0'
    class_value3 = 'w14-0'
    tag_value = 'div'
    res1 = page.find_all(tag_value, class_value1)  # <class 'bs4.element.ResultSet'>
    res2 = page.find_all(tag_value, class_value2)
    res3 = page.find_all(tag_value, class_value3)

    # df = pd.DataFrame({"DNS所在地":[], "响应IP":[], "TTL值":[]})
    ip_info = zip(res1, res2, res3)
    i = 0
    loc_ip_ttl = []
    for item in ip_info:
        if i == 0:  # 第一行是文件头
            i += 1
            continue
        # print('type(item[0]): {0}, type(item[1]): {1}, type(item[2])'.format(type(item[0])),type(item[1]), type(item[2]))
        # print('item 0================')
        # print(item[0])
        # print(item[0].string)

        location = item[0].string

        # 可能出现一个location对应多个ip的情况，ip与TTL成对出现
        # print('item 1================')
        # print(item[1])
        # print(item[1].contents)
        ips = []
        for tag_p in item[1].contents:
            ip = tag_p.string
            ips.append(ip)
        # print(len(item[1].contents))
        # print('ips: {0}'.format(ips))
        # print('item 2================')
        # print(item[2])
        # print(item[2].contents)
        ttls = []
        for tag_p in item[2].contents:
            ttl = tag_p.string
            ttls.append(ttl)
        # print('ttls: {0}'.format(ttls))

        # print(type(item[2]))
        # print(item)
        locations = [location] * len(item[1].contents)
        # print('locations: {0}'.format(locations))
        for item in zip(locations, ips, ttls):
            if item[1] != '-':
                location, service_provider = split_location(item[0])
                ip, ip_loc = split_ip(item[1])
                ttl = item[2]
                loc_ip_ttl.append((domain_name, location, ip, ttl, service_provider, ip_loc))

    if len(loc_ip_ttl):
        save_to_database(loc_ip_ttl)

        # df.loc[df.shape[0] + 1] = item
    # file_name = os.path.join('domain_locs', file_name)
    # df.to_csv(file_name, encoding="gbk")


def split_location(location):
    pos = location.find(']')
    location = location[:pos] + location[pos + 1:]
    # print(location)
    loc_list = location.split('[')
    return loc_list


def split_ip(ip_str=''):
    """
    175.126.123.219 [韩国 SK Broadband]===>['175.126.123.219', '韩国 SK Broadband']
    """
    pos = ip_str.find(']')
    ip_str = ip_str[:pos] + ip_str[pos + 1:]
    ip_str_list = [item.strip() for item in ip_str.split('[')]
    # print(ip_str_list)
    return ip_str_list


if __name__ == '__main__':
    get_many_pages()
