import os
import re

def print_list(res_list):
    for index, item in enumerate(res_list):
        print("index: %s, item: %s" % (index, item))

class DomainDigger:
    def __int__(self):
        self.res_list = []
        self.answer_list = []
        self.authority_list = []
        self.additional_list = []

    def clear_all_data(self):
        self.res_list.clear()
        self.answer_list.clear()
        self.authority_list.clear()
        self.additional_list.clear()

    def get_detail_info(self, start_index, total_count, choice=1):
        temp_list = []
        i = 0
        try:
            if i < total_count and start_index < len(self.res_list):
                while i < total_count and start_index + i < len(self.res_list):
                    ans_str = self.res_list[start_index + i].strip(" ")
                    ans_list = [item.strip(" ") for item in re.split("\t| ", ans_str) if len(item) > 0]
                    i += 1
                    if choice == 1 and ans_list[3] != 'A':
                        ans_list = []
                    else:
                        del ans_list[2], ans_list[2]
                    print("choice: %s, ans_list: %s" % (choice, ans_list))
                    if len(ans_list) == 3:
                        temp_list.append(tuple(ans_list))
        except Exception as e:
            print("error e: %s" % e)
        return temp_list

    def split_statistic_get_count(self, res):
        """
        从统计行中获取各个应答个数，统计行如：
        :return:
        """
        answer_count, additional_count, authority_count = 0, 0, 0
        res = res.strip(" ")
        pos = res.find(";")
        res = res[pos + 1:].strip(" ")
        line_list = res.split(",")
        for item in line_list:
            item = item.strip(" ")
            item_list = [each.strip(" ") for each in item.split(":")]
            if item_list[0] == "ANSWER":
                answer_count = int(item_list[1])
            elif item_list[0] == "AUTHORITY":
                authority_count = int(item_list[1])
            elif item_list[0] == "ADDITIONAL":
                additional_count = int(item_list[1])
        return answer_count, authority_count, additional_count

    def add_new_answer(self, start_index, count, data_list, choice):
        tmp_list = self.get_detail_info(start_index, count, choice)
        if tmp_list:
            new_tmp = list(set(tmp_list) - set(data_list))
            data_list.extend(new_tmp)

    def get_domain_info(self):
        """
        answer domain_name,
            原始字段包括：TTL, 'IN', 'A', IP_address；切分后只保留TTL, 'A', IP_address
        authority: the nameserver which provides the convertion result from domain name to the ip address
            原始字段包括：domain_name, TTL, 'IN', 'NS', nameserver；切分后只保留domain_name, TTL, nameserver
        additional: 有时不一定能找到，它指定了返回该DNS应答的权威域名服务器的ip地址
            原始字段包括：nameserver, TTL, 'IN', 'A', IP_address；切分后只保留nameserver, TTL, IP_address
        :return:
        """
        answer_count, additional_count, authority_count = 0, 0, 0
        answer_index, authority_index, additional_index = len(self.res_list), len(self.res_list), len(self.res_list)
        for index, res in enumerate(self.res_list):
            pattern = "flags.+QUERY.+ANSWER.+AUTHORITY.+ADDITIONAL*"
            if re.match(pattern, res.strip(" ")):
                answer_count, authority_count, additional_count = self.split_statistic_get_count(res)
            elif res.find("ANSWER SECTION") >= 0:
                answer_index = index + 1
            elif res.find("AUTHORITY SECTION") >= 0:
                authority_index = index + 1
            elif res.find("ADDITIONAL SECTION") >= 0:
                additional_index = index + 1

        # print("answer_count: %s, authority_count:%s, additional_count:%s" % (
        #     answer_count, authority_count, additional_count))

        self.add_new_answer(answer_index, answer_count, self.answer_list, 1)
        print("len of answer_list: %s" % (len(self.answer_list),))

        self.add_new_answer(authority_index, authority_count, self.authority_list, 2)
        print("len of authority_list: %s" % (len(self.authority_list),))

        self.add_new_answer(additional_index, additional_count, self.additional_list, 3)
        print("len of additional_list: %s" % (len(self.additional_list),))

    def dig_domain(self, domain):
        self.clear_all_data()
        prefix = "dig @%s %s"
        dns_servers = [
            "8.8.8.8", "8.8.4.4",  # google DNS servers
            "114.114.114.114", "114.114.115.115",  # 114DNS
            "1.1.1.1", "1.0.0.1",  # CloudFlare DNS
            "119.29.29.29"  # DNS pod
        ]
        for dns_server in dns_servers:
            command = prefix % (dns_server, domain)
            with os.popen(command) as fd:
                res = fd.read()
            res_list = [item.strip(";").strip(" ") for item in res.split("\n") if item != ""]

            print_list(res_list)

            self.res_list.extend(res_list)
            self.get_domain_info()
            print_list(self.answer_list)
            print_list(self.authority_list)
            print_list(self.additional_list)




if __name__ == "__main__":
    domains = ["freedownload.ir", "lrtips.com", "hlc.edu.com"]
    domain_digger = DomainDigger()
    for domain in domains:
        domain_digger.dig_domain(domain)
