import os
import re


def get_detail_info(res_list, start_index, total_count, choice=1):
    temp_list = []
    i = 0
    try:
        if i < total_count and start_index < len(res_list):
            while i < total_count and start_index + i < len(res_list):
                ans_str = res_list[start_index + i].strip(" ")
                ans_list = [item.strip(" ") for item in re.split("\t| ", ans_str) if len(item) > 0]
                i += 1
                if choice == 1:
                    if ans_list[3] == "A":
                        del ans_list[2], ans_list[2]  # first delete the index 0 item and then resort the items
                    else:               # 当answer是CNAME记录时
                        ans_list = []
                if choice == 2:
                    del ans_list[2], ans_list[2]
                if choice == 3:
                    del ans_list[2], ans_list[2]
                # print("choice: %s, ans_list: %s" % (choice, ans_list))
                if ans_list:
                    temp_list.append(tuple(ans_list))
    except Exception as e:
        print("error e: %s" % e)
    return temp_list


def get_domain_info(res_list):
    answer_count, additional_count, authority_count = 0, 0, 0
    answer_index, authority_index, additional_index = len(res_list), len(res_list), len(res_list)
    for index, res in enumerate(res_list):
        pattern = "flags.+QUERY.+ANSWER.+AUTHORITY.+ADDITIONAL*"
        if re.match(pattern, res.strip(" ")):
            res = res.strip(" ")
            pos = res.find(";")
            res = res[pos + 1:].strip(" ")
            line_list = res.split(",")
            for item in line_list:
                item = item.strip(" ")
                item_list = [each.strip(" ") for each in item.split(":")]
                if item_list[0] == "ANSWER":
                    answer_count = int(item_list[1])
                if item_list[0] == "AUTHORITY":
                    authority_count = int(item_list[1])
                if item_list[0] == "ADDITIONAL":
                    additional_count = int(item_list[1])
        elif res.find("ANSWER SECTION") >= 0:
            answer_index = index + 1
        elif res.find("AUTHORITY SECTION") >= 0:
            authority_index = index + 1
        elif res.find("ADDITIONAL SECTION") >= 0:
            additional_index = index + 1

    print("answer_count: %s, authority_count:%s, additional_count:%s" % (
        answer_count, authority_count, additional_count))

    # answer domain_name, TTL, 'IN', 'A', IP_address
    answer_list = get_detail_info(res_list, answer_index, answer_count, 1)
    print("len of answer_list: %s" % (len(answer_list),))

    # authority: the nameserver which provides the convertion result from domain name to the ip address
    # authority: domain_name, TTL, 'IN', 'NS', nameserver
    authority_list = get_detail_info(res_list, authority_index, authority_count, 2)
    print("len of authority_list: %s" % (len(authority_list),))

    # additional: sometimes may not exist, which the ip address belonging to the nameserver
    # additional: nameserver, TTL, 'IN', 'A', IP_address
    additional_list = get_detail_info(res_list, additional_index, additional_count, 3)
    print("len of additional_list: %s" % (len(additional_list),))
    return answer_list, authority_list, additional_list


def dig_one_domain(domain):
    prefix = "dig @%s %s"
    dns_servers = [
        "8.8.8.8", "8.8.4.4",                    # DNS servers
        "114.114.114.114", "114.114.115.115"    # 114DNS
    ]
    answer_list, authority_list, additional_list = [], [], []
    for dns_server in dns_servers:
        command = prefix % (dns_server, domain)
        pfile = os.popen(command)
        res = pfile.read()
        pfile.close()
        res_list = [item.strip(";").strip(" ") for item in res.split("\n") if item != ""]
        answer_list, authority_list, additional_list = get_domain_info(res_list)
        if answer_list:
            break
        # 当answer为空时，强行将authority_list和additional_list置空
        if not answer_list:
            authority_list, additional_list = [], []
    return answer_list, authority_list, additional_list


if __name__ == "__main__":
    domains = ["freedownload.ir", "lrtips.com", "hlc.edu.com"]
    for domain in domains:
        dig_one_domain(domain)
