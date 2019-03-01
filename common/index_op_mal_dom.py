from elasticsearch import helpers, Elasticsearch

HOST = "10.1.1.205:9200"
MAL_DOMAIN_INDEX_NAME = "malicious-domains"
MAL_DOMAIN_DOC_TYPE = 'logs'


def get_all_domains(es, index_name, doc_type):
    domain_set = set()
    print(index_name)
    if es.indices.exists(index_name):
        query_body = {"query": {"match_all": {}}}
        gen = helpers.scan(es, index=index_name, doc_type=doc_type, query=query_body)
        for item in gen:
            item = item['_source']
            domain_name = item['domain']
            domain_set.add(domain_name)
        return list(domain_set), len(domain_set)


def set_mal_domain_index_params():
    index_name = MAL_DOMAIN_INDEX_NAME
    doc_type = MAL_DOMAIN_DOC_TYPE
    es = Elasticsearch(hosts=HOST)
    domain_list, total_len = get_all_domains(es, index_name, doc_type)
    return domain_list
