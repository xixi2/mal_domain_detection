from es_data_analysis.es_class import ElasticSearchUtil

HOST = '192.168.105.132:9200'
DOC_TYPE = 'events'
INDEX_NAME = 'cuckoobox_enterprise_events'
es = ElasticSearchUtil(HOST, DOC_TYPE)

def save_to_es():
    mapping_dict = {
        "time": ""
    }
    es.set_index_mapping(INDEX_NAME, mapping_dict)


if __name__ == '__main__':
    pass
