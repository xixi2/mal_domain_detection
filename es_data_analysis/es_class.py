# -*- coding:utf-8 -*-
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError, TransportError


class CreateIndexError(Exception):
    def __init__(self, err):
        Exception.__init__(self, err)


class IndexAlreadyExistError(Exception):
    def __init__(self, err):
        Exception.__init__(self, err)


class DocumentMissingError(Exception):
    def __init__(self, err):
        Exception.__init__(self, err)


class BulkInsertDataError(Exception):
    def __init__(self, err):
        Exception.__init__(self, err)


class QueryBody:
    """
    QueryBody是用于构建查询体
    """

    def __init__(self):
        self.query_body = {
            "query": {"bool": {"must": [], }},
            "sort": [], "from": 0,
        }

    def set_query_string(self, content):
        """
        :param content: 搜索的内容，content若为空字符串，则会匹配空字符串
        :return:
        """
        self.query_body["query"]["bool"]["must"].append({
            "query_string": {
                "query": content
            }
        })

    def set_query_range(self, fields, min_val, max_val):
        """
        :param fields: 范围搜索所需的字段名
        :param min_val: 范围搜索的最小值
        :param max_val: 范围搜索的最大值
        :return:
        """
        for field in fields:
            self.query_body["query"]["bool"]["must"].append({
                "range": {field: {"gte": min_val, "lte": max_val}}
            })

    def set_query_sort(self, fields, is_desc=True):
        """
        :param fields: 排序所需的字段名,默认逆序排序
        :param is_desc: 是否按逆序排序
        :return:
        """
        for field in fields:
            self.query_body["sort"].append({
                field: {"order": "desc" if is_desc else "asc"}
            })

    def set_from_doc(self, from_num):
        self.query_body["from"] = from_num

    def set_doc_size(self, size):
        self.query_body["size"] = size

    def set_search_all(self):
        self.query_body["query"]["match_all"] = {}

    def get_query_body(self):
        return self.query_body


class ElasticSearchUtil(object):
    def __init__(self, host, doc_type):
        self.doc_type = doc_type
        self.conn = Elasticsearch(hosts=host)

    def __del__(self):
        self.close()

    def set_setting(self, index_name, max_result_window=10000000):
        setting_body = {
            "index": {
                "max_result_window": max_result_window
            }
        }
        return self.conn.indices.put_settings(body=setting_body, index=index_name)

    def index_exists(self, index_name):
        """
        返回是True或者False
        """
        return self.conn.indices.exists(index=index_name)

    def set_index_mapping(self, index_name, mapping_dict):
        """
        设置mapping
        """
        mapping = {
            self.doc_type: mapping_dict
        }
        if not self.conn.indices.exists(index=index_name):
            # 创建index和mapping
            self.conn.indices.create(index=index_name)
            self.conn.indices.put_mapping(index=index_name, doc_type=self.doc_type, body=mapping)

    def insert_doc(self, index_name, body, id_name=None):
        """
        新插入一条数据body到指定的index、指定的type下;可指定Id,若不指定,ES会自动生成
        """
        if id_name is None:
            try:
                self.conn.index(index=index_name, doc_type=self.doc_type, body=body, refresh=True)
            except Exception as e:
                raise CreateIndexError(e)
        else:
            id = body.get(id_name)
            try:
                flow = self.conn.get(index_name, self.doc_type, id)
            except NotFoundError as e:
                try:
                    self.conn.create(index=index_name, doc_type=self.doc_type, body=body, id=id, refresh=True)
                except Exception as e:
                    raise CreateIndexError(e)
            else:
                detail = 'document whose id is %s already exists' % body[id_name]
                raise IndexAlreadyExistError(detail)

    def bulk_insert_doc(self, index_name, body_list, id_name=None):
        """
            批量插入文档
        """
        load_data = []
        for body in body_list:
            if id_name:
                id = body.get(id_name)
                body.pop(id_name)
                load_data.append({"index": {"_id": id}})
            else:
                load_data.append({"index": {}})
            load_data.append(body)

        try:
            self.conn.bulk(index=index_name, doc_type=self.doc_type, body=load_data, refresh=True)
            del load_data[:len(load_data)]
        except Exception as e:
            raise BulkInsertDataError(e)

    def update_doc_by_id(self, index_name, id, body=None):
        """
        通过id修改一条已经存在的数据
        """
        try:
            self.conn.update(index=index_name, doc_type=self.doc_type, id=id, body=body, refresh=True)
        except TransportError as e:
            raise DocumentMissingError('index:%s, id:%s, document missing' % (index_name, id))
        except Exception as e:
            raise

    def delete_doc_by_id(self, index_name, id):
        """
        删除指定的index，type,id对应的数据
        """
        try:
            self.conn.delete(index=index_name, doc_type=self.doc_type, id=id, refresh=True)
        except Exception as e:
            raise

    def delete_doc_by_query(self, index_name, query):
        """
        删除index下符合条件query的所有数据
        """
        try:
            self.conn.delete_by_query(index=index_name, doc_type=self.doc_type, body=query, refresh=True)
        except Exception as e:
            raise

    def delete_all_doc(self, index_name):
        """
        删除指定idnex下所有数据
        """
        try:
            query = {"query": {"match_all": {}}}
            self.conn.delete_by_query(index=index_name, body=query, doc_type=self.doc_type, refresh=True)
        except Exception as e:
            raise

    def search_doc_by_query(self, index_name, body=None, params=None):
        """
        查找index下所有符合条件的数据
        返回值：返回一个元组，第一个元素是查询到的文档的总数，第二个是所有文档信息
        """
        try:
            result = self.conn.search(index=index_name, doc_type=self.doc_type, body=body, params=params)
            total = result['hits']['total']
            content = []
            for item in result['hits']['hits']:
                item['_source']['_id'] = item['_id']
                content.append(item['_source'])
            return total, content
        except Exception as e:
            raise

    def get_doc_by_id(self, index_name, id):
        """
        返回值：返回查询到的文档个数
        """
        try:
            result = self.conn.get(index=index_name, doc_type=self.doc_type, id=id)
            result['_source']['_id'] = result['_id']
            return result['_source']
        except Exception as e:
            raise

    def close(self):
        if self.conn is not None:
            self.conn = None

    def refresh(self, index_name):
        self.conn.indices.refresh(index=index_name)

    def get_total_by_search(self, index_name, body):
        result = self.conn.search(index=index_name, doc_type=self.doc_type, body=body)
        total = result['hits']['total']
        return total
