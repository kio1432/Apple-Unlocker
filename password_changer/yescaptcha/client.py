from urllib.parse import urljoin
import requests
from yescaptcha.exceptions import YesCaptchaException
from yescaptcha.job import Job
from yescaptcha.settings import BALANCE_URL, BASE_URL_GLOBAL, BASE_URL_CHINA, CREATE_TASK_URL, TASK_RESULT_URL, TIMEOUT_JOIN, TIMEOUT_RESPONSE
from loguru import logger
from enum import Enum


class Region(Enum):
    GLOBAL = 'GLOBAL'
    CHINA = 'CHINA'


class Client(object):
    def __init__(self, client_key, soft_id=None, auto_join=True,
                 region=Region.GLOBAL, timeout_response=TIMEOUT_RESPONSE,
                 timeout_join=TIMEOUT_JOIN, debug=False):
        self.client_key = client_key
        self.soft_id = soft_id
        self.auto_join = auto_join
        self.region = region
        self.debug = debug
        self.timeout_response = timeout_response
        self.timeout_join = timeout_join
        self.session = requests.Session()
        
        self.base_url = BASE_URL_GLOBAL
        if self.region == Region.CHINA:
            self.base_url = BASE_URL_CHINA

        logger.level('DEBUG' if self.debug else 'INFO')

    def create_task(self, task):
        request = {"clientKey": self.client_key, "task": task.serialize()}
        if self.soft_id:
            request['softId'] = self.soft_id
        
        response = self.session.post(
            urljoin(self.base_url, CREATE_TASK_URL),
            json=request, timeout=self.timeout_response
        ).json()
        self._check_response(response)
        job = Job(self, response)
        if self.auto_join:
            job.join()
        return job
    
    def get_task_result(self, task_id):
        request = {"clientKey": self.client_key, "taskId": task_id}
        response = self.session.post(
            urljoin(self.base_url, TASK_RESULT_URL),
            json=request, timeout=self.timeout_response
        ).json()
        self._check_response(response)
        return response
    
    def get_balance(self):
        request = {"clientKey": self.client_key}
        response = self.session.post(
            urljoin(self.base_url, BALANCE_URL),
            json=request, timeout=self.timeout_response
        ).json()
        self._check_response(response)
        return response.get('balance')
    
    def _check_response(self, response):
        if response.get("errorId", False):
            raise YesCaptchaException(
                response["errorId"], response["errorCode"], response["errorDescription"]
            )
