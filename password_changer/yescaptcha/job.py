import time
from yescaptcha.exceptions import YesCaptchaException
from yescaptcha.settings import JOB_CHECK_INTERVAL
from loguru import logger


class Job(object):
    client = None
    task_id = None
    _last_result = None

    def __init__(self, client, data):
        self.client = client
        self.data = data
        self._last_result = data
        self.task_id = data.get('taskId')
        logger.level('DEBUG' if client.debug else 'INFO')

    def __str__(self):
        return str(self._last_result)

    def _update(self):
        self._last_result = self.client.get_task_result(self.task_id)
        
    def check_is_ready(self):
        self._update()
        return self._last_result.get('status') == 'ready'
   
    def get_solution(self):
        return self._last_result.get('solution')

    def get_solution_text(self):
        return self._last_result.get('solution', {}).get('text')

    def join(self, maximum_time=None):
        start_time = int(time.time())
        while not self.check_is_ready():
            time.sleep(JOB_CHECK_INTERVAL)
            elapsed_time = int(time.time()) - start_time
            if elapsed_time is not None and elapsed_time > self.client.timeout_join:
                raise YesCaptchaException(
                    None, 'JOB_JOIN_TIMEOUT',
                    f"Timeout after {elapsed_time} seconds"
                )
