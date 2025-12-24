class BaseTask(object):
    type = 'BaseTask'

    def __init__(self, *args, **kwargs):
        super(BaseTask, self).__init__(*args, **kwargs)

    def serialize(self):
        return {'type': self.type}
