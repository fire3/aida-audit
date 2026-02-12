class EngineLogger:
    def __init__(self, logger=None, verbose=False):
        self._logger = logger
        self._verbose = verbose

    def debug(self, event, **fields):
        pass

    def info(self, event, **fields):
        pass

    def warn(self, event, **fields):
        pass

    def error(self, event, **fields):
        pass

    def _format_value(self, value):
        if isinstance(value, (list, tuple, set)):
            items = list(value)
            head = items[:8]
            suffix = ",..." if len(items) > 8 else ""
            return "[" + ",".join(str(x) for x in head) + suffix + "]"
        if isinstance(value, dict):
            items = []
            for key in sorted(value.keys()):
                items.append(f"{key}={self._format_value(value[key])}")
            return ",".join(items)
        return str(value)