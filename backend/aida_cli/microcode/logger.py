class EngineLogger:
    def __init__(self, logger=None, verbose=False):
        self._logger = logger
        self._verbose = verbose

    def debug(self, event, **fields):
        self._emit("DEBUG", event, fields, verbose_only=True)

    def info(self, event, **fields):
        self._emit("INFO", event, fields)

    def warn(self, event, **fields):
        self._emit("WARN", event, fields)

    def error(self, event, **fields):
        self._emit("ERROR", event, fields)

    def _emit(self, level, event, fields, verbose_only=False):
        if verbose_only and not self._verbose:
            return
        message = self._format_message(event, fields)
        if self._logger and hasattr(self._logger, "log"):
            self._logger.log(message, level=level)
        else:
            print(f"[{level}] {message}")
            sys.stdout.flush()

    def _format_message(self, event, fields):
        formatted = self._format_event(event, fields)
        if formatted:
            return formatted
        parts = [f"{event}"]
        for key in sorted(fields.keys()):
            parts.append(f"{key}={self._format_value(fields[key])}")
        return " ".join(parts)

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

    def _format_event(self, event, fields):
        if event == "scan.global.callers":
            return f"callers sources={fields.get('sources')} sinks={fields.get('sinks')}"
        if event == "scan.global.missing_callers":
            return "callers missing"
        if event == "scan.global.no_path":
            return "call-chain none"
        if event == "scan.global.chain":
            return f"call-chain functions={fields.get('functions')}"
        if event == "scan.global.path":
            return f"call-chain {fields.get('path')}"
        if event == "scan.function.start":
            return f"function {fields.get('function')} insns={fields.get('insn_count')}"
        if event == "taint.source":
            return (
                f"taint source label={fields.get('label')} "
                f"ea={fields.get('ea')} func={fields.get('function')} "
                f"target={fields.get('target')} key={fields.get('key')}"
            )
        if event == "taint.flow":
            return (
                f"taint flow ea={fields.get('ea')} reads={self._format_value(fields.get('reads'))} "
                f"writes={self._format_value(fields.get('writes'))} "
                f"labels={self._format_value(fields.get('labels'))} "
                f"origins={self._format_value(fields.get('origins'))}"
            )
        if event == "taint.call.in":
            return (
                f"taint call-in caller={fields.get('caller')} callee={fields.get('callee')} "
                f"args={self._format_value(fields.get('args'))} labels={self._format_value(fields.get('labels'))} "
                f"origins={self._format_value(fields.get('origins'))}"
            )
        if event == "taint.call.propagate":
            return (
                f"taint call-prop caller={fields.get('caller')} callee={fields.get('callee')} "
                f"from={self._format_value(fields.get('from_args'))} "
                f"to={self._format_value(fields.get('to_args'))} "
                f"labels={self._format_value(fields.get('labels'))} "
                f"ret={fields.get('ret_key')}"
            )
        if event == "taint.call.ret":
            return (
                f"taint call-ret caller={fields.get('caller')} callee={fields.get('callee')} "
                f"ret={fields.get('ret_key')} labels={self._format_value(fields.get('labels'))} "
                f"origins={self._format_value(fields.get('origins'))}"
            )
        if event == "taint.sink.hit":
            return (
                f"taint sink func={fields.get('function')} callee={fields.get('callee')} "
                f"args={self._format_value(fields.get('args'))} "
                f"labels={self._format_value(fields.get('labels'))} "
                f"sources={self._format_value(fields.get('sources'))}"
            )
        return None