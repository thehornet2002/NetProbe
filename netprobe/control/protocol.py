import json
from typing import Dict, Any, Optional


class MessageType:
    HELLO = "HELLO"
    HELLO_ACK = "HELLO_ACK"
    PREPARE = "PREPARE"
    PREPARED = "PREPARED"
    EXECUTE = "EXECUTE"
    RESULT = "RESULT"
    FINISHED = "FINISHED"


class ControlMessage:
    """Wraps control plane messages transmitted over WebSocket."""

    @staticmethod
    def create(msg_type: str, payload: Optional[Dict[str, Any]] = None) -> str:
        data = {
            "type": msg_type,
            "payload": payload or {}
        }
        return json.dumps(data)

    @staticmethod
    def parse(raw_text: str) -> Dict[str, Any]:
        return json.loads(raw_text)
