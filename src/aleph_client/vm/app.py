from dataclasses import dataclass
from typing import List, Dict, Callable, Awaitable, Optional

AsgiApplication = Callable


@dataclass
class EventHandler:
    filters: List[Dict]
    handler: Callable

    def matches(self, scope: Dict) -> bool:
        for filter in self.filters:
            # if [filter matches scope]: TODO
            if True:
                return True
        return False


class AlephApp:
    """ASGI compatible wrapper for apps running inside Aleph Virtual Machines.
    The wrapper adds support to register functions to react to non-HTTP events.
    """

    http_app: Optional[AsgiApplication] = None
    event_handlers: List[EventHandler]

    def __init__(self, http_app: Optional[AsgiApplication] = None):
        self.http_app = http_app
        self.event_handlers = []

    def event(self, filters: List[Dict]):
        """Use this decorator to register event calls.

        ```python
            @app.event(filters=[...])
            def on_event(event):
                ...
        ```
        """

        def inner(func: Callable):
            # Register the event handler
            event_handler = EventHandler(filters=filters, handler=func)
            self.event_handlers.append(event_handler)
            return func

        return inner

    def __call__(
        self, scope: Dict, receive: Awaitable, send: Callable[[Dict], Awaitable]
    ):
        if scope["type"] in ("http", "websocket"):
            if self.http_app:
                return self.http_app(scope=scope, receive=receive, send=send)
            else:
                raise ValueError("No HTTP app registered")
        elif scope["type"] == "aleph.message":
            for event_handler in self.event_handlers:
                if event_handler.matches(scope):
                    # event_handler.handler(scope=scope, receive=receive, send=send)
                    async def send_handler_result():
                        result = await event_handler.handler(event=scope)
                        await send(result)

                    return send_handler_result()
        else:
            raise ValueError(f"Unknown scope type '{scope['type']}'")

    def __getattr__(self, name):
        # Default all calls to the HTTP handler
        return getattr(self.http_app, name)
