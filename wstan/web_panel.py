import asyncio
import logging
import time
from json import dumps
import importlib.resources
from mimetypes import guess_type

import sanic
from sanic import Sanic, Blueprint, Request
from sanic.response import text, json, raw
from sanic.server import AsyncioServer

from wstan import __version__, InMemoryLogHandler

sanic_app = Sanic('wstan', log_config=None)
server: AsyncioServer
api_bp = Blueprint("api", url_prefix="/api/")
sanic_app.blueprint(api_bp)


@sanic_app.route("/")
async def index(request):
    return await package_file_handler(request, 'index.html')


@sanic_app.get("/<filename>")
async def package_file_handler(request, filename):
    resource_path = importlib.resources.files('wstan.static') / filename
    content_type = guess_type(resource_path)[0]
    try:
        with resource_path.open('rb') as f:
            return raw(f.read(), content_type=content_type)
    except FileNotFoundError:
        return text("File not found", status=404)


@api_bp.route("/status")
async def get_status(request):
    return json({"version": __version__,
                 "rtt": WSTunClientProtocol.rtt,
                 "connections": len(WSTunClientProtocol.allConn),
                 "poolSize": len(WSTunClientProtocol.pool),
                 })


@api_bp.route("/logs")
async def get_logs(request: Request):
    response = await request.respond(content_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    if request.args.get("history") == 'true':
        data = dumps(tuple(InMemoryLogHandler.logs))
        await response.send(f"event: message\ndata: {data}\n\n".encode('utf-8'))

    loop = asyncio.get_event_loop()

    async def send_log(log_item):
        try:
            await response.send(f"event: message\ndata: {dumps(log_item)}\n\n".encode('utf-8'))
        except sanic.SanicException:
            pass

    subscribe = lambda log_item: loop.create_task(send_log(log_item))
    InMemoryLogHandler.subscribe(subscribe)

    try:
        while True:
            await response.send(f"event: ping\ndata: {time.time()}\n\n".encode('utf-8'))
            await asyncio.sleep(1)
            # await response.send(f"event: message\ndata: {{\"levelname\": \"INFO\", \"message\": 1, \"asctime\": {int(time.time())}}}\n\n".encode('utf-8'))
    finally:  # CancelledError break loop
        InMemoryLogHandler.unsubscribe(subscribe)
        logging.debug('logs SSE closed')
        await response.eof()


async def setup_server(loop: asyncio.AbstractEventLoop):
    from wstan.client import WSTunClientProtocol
    global WSTunClientProtocol
    WSTunClientProtocol = WSTunClientProtocol

    global server
    # sanic_app.prepare(debug=config.debug, motd=False, verbosity=10)
    server = AsyncioServer(sanic_app, loop, None, set())
    # same logic in runners.py _serve_http_1
    await server.startup()
    await server.before_start()
    sanic_app.ack()
    sanic_app.set_serving(True)
    await server.after_start()
