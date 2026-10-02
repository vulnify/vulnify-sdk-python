"""FastAPI + Vulnify webhooks.

pip install fastapi
The vulnify package itself has no framework dependency.
"""

import os

from fastapi import FastAPI, Request, Response

from vulnify import WebhookVerificationError, construct_webhook_from_request

app = FastAPI()
SECRET = os.environ["VULNIFY_WEBHOOK_SECRET"]


@app.post("/webhooks/vulnify")
async def vulnify_webhook(request: Request):
    # await request.body() is the raw body. Do not pass a parsed dict.
    try:
        event = construct_webhook_from_request(SECRET, request.headers, await request.body())
    except WebhookVerificationError:
        return Response(status_code=400)
    if event.type == "ANOMALY":
        print(event.data.message)
    return Response(status_code=204)
