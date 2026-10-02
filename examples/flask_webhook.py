"""Flask + Vulnify webhooks.

pip install flask
The vulnify package itself has no framework dependency.
"""

import os

from flask import Flask, request

from vulnify import WebhookVerificationError, construct_webhook_from_request

app = Flask(__name__)
SECRET = os.environ["VULNIFY_WEBHOOK_SECRET"]


@app.post("/webhooks/vulnify")
def vulnify_webhook():
    # request.get_data() is the raw body. Do not pass request.json: re-serialized JSON breaks the signature.
    try:
        event = construct_webhook_from_request(SECRET, request.headers, request.get_data())
    except WebhookVerificationError:
        return "", 400
    # event.id is the delivery id. Dedupe retries on it. Obey event.data.final_decision for a decision.
    if event.type == "BLOCK":
        app.logger.info("blocked %s", event.event_id)
    return "", 204
