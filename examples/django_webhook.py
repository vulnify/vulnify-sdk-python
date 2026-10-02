"""Django + Vulnify webhooks.

The vulnify package itself has no framework dependency.
Return 400 for a bad signature so Vulnify stops retrying. 408, 429, and 5xx are retried.
"""

import os

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from vulnify import WebhookVerificationError, construct_webhook_from_request

SECRET = os.environ["VULNIFY_WEBHOOK_SECRET"]


@csrf_exempt
def vulnify_webhook(request):
    # request.body is the raw body.
    try:
        event = construct_webhook_from_request(SECRET, request.headers, request.body)
    except WebhookVerificationError:
        return HttpResponse(status=400)
    if event.type == "TEST":
        return HttpResponse(status=204)
    # event.id is the delivery id. Dedupe retries on it.
    return HttpResponse(status=204)
