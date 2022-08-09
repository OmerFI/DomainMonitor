from flask import Flask, render_template
from flask_restful import Api

from resources import Subdomains, Whois

import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

sentry_sdk.init(
    dsn="https://8e6b6d0c6cc441d5970d38c5e52af2ad@o1306235.ingest.sentry.io/6636657",
    integrations=[
        FlaskIntegration(),
    ],

    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    # We recommend adjusting this value in production.
    traces_sample_rate=1.0
)

app = Flask(__name__)
api = Api(app)


@app.get("/")
def index():
    return render_template("index.html")


api.add_resource(Whois, "/api/domains/<string:domain>/whois")
api.add_resource(Subdomains, "/api/domains/<string:domain>/subdomains")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
