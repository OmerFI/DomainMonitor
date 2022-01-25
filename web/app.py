from flask import Flask, render_template
from flask_restful import Api

from resources import Subdomains, Whois


app = Flask(__name__)
api = Api(app)


@app.get("/")
def index():
    return render_template("index.html")


api.add_resource(Whois, "/api/domains/<string:domain>/whois")
api.add_resource(Subdomains, "/api/domains/<string:domain>/subdomains")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
