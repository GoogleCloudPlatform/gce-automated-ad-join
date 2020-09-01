import main
from flask import Flask, request

app = Flask(__name__)
app.debug=False

@app.route("/", methods=['GET', 'POST'])
@app.route("/cleanup", methods=['GET', 'POST'])
def index():
    return main.register_computer(request)

if __name__ == "__main__":
    app.run()
