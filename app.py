# TODO: Create the app especially input text box that the user can enter the url #complete
# TODO: Ensure the url is visible to the system #url is visible on terminal #complete
# TODO: Import dataset used to initially train #complete
# TODO: Separate into parts and add features #complete
# TODO: Train model #code completed
# TODO: Show accuracy and prediction on test values #code completed
# TODO: Apply these same steps to the URL entered #code completed
# TODO: If url prediction is 0, show legitimate else show warn that url is phishing #code completed
# TODO: Show values on the website #code completed

from flask import Flask, render_template, request
import detection

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index_page():
    request_type_str = request.method
    if request_type_str == 'GET':
        return render_template("index.html")  # returns to the html page
    else:
        newURL = request.form['url']
        print(newURL)

        if not newURL:
            result = "No value has been entered"
            print(result)
        else:
            result = detection.getResult(newURL)
            print(result)
        return render_template("index.html", classify=result)  # returns to the html page and provide the solution


if __name__ == '__main__':
    app.run(debug=True)
