from flask import Flask, request, jsonify, session
from file import prepare_and_upload_file
from auth import get_access_token, login, authorized, logout

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def home():
    if 'access_token' in session:
        return 'You are logged in! <a href="/upload">Upload a File</a>'
    return 'Please <a href="/login">login</a> first.'

@app.route('/login')
def login_page():
    return login()

@app.route('/getAToken')
def get_token():
    return authorized()

@app.route('/logout')
def logout_page():
    return logout()

@app.route('/upload', methods=['GET', 'POST'])
def upload_page():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    access_token = get_access_token()

    if request.method == 'POST':
        file = request.files['file']
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)

        # Prepare and upload the file to OneDrive
        prepare_and_upload_file(access_token, file_path)

        return jsonify({"message": "File uploaded to OneDrive successfully!"})

    return '''
    <form method="POST" enctype="multipart/form-data">
      <input type="file" name="file">
      <input type="submit" value="Upload">
    </form>
    '''

if __name__ == '__main__':
    app.run(debug=True)
