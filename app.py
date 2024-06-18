from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import requests
import os

app = Flask(__name__)

app.secret_key = 'secret'


APPLICATION_ID = '4A129354-ABA1-427C-9693-F3DA203B7165'
REST_KEY = '07C00E2C-F1A5-4DA5-950F-26F7C1E7A983'
SUBDOMAIN = 'scenicicicle-us.backendless.app'

# BACKENDLESS_REST_API_BASE = f'https://api.backendless.com/{APPLICATION_ID}/{REST_KEY}'

REGISTER_URL = f'https://{SUBDOMAIN}/api/users/register'
LOGIN_URL = f'https://{SUBDOMAIN}/api/users/login'
LOGOUT_URL = f'https://{SUBDOMAIN}/api/users/logout'
RESTORE_PASSWORD_URL = f'https://{SUBDOMAIN}/api/users/restorepassword'

FOLDER_URL = f'https://{SUBDOMAIN}/api/files/users'
WEB_FOLDER = f'https://{SUBDOMAIN}/api/files/web'

@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/register', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        age = int(request.form['age'])
        gender = request.form['gender']
        country = request.form['country']
        
        if age < 5:
            return jsonify({'error': 'Registration not allowed for users under 5 years old'}), 400
        
        payload = {
            'password': password,
            'email': email,
            'name': username,
            'age': age,
            'gender': gender,
            'country': country
        }
        
        url = REGISTER_URL
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 200:
            user_data = response.json()
            
            try:
                create_user_directory(username)
                create_shared_directory(username)
            except Exception as e:
                return jsonify({'error': 'Failed to create user directories', 'details': str(e)}), 500
            
            return jsonify({'message': 'User registered successfully', 'user': user_data}), 201
        else:
            return jsonify({'error': 'Failed to register user', 'details': response.json()}), response.status_code
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        payload = {
            'login': email,
            'password': password
        }
        
        url = LOGIN_URL
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 200:
            user_data = response.json()
            session['user_id'] = user_data['objectId']
            session['user_email'] = user_data['email']
            session['user_name'] = user_data['name']
            session['user_age'] = user_data['age']
            session['user_gender'] = user_data['gender']
            session['user_country'] = user_data['country']
            session['user_token'] = user_data['user-token']
            
            return jsonify({
                'message': 'Login successful',
                'user_id': user_data['objectId'],
                'user_email': user_data['email'],
                'user_name': user_data['name'],
                'user_age': user_data['age'],
                'user_gender': user_data['gender'],
                'user_country': user_data['country'],
                'user_token': user_data['user-token']
            }), 200
        else:
            return jsonify({'error': 'Failed to login', 'details': response.json()}), response.status_code
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_email', None)
    session.pop('user_name', None)
    session.pop('user_age', None)
    session.pop('user_gender', None)
    session.pop('user_country', None)
    
    return render_template('logout.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session and 'user_token' in session:
        return render_template('dashboard.html')
    else:
        return redirect(url_for('login'))


@app.route('/restore_password', methods=['GET', 'POST'])
def restore_password():
    if request.method == 'POST':
        email = request.form['email']
        
        url = f'{RESTORE_PASSWORD_URL}/{email}'
        headers = {'Content-Type': 'application/json'}
        response = requests.get(url, headers=headers)  
        
        if response.status_code == 200:
            return jsonify({'message': 'Password recovery email sent successfully.', 'response': response.json()}), 200
        else:
            return jsonify({'error': 'Failed to send password recovery email.', 'details': response.json()}), response.status_code
    
    # Render the restore password form (GET request)
    return render_template('restore_password.html')


@app.route('/user_directory')
def user_directory():
    if 'user_id' in session:
        username = session['user_name']

        if 'user_token' not in session:
            return jsonify({'error': 'User token missing. Please login again.'}), 401
        
        url = f'{FOLDER_URL}/{username}/'
        headers = {
            'Content-Type': 'application/json',
            'user-token': session['user_token']
        }
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                directory_contents = response.json()
                # if request.headers.get('Content-Type') == 'application/json':
                #     return jsonify(directory_contents)
                # else:
                return render_template('user_directory.html', directory_contents=directory_contents)
            else:
                return jsonify({'error': f'Failed to fetch user directory contents. Status code: {response.status_code}', 'details': response.json()}), response.status_code
        except requests.exceptions.RequestException as e:
            return jsonify({'error': 'Failed to connect to Backendless', 'details': str(e)}), 500
    else:
        return redirect(url_for('login'))

@app.route('/create_folder/<foldername>', methods=['GET'])
def create_folder(foldername):
    if 'user_id' in session:
        username = session['user_name']
        if 'user_token' not in session:
            return jsonify({'error': 'User token missing. Please login again.'}), 401
        
        url = f'{FOLDER_URL}/{username}/{foldername}'
        
        headers = {
            'Content-Type': 'application/json',
            'user-token': session['user_token']
        }
        
        try:
            response = requests.post(url, headers=headers)
            if response.status_code == 200:
                return jsonify({'message': f'Folder "{foldername}" created successfully.'}), 200
            else:
                return jsonify({'error': 'Failed to create folder.', 'details': response.json()}), response.status_code
        
        except requests.exceptions.RequestException as e:
            return jsonify({'error': 'Failed to connect to Backendless', 'details': str(e)}), 500
    
    else:
        return jsonify({'error': 'User not authenticated. Please log in.'}), 401

@app.route('/delete_folder/<foldername>', methods=['GET'])
def delete_folder(foldername):
    if 'user_id' in session:
        username = session['user_name']
        
        if 'user_token' not in session:
            return jsonify({'error': 'User token missing. Please login again.'}), 401
        
        url = f'{FOLDER_URL}/{username}/{foldername}'
        
        headers = {
            'Content-Type': 'application/json',
            'user-token': session['user_token']
        }
        
        try:
            response = requests.delete(url, headers=headers)

            return jsonify({'message': f'Folder "{foldername}" deleted successfully.'}), 200
        
        except requests.exceptions.RequestException as e:
            return jsonify({'error': 'Failed to connect to Backendless', 'details': str(e)}), 500
    
    else:
        return jsonify({'error': 'User not authenticated. Please log in.'}), 401


# === File Work ===

def create_user_directory(username):
    url = f'{FOLDER_URL}/{username}/'
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.post(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Failed to create user directory {username}. Error: {response.json()}")

def create_shared_directory(username):
    url = f'{FOLDER_URL}/{username}/shared-with-me/'
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.post(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Failed to create shared directory for {username}. Error: {response.json()}")



if __name__ == '__main__':
    app.run(debug=True)
