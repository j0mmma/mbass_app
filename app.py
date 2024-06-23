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

USERS_URL = f'https://{SUBDOMAIN}/api/users'
USERS_TABLE_URL = f'https://{SUBDOMAIN}/api/data/Users'


FOLDER_URL = f'https://{SUBDOMAIN}/api/files/users'
WEB_FOLDER = f'https://{SUBDOMAIN}/api/files/web'


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


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
        
        profile_picture_url = ''

        payload = {
            'password': password,
            'email': email,
            'name': username,
            'age': age,
            'gender': gender,
            'country': country,
            'profile_picture_url': profile_picture_url
        }
        
        url = REGISTER_URL
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 200:
            user_data = response.json()
            
            try:
                create_user_directory(email)
                create_shared_directory(email)
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
            session['profile_picture_url'] = user_data['profile_picture_url']
            
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
    
    return render_template('restore_password.html')


@app.route('/user_directory')
def user_directory():
    if 'user_id' in session:
        email = session['user_email']

        if 'user_token' not in session:
            return jsonify({'error': 'User token missing. Please login again.'}), 401
        
        url = f'{FOLDER_URL}/{email}/'
        headers = {
            'Content-Type': 'application/json',
            'user-token': session['user_token']
        }
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                directory_contents = response.json()
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
        email = session['user_email']
        if 'user_token' not in session:
            return jsonify({'error': 'User token missing. Please login again.'}), 401
        
        url = f'{FOLDER_URL}/{email}/{foldername}'
        
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
        email = session['user_email']
        
        if 'user_token' not in session:
            return jsonify({'error': 'User token missing. Please login again.'}), 401
        
        url = f'{FOLDER_URL}/{email}/{foldername}'
        
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


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        email = session['user_email']

        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file.filename == '':
                flash('No selected file', 'danger')
                return redirect(request.url)

            if file and allowed_file(file.filename):
                filename = file.filename

                backendless_filepath = f'{FOLDER_URL}/{email}/{filename}?overwrite=true'

                headers = {
                    'user-token': session['user_token']
                }
                files = {
                    'file': (filename, file.stream, file.mimetype)
                }
                response = requests.post(backendless_filepath, headers=headers, files=files)

                if response.status_code == 200:
                    profile_picture_url = backendless_filepath.replace('\\', '/')
                    user_id = session['user_id']
                    update_profile_picture_url(user_id, profile_picture_url)

                    update_backendless_user(user_id, {
                        'profile_picture_url': profile_picture_url
                    })

                    update_session_data(user_id)

                    flash('Profile picture updated successfully', 'success')
                else:
                    error_message = f'Failed to upload file to Backendless. Error: {response.text}'
                    flash(error_message, 'danger')

        return redirect(url_for('profile'))

    return render_template('profile.html', user=session)


def update_backendless_user(user_id, data):
    url = f'{USERS_URL}/{user_id}'
    headers = {
        'Content-Type': 'application/json',
        'user-token': session['user_token']
    }
    try:
        response = requests.put(url, headers=headers, json=data)
        response.raise_for_status()  # Raise exception for non-2xx status codes
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f'Failed to update user in Backendless: {str(e)}')


def update_session_data(user_id):
    user = {
        'email': session['user_email'],
        'name': session['user_name'],
        'age': session['user_age'],
        'gender': session['user_gender'],
        'country': session['user_country'],
        'profile_picture_url': session['profile_picture_url']
    }
    session['user'] = user


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def update_profile_picture_url(user_id, profile_picture_url):
    payload = {
        'profile_picture_url': profile_picture_url
    }
    url = f'{USERS_URL}/{user_id}'
    headers = {
        'Content-Type': 'application/json',
        'user-token': session['user_token']
    }
    response = requests.put(url, headers=headers, json=payload)

    if response.status_code != 200:
        error_message = f'Failed to update profile picture URL in the database. Error: {response.text}'
        flash(error_message, 'danger')


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session and 'user_token' in session:
        profile_picture_url = session.get('profile_picture_url', None)
        print(profile_picture_url)
        return render_template('dashboard.html', profile_picture_url=profile_picture_url)
    else:
        return redirect(url_for('login'))

@app.route('/users', methods=['GET'])
def users():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    headers = {'user-token': session['user_token']}

    response = requests.get(USERS_TABLE_URL, headers=headers)

    if response.status_code == 200:
        all_users = response.json()
        users = [user for user in all_users if user['objectId'] != current_user_id]

        current_user_response = requests.get(f'{USERS_TABLE_URL}/{current_user_id}', headers=headers)
        
        if current_user_response.status_code == 200:
            current_user = current_user_response.json()
            friends = current_user.get('friends', []) or []
        else:
            friends = []

        return render_template('users.html', users=users, friends=friends)
    else:
        flash('Failed to fetch users from Backendless', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/add_friend/<user_email>', methods=['GET'])
def add_friend(user_email):
    current_user_id = session['user_id']
    user_token = session['user_token']

    response = requests.get(f'{USERS_TABLE_URL}/{current_user_id}', headers={'user-token': user_token})
    if response.status_code == 200:
        current_user = response.json()
        friends = current_user.get('friends', [])
        if user_email not in friends:
            friends.append(user_email)
            update_user_data(current_user_id, {'friends': friends}, user_token)
            flash('Friend added successfully', 'success')
        else:
            flash('User is already your friend', 'info')
    else:
        flash('Failed to add friend', 'danger')

    return redirect(url_for('users'))

@app.route('/remove_friend/<user_email>', methods=['GET'])
def remove_friend(user_email):
    current_user_id = session['user_id']
    user_token = session['user_token']

    response = requests.get(f'{USERS_TABLE_URL}/{current_user_id}', headers={'user-token': user_token})
    if response.status_code == 200:
        current_user = response.json()
        friends = current_user.get('friends', [])
        if user_email in friends:
            friends.remove(user_email)
            update_user_data(current_user_id, {'friends': friends}, user_token)
            flash('Friend removed successfully', 'success')
        else:
            flash('User is not in your friends list', 'info')
    else:
        flash('Failed to remove friend', 'danger')

    return redirect(url_for('users'))

def update_user_data(user_id, data, user_token):
    headers = {
        'Content-Type': 'application/json',
        'user-token': user_token
    }
    response = requests.put(f'{USERS_TABLE_URL}/{user_id}', headers=headers, json=data)
    return response


# === File Work ===

def create_user_directory(email):
    url = f'{FOLDER_URL}/{email}/'
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.post(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Failed to create user directory {email}. Error: {response.json()}")


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
