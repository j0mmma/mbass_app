from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import requests

app = Flask(__name__)

# Set a secret key for your application
app.secret_key = 'secret'


APPLICATION_ID = '4A129354-ABA1-427C-9693-F3DA203B7165'
REST_KEY = '07C00E2C-F1A5-4DA5-950F-26F7C1E7A983'
SUBDOMAIN = 'scenicicicle-us.backendless.app'

BACKENDLESS_REST_API_BASE = f'https://api.backendless.com/{APPLICATION_ID}/{REST_KEY}'


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        # Extract data from the form
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        age = int(request.form['age'])
        gender = request.form['gender']
        country = request.form['country']
        
        # Validate age
        if age < 5:
            return jsonify({'error': 'Registration not allowed for users under 5 years old'}), 400
        
        # Prepare payload for Backendless registration
        payload = {
            'password': password,
            'email': email,
            'name': username,
            'age': age,
            'gender': gender,
            'country': country
        }
        
        # Send POST request to Backendless for user registration
        url = f'{BACKENDLESS_REST_API_BASE}/users/register'
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, json=payload)
        
        # Handle Backendless response
        if response.status_code == 200:
            return jsonify({'message': 'User registered successfully', 'user': response.json()}), 201
        else:
            return jsonify({'error': 'Failed to register user', 'details': response.json()}), response.status_code
    
    # Render the registration form (GET request)
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Prepare payload for Backendless login using email
        payload = {
            'login': email,  # Use email for login
            'password': password
        }
        
        # Send POST request to Backendless for user login
        url = f'{BACKENDLESS_REST_API_BASE}/users/login'
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, json=payload)
        
        # Handle Backendless response
        if response.status_code == 200:
            # Successful login, store user session data
            user_data = response.json()
            session['user_id'] = user_data['objectId']
            session['user_email'] = user_data['email']
            session['user_name'] = user_data['name']
            session['user_age'] = user_data['age']
            session['user_gender'] = user_data['gender']
            session['user_country'] = user_data['country']
            
            # Redirect to dashboard
            return redirect(url_for('dashboard'))
        else:
            return jsonify({'error': 'Failed to login', 'details': response.json()}), response.status_code
    
    # Render the login form (GET request)
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session and 'user_token' in session:
        return render_template('dashboard.html')
    else:
        return redirect(url_for('login'))

@app.route('/password-recovery', methods=['GET', 'POST'])
def password_recovery():
    if request.method == 'POST':
        email = request.form['email']
        
        # Prepare payload for Backendless password recovery request
        payload = {
            'email': email
        }
        
        # Send POST request to Backendless for password recovery
        url = f'{BACKENDLESS_REST_API_BASE}/users/restorepassword'
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, json=payload)
        
        # Handle Backendless response for password recovery
        if response.status_code == 200:
            # Password recovery email sent successfully
            return render_template('password_recovery_success.html')
        else:
            # Failed to send password recovery email
            return jsonify({'error': 'Failed to send password recovery email', 'details': response.json()}), response.status_code
    
    # Render the password recovery form (GET request)
    return render_template('password_recovery.html')

@app.route('/logout')
def logout():
    # Clear session variables to log out the user
    session.pop('user_id', None)
    session.pop('user_token', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)