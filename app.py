from flask import Flask, request, redirect, jsonify, make_response, url_for
import jwt
import datetime
from flask_cors import CORS
from werkzeug.security import check_password_hash
import os
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests from service domains

# Config
SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secure-secret-key'
TOKEN_EXPIRATION_TIME = 3600  # 1 hour

# Simulate user database (replace with your actual database)
users = {
    'testuser': {
        'password': 'hashed-password',  # Use hashed passwords
        'name': 'Test User'
    }
}

# Routes

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users and users[username]['password'] == password:
            token = jwt.encode({
                'username': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=TOKEN_EXPIRATION_TIME)
            }, SECRET_KEY, algorithm='HS256')

            service_redirect = request.args.get('service')
            if not service_redirect:
                return "No service redirect URL provided", 400

            # Log to verify the token and service_redirect
            print(f"Generated token: {token}")
            print(f"Service redirect URL: {service_redirect}")

            # Parse the URL
            parsed_url = urlparse(service_redirect)
            
            # Extract the domain
            domain = parsed_url.netloc 
            return redirect(f'https://{domain}/login_redirect?token={token}&service={service_redirect}')
        return "Invalid credentials", 401

    return '''
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''



# Verify token route (services will hit this to verify if token is valid)
@app.route('/verify-token', methods=['POST'])
def verify_token():
    token = request.form.get('token')
    if not token:
        return jsonify({"valid": False}), 400

    try:
        # Decode the token
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({"valid": True, "username": decoded['username']}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "Invalid token"}), 401


# Route for services to validate tokens using cookies
@app.route('/validate-session', methods=['GET'])
def validate_session():
    token = request.cookies.get('auth_token')
    if not token:
        return jsonify({"valid": False}), 401

    try:
        # Decode the token
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({"valid": True, "username": decoded['username']}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "Invalid token"}), 401


if __name__ == '__main__':
    app.run(debug=True)
