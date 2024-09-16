from flask import Flask, request, redirect, jsonify, make_response, url_for
import jwt
import datetime
from flask_cors import CORS
from werkzeug.security import check_password_hash
import os

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

# Main login route (used by service to redirect users here for login)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get user credentials from request form
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check user and password
        if username in users and check_password_hash(users[username]['password'], password):
            # Generate JWT token if authenticated
            token = jwt.encode({
                'username': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=TOKEN_EXPIRATION_TIME)
            }, SECRET_KEY, algorithm='HS256')

            # Redirect user back to service with the token
            service_redirect = request.args.get('service')  # e.g., noctiservice1.vercel.app
            response = make_response(redirect(f'{service_redirect}?token={token}'))

            # Set auth_token cookie on centralserver domain (can also use other session mechanisms)
            response.set_cookie('auth_token', token, httponly=True, secure=True, domain='.onrender.com')

            return response
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
