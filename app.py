from flask import Flask, request, jsonify, redirect, url_for
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'

# Dummy database of users
users = {"testuser": "password123"}

def generate_token(username):
    # Generate JWT token with a short expiration time (for testing)
    token = jwt.encode({
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    return token

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        service_url = request.args.get('service')
        
        if username in users and users[username] == password:
            token = generate_token(username)
            # Redirect back to the service with the token
            return redirect(f'{service_url}?token={token}')
        return "Invalid credentials", 401
    return '''
    <form method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/verify-token', methods=['POST'])
def verify_token():
    token = request.form['token']
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return jsonify({"valid": True, "username": data['username']})
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "message": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "message": "Invalid token"}), 401

if __name__ == '__main__':
    app.run(debug=True)
