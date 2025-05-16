# 🔐 easySSP Authentication Python Client

This module provides a simple and secure way to authenticate with the easySSP API using JWT tokens. It performs the
initial login with username and password, requests the access and refresh tokens from the authentication endpoint,
and renews the access token when it expires using the refresh token.

---

## 🚀 Features

- 🔑 Retrieves JSON Web Tokens (JWTs) based on user credentials
- 🗂️ Securely manages credentials and access/refresh tokens
- ♻️ Automatically renews expired access tokens

## 🔐 Access Requirements

- Requires an easySSP **Pro** or **Process Edition** account

---

## 🛠️ How It Works

1. **Create the `AuthClient` instance**  

```python
from easyssp_auth.authentication import AuthClient, AuthError

try: 
    auth_client = AuthClient("your_easyssp_username", "your_easyssp_password", "your-client-id")
except AuthError as ex:
    print(ex)
```

2. **Retrieve the access token**

```python
access_token = auth_client.get_access_token()
```

3. **Authenticate your requests**  
You can use the retrieved access token in the `Authorization` header of your requests to authenticate with the easySSP API.

---

## 📦 Installation

```bash
pip install easyssp-auth-client
```

Or clone and install from source:

```bash
git clone https://github.com/exxcellent/easyssp-auth-client-python.git
cd easyssp-auth-client-python
pip install -e .
```

---

## 📁 Project Structure

```bash
easyssp_auth/
├── __init__.py
├── authentication.py      # Core logic for obtaining and storing the token
```

## 🛠️ Technical Requirements

- Python 3.11+

Install dependencies using uv:

```bash
pip install uv
uv sync
```

## 🤝 Contributing

This module is maintained as part of the easySSP ecosystem. If you find issues or want to suggest improvements, please
open an issue or submit a pull request.

## 📄 License

This project is licensed under the MIT License.