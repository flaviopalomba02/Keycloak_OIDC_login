from flask import Flask, render_template, url_for, session, abort, redirect, request
from authlib.integrations.flask_client import OAuth
from authlib.jose import JsonWebKey
from urllib.parse import urlencode, quote_plus
import jwt, logging, time, hvac, os, base64, hashlib, requests
from dotenv import load_dotenv

# Configurazione logging
logging.basicConfig(
    level=logging.DEBUG, 
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)

# Caricamento delle variabili di ambiente dal file .env
load_dotenv()
vault_token = os.getenv("VAULT_TOKEN")

# Configurazione Vault
client = hvac.Client(
    url='https://localhost:8200',
    token=vault_token,
    verify=False  # per accettare certificato self-signed
)

# Recupero dei segreti da Vault
secret_response = client.secrets.kv.v2.read_secret_version(
    path='system_security_app', mount_point='secret'
)

secrets = secret_response['data']['data']
client_secret = secrets['client_secret']
flask_secret = secrets['flask_secret']

app_conf = {
    "OAUTH2_CLIENT_ID": "ss_web_app",
    "OAUTH2_CLIENT_SECRET": client_secret,
    "OAUTH2_ISSUER": "https://localhost:8443/realms/system-security",
    "FLASK_SECRET": flask_secret,
    "FLASK_PORT": 3000
}

app.secret_key = app_conf.get("FLASK_SECRET")

oauth = OAuth(app)
oauth.register(
    "myApp",
    client_id=app_conf.get("OAUTH2_CLIENT_ID"),
    client_secret=app_conf.get("OAUTH2_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
        "verify": False  # per accettare certificato self-signed
    },
    server_metadata_url=f'{app_conf.get("OAUTH2_ISSUER")}/.well-known/openid-configuration'
)

def generate_code_verifier():
    return base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode('utf-8')

def generate_code_challenge(verifier):
    challenge = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(challenge).rstrip(b'=').decode('utf-8')

@app.route("/login")
def login():
    if "user" in session:
        logging.warning("Tentativo di login mentre l'utente è già autenticato.")
        abort(404)
    logging.info("Inizio procedura di login.")
    code_verifier = generate_code_verifier()
    session['code_verifier'] = code_verifier
    code_challenge = generate_code_challenge(code_verifier)
    return oauth.myApp.authorize_redirect(
        redirect_uri=url_for("callback", _external=True),
        code_challenge=code_challenge,
        code_challenge_method='S256'
    )

@app.route("/callback")
def callback():
    code_verifier = session.pop('code_verifier', None)
    if not code_verifier:
        logging.error("Mancante PKCE verifier nella callback.")
        abort(400, "Missing PKCE verifier")
    try:
        token = oauth.myApp.authorize_access_token(code_verifier=code_verifier)
        session["user"] = token
        logging.info("Login completato con successo per l'utente.")
        return redirect(url_for("home"))
    except Exception as e:
        logging.error(f"Errore durante la gestione della callback: {e}")
        abort(400)

@app.route("/logout")
def logout():
    id_token = session['user']["id_token"]
    session.clear()
    logging.info("Logout completato.")
    return redirect(
        app_conf.get("OAUTH2_ISSUER")
        + "/protocol/openid-connect/logout?"
        + urlencode(
            {
                "post_logout_redirect_uri": url_for("loggedout", _external=True),
                "id_token_hint": id_token
            },
            quote_via=quote_plus
        )
    )

@app.route("/loggedout")
def loggedout():
    if "user" in session:
        abort(404)
    logging.info("Utente reindirizzato alla pagina di logged out.")
    return redirect(url_for("home"))

@app.route("/")
def home():
    logging.debug("Accesso alla home page.")
    return render_template("home.html", session=session.get("user"))

@app.route("/loggedin")
def loggedin():
    logging.info("Utente autenticato, accesso alla pagina di logged in.")
    return render_template("loggedin.html")

@app.route('/admin-page')
def admin_page():
    roles = get_user_roles()
    logging.debug(f"Roles recuperati: {roles}")
    if 'AdminRole' in roles:
        logging.info("Accesso consentito alla pagina admin.")
        return render_template('admin-page.html')
    else:
        logging.warning("Tentativo di accesso non autorizzato alla pagina admin.")
        return 'Access Denied: you are not an admin.\n <p><a href="/logout">Logout</a></p>', 403

@app.before_request
def login_required():
    allowed_routes = ['loggedout', 'login', 'callback', 'home']
    if request.endpoint not in allowed_routes:
        if not is_authenticated():
            logging.warning(f"Tentativo di accesso non autenticato a: {request.endpoint}")
            return redirect(url_for('login'))

def is_authenticated():
    if "user" not in session:
        logging.debug("Utente non autenticato.")
        return False
    token = session["user"]
    access_token = token.get("access_token")

    try:
        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
        if "exp" in decoded_token and decoded_token["exp"] < int(time.time()):
            token = refresh_access_token()
            return True if token else False
    except Exception as e:
        logging.error(f"Errore durante la decodifica del token: {e}")
        return False

    logging.debug("Utente autenticato con successo.")
    return True


'''
def get_public_key():
    # URL dell'endpoint dei certificati di Keycloak
    certs_url = "https://localhost:8443/auth/realms/system-security/protocol/openid-connect/certs"
    response = requests.get(certs_url)
    jwks = response.json()
    # Vado ad estrarre la chiave pubblica dal JSON Web Key Set (JWKS)
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks['keys'][0])
    return public_key

def is_authenticated():
    if "user" not in session:
        logging.debug("Utente non autenticato.")
        return False
    token = session["user"]
    access_token = token.get("access_token")

    try:
        public_key = get_public_key()
        decoded_token = jwt.decode(access_token, key=public_key, algorithms=["RS256"])
        if "exp" in decoded_token and decoded_token["exp"] < int(time.time()):
            token = refresh_access_token()
            return True if token else False
    except jwt.ExpiredSignatureError:
        logging.error("Il token è scaduto.")
        return False
    except jwt.InvalidTokenError as e:
        logging.error(f"Token non valido: {e}")
        return False
'''

def refresh_access_token():
    try:
        token = session["user"]
        refresh_token = token.get("refresh_token")
        if not refresh_token:
            return None

        new_token = oauth.myApp.fetch_access_token(grant_type='refresh_token', refresh_token=refresh_token)
        session["user"] = new_token
        logging.info("Access token rinnovato con successo.")
        return new_token
    except Exception as e:
        logging.error(f"Errore durante il rinnovo del token: {e}")
        session.clear()
        return None

def get_user_roles():
    if "user" not in session:
        return []
    try:
        access_token = session["user"]["access_token"]
        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
        client_roles = decoded_token.get('realm_access', {}).get('roles', [])
        logging.debug(f"Ruoli utente: {client_roles}")
        return client_roles
    except Exception as e:
        logging.error(f"Errore durante la decodifica dei ruoli: {e}")
        return []


if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'), host="localhost", port=3000, debug=True)
