import hashlib
import itertools
import math
import secrets
import string
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import jwt
import streamlit as st
from streamlit.delta_generator import DeltaGenerator

# Constants
DEFAULT_SECRET_LENGTH = 32
ALGORITHM = "HS256"
ALLOWED_CHARS = string.ascii_letters + string.digits + string.punctuation
MIN_PASSWORD_LENGTH = 8
MAX_TOKEN_AGE = 30  # minutes


class User:
    def __init__(self, username: str, password_hash: str):
        self.username = username
        self.password_hash = password_hash
        self.failed_attempts = 0
        self.locked_until: Optional[datetime] = None


# Assuming total_combinations is a very large number
def to_exponential_notation(number):
    exponent = math.floor(math.log10(number))
    mantissa = number / 10**exponent
    return f"{mantissa:.2f}e{exponent}"


def init_session_state():
    """Initialize session state variables with improved security defaults."""
    defaults = {
        "logged_in": False,
        "current_user": None,
        "users": {},
        "brute_force_progress": 0,
        "found_secret": "",
        "jwt_secret": secrets.token_urlsafe(DEFAULT_SECRET_LENGTH),
        "brute_force_time": 0,
        "attack_mode": "dictionary",  # or "brute_force"
        "token_blacklist": set(),
        "last_activity": datetime.utcnow(),
    }

    for key, default_value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default_value


def hash_password(password: str) -> str:
    """Hash password using SHA-256 with a random salt."""
    salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256((password + salt).encode())
    return f"{salt}${hash_obj.hexdigest()}"


def verify_password(password: str, hash_string: str) -> bool:
    """Verify a password against its hash."""
    salt, hash_value = hash_string.split("$")
    hash_obj = hashlib.sha256((password + salt).encode())
    return hash_obj.hexdigest() == hash_value


def create_token(username: str, custom_claims: Dict[str, Any] = None) -> str:
    """Create a JWT token."""
    expiration = datetime.utcnow() + timedelta(minutes=MAX_TOKEN_AGE)
    jti = secrets.token_urlsafe(16)  # unique token identifier

    payload = {
        "sub": username,
        "exp": expiration,
        "iat": datetime.utcnow(),
        "jti": jti,
        **(custom_claims or {}),
    }

    token = jwt.encode(payload, st.session_state.jwt_secret, algorithm=ALGORITHM)
    return token


def verify_token(token: str) -> bool:
    """Verify a JWT token with additional security checks."""
    try:
        payload = jwt.decode(token, st.session_state.jwt_secret, algorithms=[ALGORITHM])

        # Check if token is blacklisted
        if payload.get("jti") in st.session_state.token_blacklist:
            return False

        # Check token age
        iat = datetime.fromtimestamp(payload.get("iat"))
        if datetime.utcnow() - iat > timedelta(minutes=MAX_TOKEN_AGE):
            return False

        return True
    except jwt.InvalidTokenError:
        return False


def show_token_analysis(token: str, col: DeltaGenerator):
    """Display detailed token analysis with security insights."""
    try:
        decoded_header = jwt.get_unverified_header(token)
        decoded_payload = jwt.decode(token, options={"verify_signature": False})
        header, payload, signature = token.split(".")

        col.subheader("🔍 Token Analysis")

        # Header Analysis
        col.markdown("**Header Analysis**")
        col.json(decoded_header)
        if decoded_header.get("alg") == "none":
            col.warning(
                "⚠️ 'none' algorithm detected - vulnerable to algorithm stripping attacks!"
            )

        # Payload Analysis
        col.markdown("**Payload Analysis**")
        col.json(decoded_payload)

        exp = decoded_payload.get("exp")
        if exp:
            exp_date = datetime.fromtimestamp(exp)
            time_left = exp_date - datetime.utcnow()
            col.info(f"Token expires in: {time_left.total_seconds():.0f} seconds")

        # Signature Analysis
        col.markdown("**Signature**")
        col.code(signature)

        # Security Recommendations
        col.markdown("**Security Insights**")
        security_checks = [
            ("✓ Using HS256 algorithm", decoded_header.get("alg") == "HS256"),
            ("✓ Expiration time set", "exp" in decoded_payload),
            ("✓ Issued at time present", "iat" in decoded_payload),
            ("✓ Contains token ID (jti)", "jti" in decoded_payload),
        ]

        for check, passed in security_checks:
            if passed:
                col.success(check)
            else:
                col.error(f"❌ Missing: {check}")

    except Exception as e:
        col.error(f"Error analyzing token: {str(e)}")


def simulate_dictionary_attack(progress_bar: DeltaGenerator, status: DeltaGenerator):
    """Simulate a dictionary-based attack using common passwords."""
    common_passwords = [
        "password123",
        "admin123",
        "letmein",
        "welcome1",
        "123456",
        "qwerty",
        "dragon",
        "baseball",
    ]

    total = len(common_passwords)
    for i, password in enumerate(common_passwords):
        progress = (i + 1) / total * 100
        progress_bar.progress(int(progress))
        status.text(f"Trying common password: {password}")
        time.sleep(0.5)  # Simulate processing time

    status.error("Dictionary attack failed - no common passwords matched")


def brute_force_attack():
    """
    Brute force attack simulation with progress tracking
    and performance metrics.
    """
    target_secret = st.session_state.jwt_secret
    secret_length = len(target_secret)
    total_combinations = len(ALLOWED_CHARS) ** secret_length

    st.info(
        f"""
        - Starting brute force attack simulation
        - Secret length: {secret_length} characters
        - Total combinations to try: {total_combinations:,}
        """
    )

    # Setup progress tracking
    combinations_tried = 0
    start_time = time.time()

    # Create UI elements
    progress_bar = st.progress(0)
    status_text = st.empty()

    # Create metrics columns
    metrics_col1, metrics_col2, metrics_col3 = st.columns(3)
    attempts_metric = metrics_col1.empty()
    speed_metric = metrics_col2.empty()
    etc_metric = metrics_col3.empty()  # Estimated time to completion

    chunk_size = 1000  # Update UI every chunk_size attempts
    current_chunk = []

    # Iterate over possible combinations
    for guess_tuple in itertools.product(ALLOWED_CHARS, repeat=secret_length):
        guess_secret = "".join(guess_tuple)
        combinations_tried += 1
        current_chunk.append(guess_secret)

        # Update UI periodically
        if len(current_chunk) >= chunk_size or guess_secret == target_secret:
            # Calculate progress and metrics
            progress = (combinations_tried / total_combinations) * 100
            elapsed_time = time.time() - start_time
            attempts_per_second = combinations_tried / elapsed_time

            # Estimate time remaining
            if attempts_per_second > 0:
                remaining_combinations = total_combinations - combinations_tried
                etc = remaining_combinations / attempts_per_second
                etc_str = f"{etc:.1f}s" if etc < 60 else f"{etc/60:.1f}m"
            else:
                etc_str = "∞"

            # Update UI elements
            progress_bar.progress(min(int(progress), 100))
            attempts_metric.metric("Attempts", f"{combinations_tried:,}")
            speed_metric.metric("Attempts/sec", f"{attempts_per_second:,.0f}")
            etc_metric.metric("Est. Time Remaining", etc_str)
            status_text.text(f"Current guess: {guess_secret}")

            # Clear chunk
            current_chunk = []

        # Check if secret is found
        if guess_secret == target_secret:
            total_time = time.time() - start_time
            st.session_state.found_secret = guess_secret
            st.session_state.brute_force_time = total_time

            status_text.success(
                f"""
                - 🎉 Secret found: '{guess_secret}'
                - Time taken: {total_time:.2f} seconds
                - Attempts: {combinations_tried:,}
                - Speed: {combinations_tried/total_time:,.0f} attempts/second
                """
            )

            # Show security insight
            if total_time < 1:
                st.error(
                    "⚠️ This secret was cracked very quickly! Use a longer secret in production."
                )
            elif total_time < 60:
                st.warning(
                    "⚡ This secret was cracked in under a minute. Consider using a longer secret."
                )
            else:
                st.info(
                    "🔒 Even this short demo took significant time to crack. A longer secret would be even more secure!"
                )

            break

    st.session_state.brute_force_progress = 100


def main():
    st.set_page_config(
        page_title="JWT Security Demo", layout="wide", initial_sidebar_state="expanded"
    )

    init_session_state()

    st.title("🔐 JWT Security Demo")
    st.markdown(
        """
    This demo illustrates JWT security best practices and common attack vectors.
    Features include:
    - Password hashing with salt
    - Token blacklisting
    - Session management
    - Attack simulations (dictionary & brute force)
    - Detailed token analysis
    """
    )

    # Sidebar for Configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        if not st.session_state.logged_in:
            st.session_state.jwt_secret = st.text_input(
                "JWT Secret",
                value=st.session_state.jwt_secret,
                help="In production, use a strong random secret and keep it secure!",
            )

        st.markdown("---")
        st.markdown("### 🛡️ Security Settings")
        MAX_TOKEN_AGE = st.slider(
            "Token Expiration (minutes)", min_value=1, max_value=60, value=30
        )

    # Main content in two columns
    col1, col2 = st.columns(2)

    # Legitimate User Side
    with col1:
        st.header("👤 Legitimate User")

        if not st.session_state.logged_in:
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="e.g., alice")
                password = st.text_input(
                    "Password", type="password", placeholder="Minimum 8 characters"
                )

                submitted = st.form_submit_button("Login")
                if submitted:
                    if len(password) < MIN_PASSWORD_LENGTH:
                        st.error(
                            f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
                        )
                    else:
                        user = st.session_state.users.get(username)
                        if not user:
                            # New user registration
                            password_hash = hash_password(password)
                            st.session_state.users[username] = User(
                                username, password_hash
                            )
                            st.success("New user registered!")

                        user = st.session_state.users[username]
                        if user.locked_until and user.locked_until > datetime.utcnow():
                            st.error(
                                f"Account locked. Try again in {(user.locked_until - datetime.utcnow()).seconds} seconds"
                            )
                        elif verify_password(password, user.password_hash):
                            token = create_token(username)
                            st.session_state.logged_in = True
                            st.session_state.current_user = username
                            st.session_state.current_token = token
                            user.failed_attempts = 0
                            st.rerun()
                        else:
                            user.failed_attempts += 1
                            if user.failed_attempts >= 3:
                                user.locked_until = datetime.utcnow() + timedelta(
                                    minutes=5
                                )
                                st.error(
                                    "Too many failed attempts. Account locked for 5 minutes."
                                )
                            else:
                                st.error("Invalid credentials")

        if st.session_state.logged_in:
            st.success(f"Logged in as **{st.session_state.current_user}**")

            # Token Display and Analysis
            st.subheader("Your JWT Token")
            token = st.session_state.current_token
            st.code(token)

            show_token_analysis(token, st)

            if st.button("Logout"):
                # Blacklist current token
                payload = jwt.decode(token, options={"verify_signature": False})
                st.session_state.token_blacklist.add(payload.get("jti"))
                st.session_state.logged_in = False
                st.rerun()

    # Hacker's Laboratory
    with col2:
        st.header("🔨 Hacker's Laboratory")
        if st.session_state.logged_in:
            st.info(
                """
            This section demonstrates various attack vectors and their complexity:
            - Dictionary Attack: Tests common passwords
            - Brute Force Attack: Tests all possible combinations
            - Token Analysis: Examines token structure and potential vulnerabilities
            """
            )

            attack_type = st.radio("Select Attack Type", ["dictionary", "brute_force"])

            if st.button("Start Attack Simulation"):
                progress_bar = st.progress(0)
                status = st.empty()

                if attack_type == "dictionary":
                    simulate_dictionary_attack(progress_bar, status)
                else:
                    if len(st.session_state.jwt_secret) <= 4:
                        brute_force_attack()
                    else:
                        total_combinations = len(ALLOWED_CHARS) ** len(
                            st.session_state.jwt_secret
                        )
                        # Format total_combinations and estimated time in the 10^x format
                        formatted_combinations = to_exponential_notation(
                            total_combinations
                        )
                        estimated_time = total_combinations / 1_000_000
                        formatted_time = to_exponential_notation(estimated_time)

                        st.info(
                            f"""
                            - Secret length: {len(st.session_state.jwt_secret)} characters.
                            - Possible combinations: {formatted_combinations}
                            - Estimated time at 1M attempts/second: {formatted_time} seconds
                            """
                        )
        else:
            st.warning("Login first to access the hacking demonstration.")

    # Educational Resources
    st.markdown("---")
    with st.expander("📚 Security Best Practices"):
        st.markdown(
            """
        ### JWT Security Best Practices
        
        1. **Secret Management**
           - Use long, random secrets (recommended: 32+ characters)
           - Rotate secrets periodically
           - Never store secrets in code or version control
        
        2. **Token Security**
           - Set appropriate expiration times
           - Include necessary claims (sub, exp, iat, jti)
           - Implement token blacklisting for logout
           - Use secure algorithms (HS256, RS256)
        
        3. **Implementation Security**
           - Implement rate limiting
           - Use password hashing with salt
           - Enable account lockout after failed attempts
           - Maintain secure session management
        
        ### Common Attack Vectors
        
        1. **Brute Force Attacks**
           - Targeting weak secrets
           - Dictionary attacks on passwords
           - Algorithm stripping attacks
        
        2. **Token Vulnerabilities**
           - None algorithm attack
           - Weak secret keys
           - Missing expiration
           - Replay attacks
        
        ### Additional Resources
        - [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
        - [JWT.io](https://jwt.io/)
        - [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
        """
        )


if __name__ == "__main__":
    main()
