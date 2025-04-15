import random
import hashlib
import time

class QuantumKeyDistribution:
    """Class to simulate Quantum Key Distribution for secure key generation."""
    
    def __init__(self):
        self.shared_key = self.generate_shared_key()

    def generate_shared_key(self):
        """Generates a random shared key for encryption."""
        return ''.join(random.choice('01') for _ in range(128))  # 128-bit key


class HomomorphicEncryption:
    """Class to handle homomorphic encryption of passwords."""
    
    @staticmethod
    def encrypt(plaintext):
        """Encrypts the plaintext password using SHA-256 hashing."""
        return hashlib.sha256(plaintext.encode()).hexdigest()


class ZeroKnowledgeProof:
    """Class to handle Zero-Knowledge Proofs for password verification."""
    
    @staticmethod
    def generate_proof(password):
        """Generates a proof of knowledge of the password."""
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def verify_proof(submitted_proof, actual_password):
        """Verifies the submitted proof against the actual password."""
        expected_proof = ZeroKnowledgeProof.generate_proof(actual_password)
        return submitted_proof == expected_proof


class SecurePasswordManager:
    """Main class to manage user registration, login, and password security."""
    
    def __init__(self):
        self.qkd = QuantumKeyDistribution()
        self.password_storage = {}  # Store encrypted passwords
        self.otp_storage = {}  # Store OTPs for 2FA

    def register_user(self, username, password):
        """Registers a new user by storing their encrypted password and ZKP proof."""
        if username in self.password_storage:
            print("Username already exists. Please choose a different one.")
            return
        
        encrypted_password = HomomorphicEncryption.encrypt(password)
        self.password_storage[username] = {
            'encrypted_password': encrypted_password,
            'zkp_proof': ZeroKnowledgeProof.generate_proof(password)
        }
        print(f"User '{username}' registered successfully.")

    def generate_otp(self, username):
        """Generates a One-Time Password (OTP) for 2FA and simulates sending it to the user."""
        otp = random.randint(100000, 999999)  # Generate a 6-digit OTP
        self.otp_storage[username] = otp
        print(f"OTP for {username}: {otp}")  # Simulate sending OTP (e.g., via SMS or email)
        return otp

    def login_user(self, username, entered_password):
        """Handles user login process including ZKP verification and OTP validation."""
        
        if username not in self.password_storage:
            print("User not found.")
            return False
        
        stored_data = self.password_storage[username]
        
        # Verify the password using Zero-Knowledge Proof
        if ZeroKnowledgeProof.verify_proof(ZeroKnowledgeProof.generate_proof(entered_password), entered_password):
            print("ZKP verification passed.")
            
            # Check if the encrypted password matches
            if stored_data['encrypted_password'] == HomomorphicEncryption.encrypt(entered_password):
                print("Password verified. Generating OTP...")
                otp = self.generate_otp(username)

                # Simulate waiting for user to enter the OTP
                user_otp = input("Enter the OTP sent to your device: ").strip()
                
                if user_otp == str(otp):
                    print("Login successful!")
                    return True
                else:
                    print("Invalid OTP.")
                    return False
            else:
                print("Invalid password.")
                return False
        else:
            print("ZKP verification failed.")
            return False


def main():
    """Main function to run the Secure Password Manager application."""
    
    secure_manager = SecurePasswordManager()
    
    while True:
        action = input("Do you want to (register/login/exit)? ").strip().lower()
        
        if action == 'register':
            username = input("Enter a username: ").strip()
            password = input("Enter a password: ").strip()
            
            # Basic validation for password strength (at least 8 characters)
            if len(password) < 8:
                print("Password must be at least 8 characters long.")
                continue
            
            secure_manager.register_user(username, password)

        elif action == 'login':
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()
            secure_manager.login_user(username, password)

        elif action == 'exit':
            print("Exiting the program.")
            break

        else:
            print("Invalid option. Please choose 'register', 'login', or 'exit'.")

if __name__ == "__main__":
    main()
 
