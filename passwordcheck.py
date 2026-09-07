class Password:
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        # Check if the password meets certain criteria
        if len(self.password) < 8:
            return False

        if not any(char.isdigit() for char in self.password):
            return False

        if not any(char.isupper() for char in self.password):
            return False

        if not any(char.islower() for char in self.password):
            return False

        return True

    def strength(self):
        # Determine the strength of the password
        score = 0

        if len(self.password) >= 8:
            score += 1

        if any(char.isdigit() for char in self.password):
            score += 1

        if any(char.isupper() for char in self.password):
            score += 1

        if any(char.islower() for char in self.password):
            score += 1

        if any(not char.isalnum() for char in self.password):
            score += 1

        if score <= 2:
            return "Weak"
        elif score == 3:
            return "Moderate"
        else:
            return "Strong"


# Get password from the user
user_password = input("Enter your password: ")

# Create Password object
password = Password(user_password)

# Check validity
if password.is_valid():
    print("Password is valid!")
else:
    print("Password is invalid!")

# Check strength
print("Password strength:", password.strength())