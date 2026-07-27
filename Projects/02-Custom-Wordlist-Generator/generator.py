import random

# Generate 3 usernames 4 passwords with a list of combination
usernames = [ "ali", "boba", "coca"]
passwords = ["pass", "1234", "4321", "ssap"]

# The third list to hold all combinations
combinations = []

# Nested for loop to combine usernames and passwords
for u in usernames:
    for p in passwords:
        # Combine with : and append
        item = u + ":" + p
        combinations.append(item)

# Print all combinations
for c in combinations:
    print(c)
