from auth import register, login, logout

while True:
    print("\n1. Register\n2. Login\n3. Logout\n4. Exit")
    choice = input("> ")

    if choice == "1":
        u = input("Username: ")
        p = input("Password: ")
        register(u, p)

    elif choice == "2":
        u = input("Username: ")
        p = input("Password: ")
        login(u, p)

    elif choice == "3":
        logout()

    elif choice == "4":
        break