import sqlite3

def get_user_data(user_id):
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    # This line is vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

user_id = input("Enter user ID: ")
print(get_user_data(user_id))
