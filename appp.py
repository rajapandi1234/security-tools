import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    # Get the user input from the query parameter
    query = request.args.get('query', '')

    # Vulnerable: User input is directly concatenated into the SQL query
    connection = sqlite3.connect('example.db')
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")  # SQL injection vulnerability
    results = cursor.fetchall()
    connection.close()

    return str(results)

if __name__ == '__main__':
    app.run(debug=True)
