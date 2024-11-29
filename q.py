import pickle

def load_data(file_path):
    with open(file_path, 'rb') as file:
        # This line is vulnerable to insecure deserialization
        data = pickle.load(file)
    return data

file_path = input("Enter file path: ")
print(load_data(file_path))
