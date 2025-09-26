import re
import csv

#Function to print details about vulnerability to the console for user to see immediately
def vulnerability(query, message, fix_suggestion):
    print(f"Potential SQL injection detected: {message}\nQuery: {query}\nSuggested Fix: {fix_suggestion}\n")

# Function to print that a query is safe to console for user to see immediately
def safe_query(query):
    print(f"Query is safe: {query}\n")

#Function that suggests fixes for found vulnerabilities based on what sql injection vulnerability pattern was found in the query
#Appends suggested fixes for the query to a list and returns the list of suggested fixes for that query
def suggest_fixes(query, pattern):
    #empty list to hold suggested fixes 
    fixes = []
    #checks if the pattern contains certain sql injection vulnerability
    #based on the vulnerability suggests fix to mitigate it
    if "union" in pattern:
        fixes.append("Avoid using UNION with untrusted data. Use parameterized queries to separate SQL code from data.")
    if "select" in pattern and ("or " in query.lower() or "and " in query.lower()):
        fixes.append("Avoid using OR and AND with untrusted data in SELECT queries. Use parameterized queries.")
    if any(keyword in pattern for keyword in ["insert", "delete", "update", "drop", "alter", "create", "exec"]):
        fixes.append("Avoid using DDL or DML operations with untrusted data. Use stored procedures or parameterized queries.")
    if "--" in pattern or ";" in pattern:
        fixes.append("Ensure that comments and semicolons are not included in user inputs. Sanitize and validate all inputs.")
    if any(keyword in pattern for keyword in ["sleep", "benchmark"]):
        fixes.append("Avoid using time-based functions with untrusted data. Use parameterized queries.")
    
    #if none of the injection types checked matched generates list of general suggested practices to prevent sql injection
    if not fixes:
        fixes.append("Use parameterized queries or prepared statements to prevent SQL injection.")
        fixes.append("Validate and sanitize all user inputs.")
        fixes.append("Implement input validation and allow only trusted inputs.")
        fixes.append("Limit database permissions to reduce the impact of potential injections.")
    #returns list of suggested fixes
    return fixes

#Function to analyze an individual query for SQL injection patterns and suggest fixes
#uses regex to create patterns to get better accuracy
def analyze_query(query):
    injection_patterns = [
    #checks for sql comment syntax and common sql keywords
    re.compile(r"('|\")?(--|;|/\*|\*/|#|\b(union|insert|delete|update|drop|alter|create|exec|sleep)\b)", re.IGNORECASE),

    #checks for common conditions used in sql injections
    re.compile(r"('|\")?(\s|\+|or|and)(\s)?('[^']*?'|\d+)", re.IGNORECASE),

    #checks for select statement with where clause
    re.compile(r"(select.*from.*where.*('|\"|\d|\sor\s|\sand\s))", re.IGNORECASE)
    ]

    #iterates through list of injection patterns
    for pattern in injection_patterns:

        #checks if the query contains a substring matching the pattern
        if pattern.search(query):

            #if match is found a message is generated that a suspicious pattern was found and what the pattern was
            message = f"Suspicious pattern found: {pattern.pattern}"

            #generates suggested fixes for the vulnerability
            fix_suggestions = suggest_fixes(query, pattern.pattern)

            #joins suggested fixes into single string and seperates each fix into a new line
            fix_suggestion = "\n".join(fix_suggestions)

            #prints message detailing the found vulnerability
            vulnerability(query, message, fix_suggestion)

            #returns true that a vulnerability was detected
            #the message with the pattern found
            #and the list of fixes for that pattern
            return True, message, fix_suggestion
    
    #if no vulnerability found prints safe query message
    safe_query(query)

    #returns false and sets message to indicate query is safe
    return False, "Query is safe.", ""

#Function to analyze multiple queries
def analyze_queries(queries):
    #initializes empty list to store the result for each query
    results = []

    #iterates through each query in the given list
    for query in queries:

        #calls analyze query function and saves the data
        is_vulnerable, message, fix_suggestion = analyze_query(query)

        #adds the results from analysis into results list as a tuple
        results.append((query, is_vulnerable, message, fix_suggestion))

    #returns list of results from the analysis of each query
    return results

# Example usage
def main():

    #empty list to hold queries inputted
    queries = []

    #infinite loop for user to enter queries to analyze
    while(1):
        #takes query from user input
        query = input('Input query to test (enter exit to exit): ')

        #breaks loop when user enters exit
        if (query == 'exit'):
            break

        #adds the query to list of queries
        queries.append(query)

    #list of the results for each query
    analysis_results = analyze_queries(queries)

    #opens csv file to log the results and save them
    with open('results.csv', mode='w', newline='') as file:
        #creates a writer object to write to the csv file
        writer = csv.writer(file)
    
        #writes the column titles into the file
        writer.writerow(['Query', 'Status', 'Message', 'Suggested Fix'])
    
        #iterates through results 
        for query, is_vulnerable, message, fix_suggestion in analysis_results:
            #if is_vulnerable is set to true then the status of the query is set as vulnerable
            #if false status is set to safe
            status = "VULNERABLE" if is_vulnerable else "SAFE"

            #writes the query, status, message, and suggested fixes into a row in the csv file
            writer.writerow([query, status, message, fix_suggestion])
#runs main program
main()