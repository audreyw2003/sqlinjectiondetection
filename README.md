# SQL Injection Detection Tool

A Python-based utility that analyzes SQL queries for potential injection vulnerabilities using regular expressions and pattern matching. Designed to help developers and security analysts identify risky query patterns and apply secure coding practices.

## Features

- Detects common SQL injection patterns (e.g., UNION, OR/AND logic, comment injection, time-based attacks)
- Provides tailored fix suggestions based on the type of vulnerability
- Logs query analysis results to a CSV file for audit and review
- Console-based interface for real-time feedback

## How It Works

1. User inputs SQL queries via the console.
2. Each query is scanned against multiple regex-based injection patterns.
3. If a vulnerability is detected:
   - A warning is printed to the console.
   - Suggested fixes are displayed.
4. If no issues are found, the query is marked as safe.
5. All results are saved to `results.csv`.

### Prerequisites

- Python 3.x
- No external dependencies required (uses built-in `re` and `csv` modules)

### Run the Tool

```bash
python sqlinjectiondetection.py
