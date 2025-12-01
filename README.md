# AI-PROJECT

Project Overview

This project is a local code generation and vulnerability detection tool designed to help developers, students, and security enthusiasts create code snippets and scan them for common vulnerabilities. All operations are performed locally, meaning no remote AI or cloud processing is required. This approach was chosen to maximize speed, reliability, and offline functionality, especially for use cases like exams or secure environments where internet access is limited or prohibited. Although we wanted the AI approach initially we saw that running locally increated our result speeds .

The program has two main capabilities:

Code Generation — Create functional code snippets based on user prompts.

Vulnerability Detection — Scan code for common security issues and generate detailed reports.

| File                          | Purpose 

| `gui.py`                      | Main graphical interface (PySide6) allowing users to generate                    code and scan vulnerabilities. Contains all widgets, tabs, and event handlers.                                                          |
| `generator.py`                | Local code generator. Holds the `Generator` class and all               templates for generating meaningful code snippets, including loops, functions, and               complex logic.                                           |
| `vulnerability_scanner.py`    | Local vulnerability scanner. Contains `VulnerabilityScanner`                                     which performs heuristic analysis of code to detect potential                                    security issues like hardcoded secrets, use of `eval`, or                                        unsafe commands. |
| `validator.py`                | Validates user inputs. Ensures prompts and actions are                                          acceptable before passing them to the generator or scanner.                                                                                    |
| `workflow_manager.py`         | Manages the workflow between code generation, validation, and                                   scanning. Centralizes logic so the GUI only calls                                                `process_request`.                                          
Code Generation Functionality
Generator Class
The Generator class is the core of the code generation portion. It can:
Generate functions with loops, recursion, and conditionals.
Create simple to complex algorithms (e.g., factorial, Fibonacci, sorting).
Include classes, nested functions, and basic data structures.
Execute up to 50+ templates for different coding tasks:
Some example templates the generator can handle:
-Mathematical Functions
Factorial of a number.
Fibonacci sequence up to N.
Prime number check.
-Data Structures
Create and manipulate lists, sets, and dictionaries.
Implement stacks, queues, and simple linked lists.
-String & File Operations
Reverse a string.
Count words in a text file.
Parse CSV files.
-Loops & Recursion
For/while loops generating repeated output.
Recursive functions for tree traversal or factorial.
-Error Handling
Demonstrate try/except blocks.
Input validation inside functions.


Vulnerability Detection Functionality
The VulnerabilityScanner class can identify:
Hardcoded secrets
Passwords, API keys, or secret tokens inside the code.
Unsafe code execution
Use of eval(), exec(), os.system(), or subprocess calls.
Basic logic and syntax issues
Optional: can detect missing imports or suspicious operations.
Output
The scanner returns:
A JSON report with:
id – unique issue ID.
title – description of the issue.
severity – LOW / MEDIUM / HIGH / CRITICAL.
line – line number where the issue appears.

Why Local Instead of Cloud AI

Speed: Generating code locally is faster than sending requests to a cloud AI and waiting for responses.
Offline Access: Works without internet connection — perfect for exams or restricted environments.
Security: No sensitive data is sent over the internet.
Control: Users can add or modify templates and detection rules directly in the local files.
Reliability: Avoids rate limits, API downtime, or subscription requirements.

How to Use

Run the program>
IN A TERMINAL TYPE : python gui.py
Code Generation Tab
Type a prompt describing the function you want.
Press Run.
Generated code will appear in the output box.
Vulnerability Detector Tab
Paste the code to scan.
Press Run.
A table shows the issues; raw JSON report is also displayed.
Save outputs using the Save buttons if needed.

Notes

All templates and scans run locally.
New code templates can be added to generator.py.
Detection rules can be modified in vulnerability_scanner.py.
Input validation ensures no invalid prompts or actions are processed.


CODE GEN EXAMPLES:
Prompt: Generate a factorial function using recursion
Expected: Recursive factorial function

Prompt: Generate Fibonacci sequence up to 10
Expected: Function returning [0,1,1,2,3,5,8]

Prompt: Generate a function that sums all numbers in a list
Expected: Function using for loop or sum() function

Prompt: Generate a function to reverse a string
Expected: Uses slicing or loop to reverse string

Prompt: Generate a class for a simple Stack
Expected: Class with push, pop, peek methods

Prompt: Generate a function to check if a number is prime
Expected: Loop through divisors, returns True/False

Prompt: Generate a function to read a CSV file and sum a column
Expected: Uses csv.DictReader, loops over rows

Prompt: Generate a function with a while loop that counts down from 10
Expected: Simple countdown logic

Prompt: Generate a function to find the maximum value in a list
Expected: Uses max() or manual loop comparison

Prompt: Generate a function that uses recursion to compute power(x, n)
Expected: Function with base case and recursive call

Prompt: Generate a function to remove duplicates from a list
Expected: Uses set() or loop to filter duplicates

Prompt: Generate a function to merge two dictionaries
Expected: Handles key conflicts, returns merged dictionary

Prompt: Generate a function to reverse words in a sentence
Expected: Splits sentence, reverses order, joins back

Prompt: Generate a function to validate email addresses
Expected: Basic regex or string checks for @ and .

Prompt: Generate a function to compute factorial iteratively
Expected: Loop-based factorial calculation

VULNERABILITY DETECTOR EXAMPLES: 
Code: password = "1234"
Expected Detection: Hardcoded secret (CRITICAL)

Code: api_key = "abcd1234"
Expected Detection: Hardcoded secret (CRITICAL)

Code: eval("print(2+2)")
Expected Detection: Use of eval/exec (HIGH)

Code: exec("x=5")
Expected Detection: Use of eval/exec (HIGH)

Code: import os
os.system("rm -rf /")
Expected Detection: Unsafe command execution (HIGH)

Code: import subprocess
subprocess.call("ls")
Expected Detection: Unsafe command execution (HIGH)

Code: def safe_func():
return 2+2
Expected Detection: No vulnerabilities (score 100)

Code: password="secret"
eval("print(password)")
os.system("ls")
Expected Detection: Multiple issues (CRITICAL/HIGH)

Code: api_key="key"
subprocess.call("echo hello")
Expected Detection: Hardcoded secret + unsafe command

Code: def check(x):
return x*2
Expected Detection: No vulnerabilities detected

Code: exec("print('hello')")
Expected Detection: Use of exec (HIGH)

Code: passwd = "admin123"
Expected Detection: Hardcoded secret (CRITICAL)

Code: def myfunc():
os.system("mkdir test")
Expected Detection: Unsafe command execution (HIGH)
