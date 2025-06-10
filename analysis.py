import os
import json
import google.generativeai as genai
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

INPUT_DIR = "unlabelled_dataset"
NAME_SOURCE_DIR = "mythril"
OUTPUT_DIR ="gemini_output"
MODEL_NAME = "gemini-2.0-flash"

# System prompt for consistent vulnerability analysis
SYSTEM_PROMPT = """You are an expert Solidity vulnerability analyzer specializing in static analysis. Your task is to analyze Solidity smart contracts and produce comprehensive vulnerability reports in the exact Mythril JSON schema format.

CRITICAL FORMATTING REQUIREMENTS:
- You MUST return ONLY the raw JSON object
- DO NOT use markdown code blocks (```json or ```)
- DO NOT add any text before or after the JSON
- DO NOT use any formatting, indentation, or special characters outside the JSON
- The response should start with { and end with }
- NO explanations, NO comments, NO additional text

VULNERABILITY DETECTION GUIDELINES:

1. REENTRANCY VULNERABILITIES:
   - Look for external calls (call, send, transfer) followed by state changes
   - Check for recursive call patterns in fallback functions
   - Identify unprotected withdrawal functions
   - Title: "State change after external call" or "Message call to external contract"
   - Focus on: external call → state change pattern

2. ACCESS CONTROL ISSUES:
   - Detect use of tx.origin instead of msg.sender
   - Find missing access modifiers (public vs private)
   - Identify unauthorized function access patterns
   - Title: "Use of tx.origin" or "Access control vulnerability"
   - Focus on: tx.origin usage, missing modifiers

3. INTEGER OVERFLOW/UNDERFLOW:
   - Check arithmetic operations without SafeMath
   - Look for unchecked additions, subtractions, multiplications
   - Identify potential overflow in loops or calculations
   - Title: "Integer Overflow" or "Integer Underflow"
   - Focus on: arithmetic operations without bounds checking

4. UNCHECKED EXTERNAL CALLS:
   - Find external calls without return value checks
   - Identify low-level calls (call, delegatecall, staticcall)
   - Check for missing error handling in send/transfer
   - Title: "Unchecked CALL return value"
   - Focus on: send(), transfer(), call() without return checks

5. TRANSACTION ORDER DEPENDENCE:
   - Detect race conditions in state changes
   - Find front-running vulnerabilities
   - Identify predictable state variables
   - Title: "Transaction order dependence"
   - Focus on: state changes that can be front-run

6. DENIAL OF SERVICE:
   - Look for unbounded loops
   - Check for expensive operations in loops
   - Identify gas limit issues
   - Title: "Denial of Service" or "Gas limit exceeded"
   - Focus on: loops without bounds, expensive operations

7. BAD RANDOMNESS:
   - Detect use of block.timestamp, block.number, block.blockhash
   - Find predictable random number generation
   - Identify miner-manipulatable sources
   - Title: "Dependence on predictable environment variable"
   - Focus on: block.timestamp, block.number, block.blockhash usage

8. UNCHECKED LOW-LEVEL CALLS:
   - Find dangerous low-level operations
   - Check for delegatecall usage
   - Identify unsafe external calls
   - Title: "Unchecked low-level call"
   - Focus on: delegatecall, low-level call patterns

TECHNICAL REQUIREMENTS:
- Provide EXACT line numbers where vulnerabilities occur
- Include the precise code snippet causing the vulnerability
- Use exact function signatures (including parameters)
- Set address field to the line number (for consistency with your format)
- Include detailed debug information explaining the vulnerability
- Ensure descriptions explain both the vulnerability and potential impact

SEVERITY LEVELS:
- "Warning": High-risk vulnerabilities that could lead to loss of funds or contract compromise
- "Informational": Lower-risk issues, best practices violations, code quality issues
- "Error": Critical vulnerabilities requiring immediate attention

OUTPUT FORMAT:
{
  "contract": "<filename>",
  "tool": "mythril",
  "start": <start_unix_timestamp>,
  "end": <end_unix_timestamp>,
  "duration": <duration_seconds>,
  "analysis": {
    "success": true,
    "error": null,
    "issues": [
      {
        "filename": "<relative_path>",
        "function": "<function_name>",
        "lineno": <exact_line_number>,
        "code": "<exact_offending_code_line>",
        "title": "<vulnerability_title>",
        "type": "<severity_level>",
        "description": "<detailed_description_with_explanation>",
        "address": <line_number>,
        "debug": "<technical_debug_info>"
      }
    ]
  }
}

ANALYSIS INSTRUCTIONS:
1. Carefully examine each function and line of code
2. Look for security patterns and anti-patterns
3. Provide specific line numbers and function names
4. Include the exact code that causes the vulnerability
5. Write detailed descriptions explaining the risk and potential impact
6. If no vulnerabilities are found, return empty "issues": [] array
7. Ensure all timestamps and durations are accurate
8. Use precise vulnerability titles matching Mythril conventions
9. Focus on finding ALL vulnerabilities, not just the most obvious ones
10. Pay special attention to cross-function vulnerabilities

FINAL REMINDER: Return ONLY the JSON object. No markdown, no formatting, no additional text."""

# Configure Gemini API
# The API key can be set in several ways:
# 1. Environment variable: export GOOGLE_API_KEY="your-api-key-here"
# 2. .env file: Create a .env file with GOOGLE_API_KEY=your-api-key-here
# 3. Direct assignment: api_key = "your-api-key-here"
api_key = os.getenv("GOOGLE_API_KEY")
if not api_key:
    raise ValueError("GOOGLE_API_KEY not found. Please set it as an environment variable or in a .env file.")

genai.configure(api_key=api_key)

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Get all contract names from mythril folder (these are the target names we're looking for)
mythril_contract_names = set()
for item in os.listdir(NAME_SOURCE_DIR):
    if os.path.isdir(os.path.join(NAME_SOURCE_DIR, item)):
        mythril_contract_names.add(item)

print(f"🔍 Looking for {len(mythril_contract_names)} contracts from mythril folder")

# Track processed contracts
processed_count = 0
found_count = 0

# Iterate through all vulnerability categories in unlabelled_dataset
for category in os.listdir(INPUT_DIR):
    category_path = os.path.join(INPUT_DIR, category)
    
    # Skip if not a directory
    if not os.path.isdir(category_path):
        continue
    
    print(f"\n📁 Processing category: {category}")
    
    # Iterate through all .sol files in this category
    for sol_file in os.listdir(category_path):
        if not sol_file.endswith('.sol'):
            continue
            
        # Get the contract name (filename without .sol extension)
        contract_name = sol_file[:-4]  # Remove .sol extension
        
        # Check if this contract name exists in mythril folder
        if contract_name not in mythril_contract_names:
            continue
            
        found_count += 1
        input_path = os.path.join(category_path, sol_file)
        output_path = os.path.join(OUTPUT_DIR, f"{contract_name}.json")

        # Skip if output already exists
        if os.path.exists(output_path):
            print(f"⏩ Skipping {contract_name} (already analyzed)")
            continue

        print(f"🔍 Processing: {input_path}")

        try:
            with open(input_path, "r", encoding="utf-8") as f:
                contract_code = f.read()

            # Create Gemini model instance
            model = genai.GenerativeModel(MODEL_NAME)
            
            # Record start time
            start_time = int(time.time())
            
            # Generate response from Gemini with system prompt
            response = model.generate_content([
                {"role": "user", "parts": [SYSTEM_PROMPT + "\n\nAnalyze this Solidity contract:\n\n" + contract_code]}
            ])
            
            # Record end time
            end_time = int(time.time())
            duration = end_time - start_time
            
            output = response.text.strip()

            # Clean up any markdown formatting that might have been added
            if output.startswith('```json'):
                output = output[7:]  # Remove ```json
            if output.startswith('```'):
                output = output[3:]   # Remove ```
            if output.endswith('```'):
                output = output[:-3]  # Remove trailing ```
            output = output.strip()

            try:
                json_data = json.loads(output)
                
                # Ensure the JSON has the required structure with timestamps
                if "start" not in json_data:
                    json_data["start"] = start_time
                if "end" not in json_data:
                    json_data["end"] = end_time
                if "duration" not in json_data:
                    json_data["duration"] = duration
                if "contract" not in json_data:
                    json_data["contract"] = sol_file
                if "tool" not in json_data:
                    json_data["tool"] = "mythril"
                
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(json_data, f, indent=2)
                print(f"✅ Saved: {output_path}")
                processed_count += 1
                
                # Continue processing other files
                print("✅ File processed successfully, continuing...")
                
            except json.JSONDecodeError:
                raw_path = os.path.join(OUTPUT_DIR, f"{contract_name}_raw.txt")
                with open(raw_path, "w", encoding="utf-8") as f:
                    f.write(output)
                print(f"⚠️ JSON parse failed — raw output saved: {raw_path}")
                processed_count += 1
                
                # Continue processing other files
                print("⚠️ JSON parsing failed, continuing with next file...")

        except Exception as e:
            print(f"💥 Error processing {contract_name}: {e}")
            # Continue processing other files
            print("💥 Error occurred, continuing with next file...")

print(f"\n📊 Summary:")
print(f"   - Found {found_count} matching contracts")
print(f"   - Processed {processed_count} contracts")
print(f"   - Total mythril contracts: {len(mythril_contract_names)}")
