import re
from PIL import Image
import pytesseract  # For OCR
import io

# --- Configuration ---
PII_PATTERNS = {
    "Aadhaar": r"\d{4}\s\d{4}\s\d{4}",  # Aadhaar pattern with spaces
    "PAN": r"[A-Z]{5}[0-9]{4}[A-Z]{1}",  # PAN format
    "Mobile": r"(?:\+91|0)?[6-9]\d{9}",  # Indian mobile number
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Driving License": r"[A-Z]{2}\d{2}\s?\d{7}\s?[A-Z]{2}\d{4}",  # DL pattern
}

SENSITIVE_KEYWORDS = [
    "Aadhaar", "Government of India", "Income Tax Department",
    "Driving License", "License Number", "Permanent Account Number",
]

# --- Helper Functions ---

def extract_text_from_image(image_file):
    """Extracts text from an image file using OCR."""
    try:
        img = Image.open(image_file)
        text = pytesseract.image_to_string(img, lang='eng+hin')  # Using English & Hindi for better detection
        return text.strip()
    except FileNotFoundError:
        print(f"Error: Image file not found: {image_file}")
        return ""
    except Exception as e:
        print(f"Error during OCR: {e}")
        return ""

def detect_pii_in_text(text):
    """Detects potential PII in a given text."""
    found_pii = {}
    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            found_pii[pii_type] = list(set(matches))  # Avoid duplicates
    return found_pii

def detect_sensitive_keywords(text):
    """Detects the presence of sensitive keywords."""
    found_keywords = [keyword for keyword in SENSITIVE_KEYWORDS if re.search(r'\b' + re.escape(keyword) + r'\b', text, re.IGNORECASE)]
    return list(set(found_keywords))

def analyze_document(file_path):
    """Analyzes a document (image or text) for PII."""
    detected_pii = {}
    sensitive_keywords = []
    extracted_text = ""

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            extracted_text = f.read()
            detected_pii.update(detect_pii_in_text(extracted_text))
            sensitive_keywords.extend(detect_sensitive_keywords(extracted_text))
    except UnicodeDecodeError:
        # Assume it's an image if text decoding fails
        extracted_text = extract_text_from_image(file_path)
        detected_pii.update(detect_pii_in_text(extracted_text))
        sensitive_keywords.extend(detect_sensitive_keywords(extracted_text))
    except FileNotFoundError:
        return {"error": f"File not found: {file_path}"}
    except Exception as e:
        return {"error": f"Error processing file: {e}"}

    return {
        "detected_pii": detected_pii,
        "sensitive_keywords": sensitive_keywords,
        "extracted_text": extracted_text[:500] + "..." if len(extracted_text) > 500 else extracted_text
    }  # Limit extracted text for brevity

def redact_pii_from_text(text, pii_patterns):
    """Redacts detected PII from text by replacing it with '[REDACTED]'."""
    redacted_text = text
    for pattern in pii_patterns.values():
        redacted_text = re.sub(pattern, "[REDACTED]", redacted_text)
    return redacted_text

# --- Application Logic ---

def main():
    file_path = input("Enter the path to the document/data file: ")
    analysis_result = analyze_document(file_path)

    if "error" in analysis_result:
        print(f"Error: {analysis_result['error']}")
        return

    print("\n--- Analysis Result ---")
    if analysis_result["detected_pii"]:
        print("Potential PII detected:")
        for pii_type, values in analysis_result["detected_pii"].items():
            print(f"- {pii_type}: {', '.join(values)}")
    else:
        print("No specific PII patterns detected.")

    if analysis_result["sensitive_keywords"]:
        print("\nSensitive keywords found:")
        print(f"- {', '.join(analysis_result['sensitive_keywords'])}")

    print("\nFirst 500 characters of extracted text:")
    print(analysis_result["extracted_text"])

    redact_option = input("\nDo you want to redact the detected PII and save a new file? (yes/no): ").lower()
    if redact_option == "yes" and analysis_result["detected_pii"]:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                original_content = f.read()
            redacted_content = redact_pii_from_text(original_content, PII_PATTERNS)
            output_file = f"{file_path}_redacted.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(redacted_content)
            print(f"\nRedacted content saved to: {output_file}")
        except UnicodeDecodeError:
            print("Warning: Could not open and redact as text. Redaction for image files is not implemented in this version.")
        except Exception as e:
            print(f"Error during redaction: {e}")
    elif redact_option == "yes" and not analysis_result["detected_pii"]:
        print("No PII detected to redact.")

if __name__ == "__main__":
    main()
