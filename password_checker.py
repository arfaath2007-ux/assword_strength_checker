# password_checker.py
"""
Password Strength Checker

Evaluates password strength based on length and character variety.
Provides a classification (Very Weak, Weak, Moderate, Strong, Very Strong)
and specific feedback for improvement.
"""

import re
import sys
from typing import Tuple, List

# Regular expression patterns for character categories
UPPER_PATTERN = re.compile(r"[A-Z]")
LOWER_PATTERN = re.compile(r"[a-z]")
DIGIT_PATTERN = re.compile(r"\d")
SPECIAL_PATTERN = re.compile(r"[^A-Za-z0-9]")


def _has_upper(password: str) -> bool:
    return bool(UPPER_PATTERN.search(password))


def _has_lower(password: str) -> bool:
    return bool(LOWER_PATTERN.search(password))


def _has_digit(password: str) -> bool:
    return bool(DIGIT_PATTERN.search(password))


def _has_special(password: str) -> bool:
    return bool(SPECIAL_PATTERN.search(password))


def evaluate_password(password: str) -> Tuple[str, List[str]]:
    """Evaluate the password and return a classification and feedback.

    Parameters
    ----------
    password: str
        The password string to evaluate.

    Returns
    -------
    Tuple[str, List[str]]
        A tuple containing the strength classification and a list of feedback strings.
    """
    feedback: List[str] = []
    length = len(password)

    # Length checks
    if length < 8:
        feedback.append("Password is too short; aim for at least 8 characters.")
    elif length < 12:
        feedback.append("Longer passwords are more secure; consider 12+ characters.")
    elif length >= 16:
        feedback.append("Excellent length!")

    # Character variety checks
    has_upper = _has_upper(password)
    has_lower = _has_lower(password)
    has_digit = _has_digit(password)
    has_special = _has_special(password)

    if not has_upper:
        feedback.append("Add uppercase letters (A‑Z).")
    if not has_lower:
        feedback.append("Add lowercase letters (a‑z).")
    if not has_digit:
        feedback.append("Add numbers (0‑9).")
    if not has_special:
        feedback.append("Add special characters (e.g., !@#$%).")

    # Scoring – each satisfied criterion adds a point
    score = 0
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1  # extra point for very long passwords
    if has_upper:
        score += 1
    if has_lower:
        score += 1
    if has_digit:
        score += 1
    if has_special:
        score += 1

    # Map score to classification
    if score <= 2:
        classification = "Very Weak"
    elif score == 3:
        classification = "Weak"
    elif score == 4:
        classification = "Moderate"
    elif score == 5:
        classification = "Strong"
    else:
        classification = "Very Strong"

    # Remove duplicate feedback entries (e.g., length messages may be contradictory)
    feedback = list(dict.fromkeys(feedback))
    return classification, feedback


def main() -> None:
    if len(sys.argv) > 1:
        # Password supplied as a command‑line argument (useful for scripting)
        pwd = sys.argv[1]
    else:
        # Interactive prompt – hide input for security
        try:
            import getpass
            pwd = getpass.getpass("Enter password to evaluate: ")
        except Exception:
            # Fallback if getpass fails (e.g., in non‑tty environments)
            pwd = input("Enter password to evaluate: ")

    classification, feedback = evaluate_password(pwd)
    print(f"Password strength: {classification}\n")
    if feedback:
        print("Feedback:")
        for f in feedback:
            print(f" - {f}")
    else:
        print("Your password meets all recommended criteria!")


if __name__ == "__main__":
    main()
