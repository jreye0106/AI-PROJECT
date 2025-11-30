# prompt_validator.py
# Call "validate_prompt" before use
# checks user input before sending to AI engine


from dataclasses import dataclass
from typing import List, Optional

# Adjust these to your project needs
ALLOWED_MODES = {"text", "image", "code"}
DEFAULT_MIN_LENGTH = 10
DEFAULT_MAX_LENGTH = 500


@dataclass
class PromptValidationResult:
    """
    Represents the result of validating a prompt.
    """
    is_valid: bool
    errors: List[str]
    cleaned_prompt: Optional[str] = None  # trimmed/normalized text
    mode: Optional[str] = None


def validate_prompt(
    prompt: Optional[str],
    mode: str = "text",
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_length: int = DEFAULT_MAX_LENGTH
) -> PromptValidationResult:
    """
    Validate a user prompt before sending it to the AI engine.

    - prompt: user-provided text (raw input).
    - mode: what kind of generation we are doing (e.g., 'text', 'image', 'code').

    Returns a PromptValidationResult object.
    """
    errors: List[str] = []

    # 1. Basic type check
    if prompt is None:
        errors.append("Prompt is missing.")
        return PromptValidationResult(False, errors, None, mode)

    if not isinstance(prompt, str):
        errors.append("Prompt must be text.")
        return PromptValidationResult(False, errors, None, mode)

    # 2. Trim whitespace
    cleaned = prompt.strip()

    # 3. Empty / whitespace check
    if not cleaned:
        errors.append("Prompt cannot be empty or just spaces.")

    # 4. Length checks
    length = len(cleaned)
    if length < min_length:
        errors.append(f"Prompt is too short (min {min_length} characters).")

    if length > max_length:
        errors.append(f"Prompt is too long (max {max_length} characters).")

    # 5. Mode validation
    if mode not in ALLOWED_MODES:
        errors.append(
            f"Mode '{mode}' is not supported. Allowed modes: {sorted(ALLOWED_MODES)}"
        )

    # 6. (Optional) very light content sanity checks
    # Example: require at least 2 words
    if len(cleaned.split()) < 2:
        errors.append("Prompt should contain at least two words.")

    # More project-specific checks can go here later:
    # - required keywords for some modes
    # - forbidden phrases
    # - simple structure checks, etc.

    is_valid = len(errors) == 0
    if not is_valid:
        return PromptValidationResult(False, errors, None, mode)

    # If valid, return the cleaned prompt so the engine can use it directly
    return PromptValidationResult(True, [], cleaned, mode)
