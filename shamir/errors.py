"""Error codes for Shamir's Secret Sharing."""

from enum import StrEnum


class Error(StrEnum):
    """Error codes for Shamir's Secret Sharing."""

    LESS_THAN_TWO_PARTS = "Less than two parts cannot be used to reconstruct the secret"
    PARTS_MUST_BE_TWO_BYTES = "Parts must be at least two bytes"
    ALL_PARTS_MUST_BE_SAME_LENGTH = "All parts must be the same length"
    DUPLICATE_PART = "Duplicate part detected"
    PARTS_CANNOT_BE_LESS_THAN_THRESHOLD = "Parts cannot be less than threshold"
    PARTS_OR_THRESHOLD_CANNOT_EXCEED_255 = "Parts or Threshold cannot exceed 255"
    THRESHOLD_MUST_BE_AT_LEAST_2 = "Threshold must be at least 2"
    CANNOT_SPLIT_EMPTY_SECRET = "Cannot split an empty secret"  # noqa: S105
    UNINITIALIZED_RNG = "RNG not initialized"
