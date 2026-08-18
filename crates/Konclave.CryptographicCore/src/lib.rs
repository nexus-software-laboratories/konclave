#![forbid(unsafe_code)]
#![allow(non_snake_case)]

use thiserror::Error;

const MAX_NAME_LEN: usize = 64;

/// Shared library boundary scaffold. Replace the placeholder API with
/// project-specific implementation when this host is selected.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PlaceholderName(String);

impl PlaceholderName {
    /// Parses a non-empty placeholder value for the shared library boundary.
    ///
    /// # Errors
    ///
    /// Returns [KonclaveCryptographicCoreError] when the supplied value is blank or too long.
    pub fn parse(value: impl Into<String>) -> Result<Self, KonclaveCryptographicCoreError> {
        let candidate = value.into();
        let trimmed = candidate.trim();

        if trimmed.is_empty() {
            return Err(KonclaveCryptographicCoreError::EmptyValue);
        }

        if trimmed.len() > MAX_NAME_LEN {
            return Err(KonclaveCryptographicCoreError::ValueTooLong {
                max: MAX_NAME_LEN,
                actual: trimmed.len(),
            });
        }

        Ok(Self(trimmed.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Stable typed errors for the shared library boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KonclaveCryptographicCoreError {
    #[error("Library value cannot be empty")]
    EmptyValue,

    #[error("Library value exceeds the maximum length of {max} characters (actual: {actual})")]
    ValueTooLong { max: usize, actual: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_valid_placeholder() {
        let value = PlaceholderName::parse(" shared ").unwrap();
        assert_eq!(value.as_str(), "shared");
    }

    #[test]
    fn rejects_empty_placeholder() {
        assert_eq!(
            PlaceholderName::parse("   ").unwrap_err(),
            KonclaveCryptographicCoreError::EmptyValue
        );
    }

    #[test]
    fn rejects_overlong_placeholder() {
        let input = "x".repeat(MAX_NAME_LEN + 1);
        assert_eq!(
            PlaceholderName::parse(input).unwrap_err(),
            KonclaveCryptographicCoreError::ValueTooLong {
                max: MAX_NAME_LEN,
                actual: MAX_NAME_LEN + 1,
            }
        );
    }
}
