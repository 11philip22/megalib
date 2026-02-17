//! MEGA API error codes.

/// MEGA API error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiErrorCode {
    /// Internal error
    Internal = -1,
    /// Invalid arguments
    Args = -2,
    /// Try again (rate limited)
    Again = -3,
    /// Rate limit exceeded
    RateLimit = -4,
    /// Upload failed
    Failed = -5,
    /// Too many IPs
    TooManyIps = -6,
    /// Access denied
    AccessDenied = -7,
    /// Resource already exists
    Exist = -8,
    /// Resource does not exist
    NotExist = -9,
    /// Circular linking
    Circular = -10,
    /// Access violation
    AccessViolation = -11,
    /// Application key required
    AppKey = -12,
    /// Session expired
    Expired = -13,
    /// Not confirmed
    NotConfirmed = -14,
    /// Resource blocked
    Blocked = -15,
    /// Over quota
    OverQuota = -16,
    /// Temporarily unavailable
    TempUnavail = -17,
    /// Too many connections
    TooManyConnections = -18,
    /// Unknown error
    Unknown = -9999,
}

impl From<i64> for ApiErrorCode {
    fn from(code: i64) -> Self {
        match code {
            -1 => ApiErrorCode::Internal,
            -2 => ApiErrorCode::Args,
            -3 => ApiErrorCode::Again,
            -4 => ApiErrorCode::RateLimit,
            -5 => ApiErrorCode::Failed,
            -6 => ApiErrorCode::TooManyIps,
            -7 => ApiErrorCode::AccessDenied,
            -8 => ApiErrorCode::Exist,
            -9 => ApiErrorCode::NotExist,
            -10 => ApiErrorCode::Circular,
            -11 => ApiErrorCode::AccessViolation,
            -12 => ApiErrorCode::AppKey,
            -13 => ApiErrorCode::Expired,
            -14 => ApiErrorCode::NotConfirmed,
            -15 => ApiErrorCode::Blocked,
            -16 => ApiErrorCode::OverQuota,
            -17 => ApiErrorCode::TempUnavail,
            -18 => ApiErrorCode::TooManyConnections,
            _ => ApiErrorCode::Unknown,
        }
    }
}

impl ApiErrorCode {
    /// Get human-readable description of the error.
    pub fn description(&self) -> &'static str {
        match self {
            ApiErrorCode::Internal => "Internal error",
            ApiErrorCode::Args => "Invalid arguments",
            ApiErrorCode::Again => "Try again",
            ApiErrorCode::RateLimit => "Rate limit exceeded",
            ApiErrorCode::Failed => "Upload failed",
            ApiErrorCode::TooManyIps => "Too many IPs",
            ApiErrorCode::AccessDenied => "Access denied",
            ApiErrorCode::Exist => "Resource already exists",
            ApiErrorCode::NotExist => "Resource does not exist",
            ApiErrorCode::Circular => "Circular linking",
            ApiErrorCode::AccessViolation => "Access violation",
            ApiErrorCode::AppKey => "Application key required",
            ApiErrorCode::Expired => "Session expired",
            ApiErrorCode::NotConfirmed => "Not confirmed",
            ApiErrorCode::Blocked => "Resource blocked",
            ApiErrorCode::OverQuota => "Over quota",
            ApiErrorCode::TempUnavail => "Temporarily unavailable",
            ApiErrorCode::TooManyConnections => "Too many connections",
            ApiErrorCode::Unknown => "Unknown error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_conversion() {
        // Test specific known codes
        assert_eq!(ApiErrorCode::from(-1), ApiErrorCode::Internal);
        assert_eq!(ApiErrorCode::from(-2), ApiErrorCode::Args);
        assert_eq!(ApiErrorCode::from(-3), ApiErrorCode::Again);
        assert_eq!(ApiErrorCode::from(-4), ApiErrorCode::RateLimit);
        assert_eq!(ApiErrorCode::from(-5), ApiErrorCode::Failed);
        assert_eq!(ApiErrorCode::from(-6), ApiErrorCode::TooManyIps);
        assert_eq!(ApiErrorCode::from(-7), ApiErrorCode::AccessDenied);
        assert_eq!(ApiErrorCode::from(-8), ApiErrorCode::Exist);
        assert_eq!(ApiErrorCode::from(-9), ApiErrorCode::NotExist);
        assert_eq!(ApiErrorCode::from(-10), ApiErrorCode::Circular);
        assert_eq!(ApiErrorCode::from(-11), ApiErrorCode::AccessViolation);
        assert_eq!(ApiErrorCode::from(-12), ApiErrorCode::AppKey);
        assert_eq!(ApiErrorCode::from(-13), ApiErrorCode::Expired);
        assert_eq!(ApiErrorCode::from(-14), ApiErrorCode::NotConfirmed);
        assert_eq!(ApiErrorCode::from(-15), ApiErrorCode::Blocked);
        assert_eq!(ApiErrorCode::from(-16), ApiErrorCode::OverQuota);
        assert_eq!(ApiErrorCode::from(-17), ApiErrorCode::TempUnavail);
        assert_eq!(ApiErrorCode::from(-18), ApiErrorCode::TooManyConnections);

        // Test unknown code
        assert_eq!(ApiErrorCode::from(-999), ApiErrorCode::Unknown);
    }

    #[test]
    fn test_error_code_descriptions() {
        assert_eq!(ApiErrorCode::Internal.description(), "Internal error");
        assert_eq!(ApiErrorCode::Args.description(), "Invalid arguments");
        assert_eq!(ApiErrorCode::Again.description(), "Try again");
        assert_eq!(ApiErrorCode::RateLimit.description(), "Rate limit exceeded");
        assert_eq!(ApiErrorCode::Failed.description(), "Upload failed");
        assert_eq!(ApiErrorCode::TooManyIps.description(), "Too many IPs");
        assert_eq!(ApiErrorCode::AccessDenied.description(), "Access denied");
        assert_eq!(ApiErrorCode::Exist.description(), "Resource already exists");
        assert_eq!(
            ApiErrorCode::NotExist.description(),
            "Resource does not exist"
        );
        assert_eq!(ApiErrorCode::Circular.description(), "Circular linking");
        assert_eq!(
            ApiErrorCode::AccessViolation.description(),
            "Access violation"
        );
        assert_eq!(
            ApiErrorCode::AppKey.description(),
            "Application key required"
        );
        assert_eq!(ApiErrorCode::Expired.description(), "Session expired");
        assert_eq!(ApiErrorCode::NotConfirmed.description(), "Not confirmed");
        assert_eq!(ApiErrorCode::Blocked.description(), "Resource blocked");
        assert_eq!(ApiErrorCode::OverQuota.description(), "Over quota");
        assert_eq!(
            ApiErrorCode::TempUnavail.description(),
            "Temporarily unavailable"
        );
        assert_eq!(
            ApiErrorCode::TooManyConnections.description(),
            "Too many connections"
        );
        assert_eq!(ApiErrorCode::Unknown.description(), "Unknown error");
    }
}
