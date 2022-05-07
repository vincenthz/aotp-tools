use aotp::OTP;
use otpauth::{
    migration_payload::{Algorithm, DigitCount, OtpParameters},
    MigrationPayload,
};
use prost::Message;
use thiserror::*;
use url::Url;

pub mod otpauth {
    include!(concat!(env!("OUT_DIR"), "/otp.migration.rs"));
}

#[derive(Debug, Error)]
pub enum OtpMigrationError {
    #[error("cannot parse QR code as URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("invalid or unknown scheme : {0}")]
    InvalidScheme(String),
    #[error("invalid base64 data: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("invalid base64 data: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),
}

pub fn try_one(url: &Url) -> Result<Vec<MigrationPayload>, OtpMigrationError> {
    if url.scheme() != "otpauth-migration" {
        return Err(OtpMigrationError::InvalidScheme(url.scheme().to_string()));
    }
    let mut pairs = url.query_pairs();
    let mut found = Vec::new();
    while let Some(pair) = pairs.next() {
        // skip all non `data=...` pairs
        if pair.0 != "data" {
            continue;
        }

        // decode with BASE64, then protobuf
        let decoded = base64::decode(pair.1.as_bytes())?;
        let payload = otpauth::MigrationPayload::decode(bytes::Bytes::from(decoded))?;

        // append to found all successfully decoded value
        found.push(payload)
    }
    Ok(found)
}

pub fn to_url(payloads: &[MigrationPayload]) -> Url {
    let mut url = Url::parse("otpauth-migration://offline").unwrap();
    {
        let mut url_pairs = url.query_pairs_mut();
        url_pairs.clear();
        for payload in payloads {
            let payload_serialized = payload.encode_to_vec();
            let value = base64::encode_config(
                payload_serialized,
                base64::Config::new(base64::CharacterSet::Standard, false),
            );
            url_pairs.append_pair("data", &value);
        }
        let _ = url_pairs.finish();
    }
    url
}

#[derive(Debug, Error)]
pub enum OtpConvertionError {
    #[error("unknown algorithm integral {0}")]
    UnknownAlgorithm(i32),
    #[error("unknown digits integral {0}")]
    UnknownDigits(i32),
    #[error("MD5 not supported")]
    MD5NotSupported,
}

pub fn params_to_otp(params: &OtpParameters) -> Result<OTP, OtpConvertionError> {
    let alg = Algorithm::from_i32(params.algorithm)
        .ok_or(OtpConvertionError::UnknownAlgorithm(params.algorithm))?;
    let digits = DigitCount::from_i32(params.digits)
        .ok_or(OtpConvertionError::UnknownDigits(params.digits))?;
    /*
    let otp_type =
        OtpType::from_i32(params.r#type).ok_or(OtpConvertionError::UnknownType(params.r#type))?;
        */

    let alg = match alg {
        Algorithm::Unspecified => return Err(OtpConvertionError::UnknownAlgorithm(0)),
        Algorithm::Md5 => {
            return Err(OtpConvertionError::MD5NotSupported);
        }
        Algorithm::Sha1 => aotp::Algorithm::Sha1,
        Algorithm::Sha256 => aotp::Algorithm::Sha256,
        Algorithm::Sha512 => aotp::Algorithm::Sha512,
    };

    let digits = match digits {
        DigitCount::Unspecified => return Err(OtpConvertionError::UnknownDigits(0)),
        DigitCount::Six => 6,
        DigitCount::Eight => 8,
    };

    Ok(aotp::OTP {
        issuer: params.issuer.clone(),
        account: if params.name == "" {
            None
        } else {
            Some(params.name.clone())
        },
        secret: params.secret.clone(),
        algorithm: alg,
        period: aotp::Period::seconds30(),
        digits,
    })
}
