//! Layout of a command APDU: where its data lies and how much response it accepts.

/// Why a command APDU is not well formed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApduError {
    /// The length fields do not match the length of the APDU.
    BadLen,
}

/// Where the data of a command APDU lies, relative to its first byte (CLA), and how much response
/// data it accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ApduLayout {
    /// Offset of the command data.
    pub data_offset: usize,
    /// Length of the command data (Nc).
    pub data_len: usize,
    /// Maximum number of response data bytes (Ne), when the APDU carries an Le field.
    pub le: Option<usize>,
    /// True when the length fields use the extended form.
    pub extended: bool,
}

/// The layout of `apdu`, a whole command APDU from CLA to its last byte.
pub(crate) fn layout(apdu: &[u8]) -> Result<ApduLayout, ApduError> {
    let short = |data_len| ApduLayout {
        data_offset: 5,
        data_len,
        le: None,
        extended: false,
    };
    match apdu.len() {
        0..=3 => Err(ApduError::BadLen),
        4 => Ok(ApduLayout {
            data_offset: 4,
            data_len: 0,
            le: None,
            extended: false,
        }),
        len => match apdu[4] {
            0 if len == 5 => Ok(short(0)),
            0 if len == 6 => Err(ApduError::BadLen),
            0 => {
                let lc = u16::from_be_bytes([apdu[5], apdu[6]]) as usize;
                if len != lc + 7 {
                    return Err(ApduError::BadLen);
                }
                Ok(ApduLayout {
                    data_offset: 7,
                    data_len: lc,
                    le: None,
                    extended: true,
                })
            }
            lc => {
                if len != lc as usize + 5 {
                    return Err(ApduError::BadLen);
                }
                Ok(short(lc as usize))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assert_eq_err as assert_eq;
    use crate::testing::TestType;
    use testmacro::test_item as test;

    // ISO/IEC 7816-4 5.1: case 1 has no body.
    #[test]
    fn case_1() {
        assert_eq!(
            layout(&[0x80, 0x10, 0x00, 0x00]),
            Ok(ApduLayout {
                data_offset: 4,
                data_len: 0,
                le: None,
                extended: false
            })
        );
    }

    // Case 2S: a single Le byte, 0x00 standing for 256.
    #[test]
    fn case_2_short() {
        assert_eq!(
            layout(&[0x00, 0xC0, 0x00, 0x00, 0x10]),
            Ok(ApduLayout {
                data_offset: 5,
                data_len: 0,
                le: Some(16),
                extended: false
            })
        );
        assert_eq!(
            layout(&[0xB0, 0x01, 0x00, 0x00, 0x00]),
            Ok(ApduLayout {
                data_offset: 5,
                data_len: 0,
                le: Some(256),
                extended: false
            })
        );
    }

    // Case 3S: Lc and the data, no Le.
    #[test]
    fn case_3_short() {
        assert_eq!(
            layout(&[0xE0, 0x02, 0x00, 0x00, 0x02, 0xAA, 0xBB]),
            Ok(ApduLayout {
                data_offset: 5,
                data_len: 2,
                le: None,
                extended: false
            })
        );
    }

    // Case 4S: Lc, the data and a final Le byte, as NFC clients send their commands.
    #[test]
    fn case_4_short() {
        assert_eq!(
            layout(&[0x80, 0x10, 0x00, 0x00, 0x01, 0x04, 0x00]),
            Ok(ApduLayout {
                data_offset: 5,
                data_len: 1,
                le: Some(256),
                extended: false
            })
        );
        assert_eq!(
            layout(&[0x80, 0x10, 0x00, 0x00, 0x01, 0x04, 0x20]),
            Ok(ApduLayout {
                data_offset: 5,
                data_len: 1,
                le: Some(32),
                extended: false
            })
        );
    }

    // Case 2E: a zero byte and a two-byte Le, 0x0000 standing for 65536.
    #[test]
    fn case_2_extended() {
        assert_eq!(
            layout(&[0x80, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00]),
            Ok(ApduLayout {
                data_offset: 7,
                data_len: 0,
                le: Some(256),
                extended: true
            })
        );
        assert_eq!(
            layout(&[0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Ok(ApduLayout {
                data_offset: 7,
                data_len: 0,
                le: Some(65536),
                extended: true
            })
        );
    }

    // Case 3E: a zero byte, a two-byte Lc and the data.
    #[test]
    fn case_3_extended() {
        assert_eq!(
            layout(&[0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB]),
            Ok(ApduLayout {
                data_offset: 7,
                data_len: 2,
                le: None,
                extended: true
            })
        );
    }

    // Case 4E: the extended Lc, the data and a two-byte Le.
    #[test]
    fn case_4_extended() {
        assert_eq!(
            layout(&[0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00]),
            Ok(ApduLayout {
                data_offset: 7,
                data_len: 1,
                le: Some(65536),
                extended: true
            })
        );
    }

    // Length fields that disagree with the APDU, and an extended Lc of zero, which no case allows.
    #[test]
    fn bad_lengths() {
        assert_eq!(layout(&[0x80, 0x10, 0x00]), Err(ApduError::BadLen));
        assert_eq!(
            layout(&[0x80, 0x10, 0x00, 0x00, 0x02, 0xAA]),
            Err(ApduError::BadLen)
        );
        assert_eq!(
            layout(&[0x80, 0x10, 0x00, 0x00, 0x01, 0xAA, 0x00, 0x00]),
            Err(ApduError::BadLen)
        );
        assert_eq!(
            layout(&[0x80, 0x10, 0x00, 0x00, 0x00, 0x01]),
            Err(ApduError::BadLen)
        );
        assert_eq!(
            layout(&[0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Err(ApduError::BadLen)
        );
        assert_eq!(
            layout(&[0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x02, 0xAA]),
            Err(ApduError::BadLen)
        );
    }
}
