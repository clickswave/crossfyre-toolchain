//! A UTC time as the CVE data, the data manifest and toolmark's inventory write it.

/// Seconds since 1970 at `t`, a UTC time as `2026-11-21T15:00:00Z`, or none when it is
/// not one.
pub fn unix_time(t: &str) -> Option<i64> {
    let b = t.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' {
        return None;
    }
    if b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let s = t.get(from..to)?;
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())?
    };
    let (y, m, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hh, mm, ss) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    // Days from 1970-01-01 to y-m-d, by Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3_600 + mm * 60 + ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_utc_time_is_read_as_seconds_since_1970() {
        assert_eq!(unix_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix_time("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(unix_time("2026-11-21T15:00:00Z"), Some(1_795_273_200));
        for bad in [
            "2026-11-21",
            "2026-11-21T15:00:00",
            "2026-13-01T00:00:00Z",
            "2026-11-21T24:00:00Z",
            "2026-11-21T15:00:00+05:30",
            "2026-1a-21T15:00:00Z",
        ] {
            assert_eq!(unix_time(bad), None, "{bad}");
        }
    }
}
