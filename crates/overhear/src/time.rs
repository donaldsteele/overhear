use jiff::tz::TimeZone;
use jiff::{Timestamp, ZonedDateTime};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeStyle {
    Time,
    DateTime,
}

fn zoned(sec: i64, usec: u32, tz: &TimeZone) -> Option<ZonedDateTime> {
    let nanos = i32::try_from(usec.min(999_999) * 1000).ok()?;
    Some(
        Timestamp::new(sec, nanos)
            .ok()?
            .to_zoned_datetime(tz.clone()),
    )
}

fn millis(usec: u32) -> u32 {
    usec.min(999_999) / 1000
}

pub fn format_line(sec: i64, usec: u32, tz: &TimeZone, style: TimeStyle) -> String {
    let Some(z) = zoned(sec, usec, tz) else {
        return format!("@{sec}.{:03}", millis(usec));
    };
    let fmt = match style {
        TimeStyle::Time => "%H:%M:%S",
        TimeStyle::DateTime => "%Y-%m-%d %H:%M:%S",
    };
    format!("{}.{:03}", z.strftime(fmt), millis(usec))
}

pub fn format_iso(sec: i64, usec: u32, tz: &TimeZone) -> Option<String> {
    let z = zoned(sec, usec, tz)?;
    Some(format!(
        "{}.{:03}{}",
        z.strftime("%Y-%m-%dT%H:%M:%S"),
        millis(usec),
        z.strftime("%:z")
    ))
}

/// Exact decimal `sec + usec/1e6`, no floating point.
pub fn format_ts(sec: i64, usec: u32) -> String {
    let total = i128::from(sec) * 1_000_000 + i128::from(usec.min(999_999));
    let sign = if total < 0 { "-" } else { "" };
    let abs = total.unsigned_abs();
    format!("{sign}{}.{:06}", abs / 1_000_000, abs % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        let tz = TimeZone::fixed(jiff::tz::offset(1));
        assert_eq!(
            format_line(1795266131, 204123, &tz, TimeStyle::Time),
            "14:02:11.204"
        );
        assert_eq!(
            format_line(1795266131, 204123, &tz, TimeStyle::DateTime),
            "2026-11-21 14:02:11.204"
        );
        assert_eq!(
            format_iso(1795266131, 204123, &tz).as_deref(),
            Some("2026-11-21T14:02:11.204+01:00")
        );
        assert_eq!(
            format_iso(1795266131, 204123, &TimeZone::UTC).as_deref(),
            Some("2026-11-21T13:02:11.204+00:00")
        );
        assert_eq!(format_ts(1795266131, 204123), "1795266131.204123");
        assert_eq!(format_ts(-5, 500000), "-4.500000");
        assert_eq!(
            format_line(i64::MAX / 2, 204123, &tz, TimeStyle::Time),
            "@4611686018427387903.204"
        );
        assert_eq!(format_iso(i64::MAX / 2, 0, &tz), None);
        assert_eq!(
            format_line(1795266131, 5_000_000, &tz, TimeStyle::Time),
            "14:02:11.999"
        );
    }
}
