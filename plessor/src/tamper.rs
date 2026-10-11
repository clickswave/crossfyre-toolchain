//! Numeric inputs whose computed result has no floor.
//!
//! A quantity multiplied into a total, a price summed into a balance, a count
//! that decides how much is credited. The bug is not that the field accepts a
//! negative number; plenty of fields legitimately do. The bug is that the number
//! is *used* in an arithmetic the application then honours, so a minus sign in a
//! request becomes a minus sign on an invoice.
//!
//! That distinction is the whole design here, because it is what separates this
//! from a wordlist of parameters called `qty`.
//!
//! # Finding the link before testing it
//!
//! The probe does not assume that `quantity` relates to anything. It proves it:
//!
//! 1. The endpoint's own answer, at its own value, is already in hand.
//! 2. Send a second in-domain value and compare. The two bodies are reduced to a
//!    SKELETON (every number replaced by a placeholder) and a list of numbers. If
//!    the skeletons are identical, the nth number of one answers the nth number
//!    of the other by construction, with no guessing about which field is which.
//! 3. A number that moved the way the input moved is the linked value. Scaled if
//!    the input scaled, offset if the input was offset.
//! 4. Send the first value again. The linked number has to come back. A
//!    timestamp, a row id or a hit counter fails this, and that is what it is for.
//!
//! Only then is an out-of-domain value worth sending, and only then does its
//! answer mean anything.
//!
//! # Why the reflection guard matters more than it looks
//!
//! An endpoint that echoes `quantity` back satisfies the scaling test perfectly:
//! send 2 instead of 1 and the echoed number doubles. It is not a computation and
//! it is not a finding. Any candidate whose values are exactly the two inputs is
//! dropped, which leaves the derived numbers, which is the point.

/// A response reduced to the shape that can be compared, plus the numbers pulled
/// out of it in order.
pub struct Reading {
    /// The body with every numeric literal replaced by one placeholder byte.
    /// Two responses with equal skeletons have positionally corresponding
    /// numbers, which is what makes the comparison exact rather than a search.
    pub skeleton: String,
    pub numbers: Vec<f64>,
}

/// The placeholder a number leaves behind. Chosen because it does not occur in
/// an HTTP response body worth comparing.
const HOLE: char = '\u{0}';

/// How the linked number follows the input.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Link {
    /// It scales: total = unit * quantity.
    Scale,
    /// It offsets: balance = base + amount.
    Offset,
}

/// A linked number: which position in the reading, and how it follows.
#[derive(Clone, Copy, Debug)]
pub struct Linked {
    pub index: usize,
    pub how: Link,
}

/// Split a body into its skeleton and its numbers.
///
/// The sign is part of the number, deliberately. A total that goes from `49.99`
/// to `-49.99` must leave the skeleton unchanged, or the one case this check
/// exists to catch would look like a different page.
pub fn read(body: &str) -> Reading {
    let b: Vec<char> = body.chars().collect();
    let mut skeleton = String::with_capacity(body.len());
    let mut numbers = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let starts =
            b[i].is_ascii_digit() || (b[i] == '-' && i + 1 < b.len() && b[i + 1].is_ascii_digit());
        if !starts {
            skeleton.push(b[i]);
            i += 1;
            continue;
        }
        let start = i;
        if b[i] == '-' {
            i += 1;
        }
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i + 1 < b.len() && b[i] == '.' && b[i + 1].is_ascii_digit() {
            i += 1;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
        }
        let text: String = b[start..i].iter().collect();
        match text.parse::<f64>() {
            Ok(n) => {
                numbers.push(n);
                skeleton.push(HOLE);
            }
            // Unparseable (absurdly long); leave it as text so the skeletons of
            // two identical pages still match.
            Err(_) => skeleton.push_str(&text),
        }
    }
    Reading { skeleton, numbers }
}

/// Equal within money-shaped tolerance: half a percent, never tighter than a
/// hundredth. Two renderings of the same computation differ in the last place
/// often enough that exact comparison would lose real findings.
pub fn close(a: f64, b: f64) -> bool {
    if !a.is_finite() || !b.is_finite() {
        return false;
    }
    let scale = a.abs().max(b.abs());
    (a - b).abs() <= (scale * 0.005).max(0.01)
}

/// What the linked number should read for input `v`, given it read `at_v1` for
/// input `v1`.
pub fn predict(how: Link, at_v1: f64, v1: f64, v: f64) -> Option<f64> {
    match how {
        Link::Scale => (v1 != 0.0).then(|| at_v1 * (v / v1)),
        Link::Offset => Some(at_v1 + (v - v1)),
    }
}

/// Which number in these two answers follows the input, if any.
///
/// `a` answered `v1` and `b` answered `v2`. Returns the first position that moved
/// the way the input moved and is not simply the input coming back.
pub fn find_link(a: &Reading, b: &Reading, v1: f64, v2: f64) -> Option<Linked> {
    // Different shapes mean the nth number is not the nth number. Without this
    // the comparison would be a search for any pair that happens to fit, which
    // is how coincidences get reported.
    if a.skeleton != b.skeleton || a.numbers.len() != b.numbers.len() {
        return None;
    }
    if close(v1, v2) {
        return None;
    }
    for (i, (&x, &y)) in a.numbers.iter().zip(b.numbers.iter()).enumerate() {
        if close(x, y) {
            continue;
        }
        // The input echoed back. Perfect correlation, no computation.
        if close(x, v1) && close(y, v2) {
            continue;
        }
        for how in [Link::Scale, Link::Offset] {
            if let Some(want) = predict(how, x, v1, v2) {
                if close(want, y) {
                    return Some(Linked { index: i, how });
                }
            }
        }
    }
    None
}

/// Values outside any sane domain for a quantity or an amount, with the name to
/// report them by.
///
/// Negative first: it is the one whose consequence needs no explaining. Zero
/// second, because a zero-priced order is a real finding and a surprising number
/// of checkouts allow it.
pub fn out_of_domain(v1: f64) -> Vec<(&'static str, f64)> {
    vec![("negative", -(v1.abs().max(1.0))), ("zero", 0.0)]
}

/// Is this value outside the domain the application should have enforced, for
/// the linked number rather than for the input?
///
/// A total that stays positive when the quantity went negative means the
/// application clamped, which is the correct behaviour and not a finding.
pub fn followed_out(how: Link, at_v1: f64, v1: f64, v_bad: f64, observed: f64) -> bool {
    let Some(want) = predict(how, at_v1, v1, v_bad) else {
        return false;
    };
    if !close(want, observed) {
        return false;
    }
    // And the result really is out of domain: negative, or zero where the
    // ordinary answer was not.
    observed < 0.0 || (close(observed, 0.0) && !close(at_v1, 0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sign_change_does_not_change_the_shape() {
        let a = read(r#"{"qty":1,"total":49.99}"#);
        let b = read(r#"{"qty":-1,"total":-49.99}"#);
        assert_eq!(
            a.skeleton, b.skeleton,
            "a minus sign must not look like a different page"
        );
        assert_eq!(a.numbers, vec![1.0, 49.99]);
        assert_eq!(b.numbers, vec![-1.0, -49.99]);
    }

    #[test]
    fn a_scaled_total_is_found_and_the_echoed_input_is_not() {
        let a = read(r#"{"quantity":2,"unit":25.0,"total":50.0}"#);
        let b = read(r#"{"quantity":4,"unit":25.0,"total":100.0}"#);
        let l = find_link(&a, &b, 2.0, 4.0).expect("total should link to quantity");
        // Index 0 is the echoed quantity and index 1 never moved, so it is the
        // total at index 2.
        assert_eq!(l.index, 2);
        assert_eq!(l.how, Link::Scale);
    }

    #[test]
    fn an_offset_balance_is_found() {
        let a = read(r#"{"amount":10,"balance":110}"#);
        let b = read(r#"{"amount":30,"balance":130}"#);
        let l = find_link(&a, &b, 10.0, 30.0).unwrap();
        assert_eq!(l.index, 1);
        assert_eq!(l.how, Link::Offset);
    }

    #[test]
    fn an_endpoint_that_only_echoes_the_input_links_to_nothing() {
        let a = read(r#"{"quantity":2}"#);
        let b = read(r#"{"quantity":4}"#);
        assert!(find_link(&a, &b, 2.0, 4.0).is_none());
    }

    #[test]
    fn a_page_that_changed_shape_is_not_compared() {
        let a = read(r#"{"total":50.0}"#);
        let b = read(r#"{"error":"bad quantity","total":50.0}"#);
        assert!(find_link(&a, &b, 2.0, 4.0).is_none());
    }

    #[test]
    fn a_number_that_moves_for_its_own_reasons_is_not_a_link() {
        // A hit counter. It moved, but not the way the input moved.
        let a = read(r#"{"views":1000,"total":50.0}"#);
        let b = read(r#"{"views":1001,"total":50.0}"#);
        assert!(find_link(&a, &b, 2.0, 4.0).is_none());
    }

    #[test]
    fn a_clamped_total_is_correct_behaviour() {
        // quantity -1 against a unit price of 25: an unclamped total is -25.
        assert!(followed_out(Link::Scale, 50.0, 2.0, -1.0, -25.0));
        // The application floored it at zero... which is still zero, and zero
        // where the ordinary answer was not is its own finding, so check a
        // genuinely clamped one instead.
        assert!(!followed_out(Link::Scale, 50.0, 2.0, -1.0, 50.0));
    }

    #[test]
    fn zero_counts_only_when_the_ordinary_answer_was_not_zero() {
        assert!(followed_out(Link::Scale, 50.0, 2.0, 0.0, 0.0));
        assert!(!followed_out(Link::Scale, 0.0, 2.0, 0.0, 0.0));
    }

    #[test]
    fn out_of_domain_values_are_out_of_domain() {
        let v = out_of_domain(3.0);
        assert_eq!(v[0].1, -3.0);
        assert_eq!(v[1].1, 0.0);
        // And a baseline of zero still produces a negative to try.
        assert!(out_of_domain(0.0)[0].1 < 0.0);
    }
}
