use super::*;

#[test]
fn a_new_passphrase_is_13_groups_of_4_crockford_characters() {
    let passphrase = Passphrase::generate().unwrap();
    let groups: Vec<&str> = passphrase.as_str().split('-').collect();
    assert_eq!(groups.len(), 13);
    assert!(groups.iter().all(|g| g.len() == 4));
    assert!(
        passphrase
            .as_str()
            .bytes()
            .all(|b| b == b'-' || ALPHABET.contains(&b))
    );
    assert_eq!(passphrase.last_group(), groups[12]);
}

#[test]
fn every_byte_value_maps_to_each_character_equally_often() {
    // 256 is a multiple of 32, so reducing a uniform byte gives a uniform character.
    let mut counts = [0usize; 32];
    for byte in 0..=255u8 {
        let index = ALPHABET.iter().position(|&c| c == symbol(byte)).unwrap();
        counts[index] += 1;
    }
    assert!(counts.iter().all(|&n| n == 8));
}

#[test]
fn typed_input_normalizes_to_the_canonical_form() {
    let canonical = Passphrase::generate().unwrap();
    let typed = canonical.as_str().replace('-', " ").to_lowercase();
    assert_eq!(
        Passphrase::parse(&typed).unwrap().as_str(),
        canonical.as_str()
    );
    let ambiguous = "IL0O-".repeat(13).replace("--", "-");
    let parsed = Passphrase::parse(&ambiguous[..ambiguous.len() - 1]).unwrap();
    assert!(parsed.as_str().starts_with("1100-1100"));
}

#[test]
fn input_of_the_wrong_length_or_alphabet_is_refused() {
    assert!(Passphrase::parse("ABCD-EFGH").is_err());
    assert!(Passphrase::parse(&"U".repeat(52)).is_err());
    assert!(Passphrase::parse(&"A".repeat(53)).is_err());
    assert!(Passphrase::parse(&"A".repeat(52)).is_ok());
}
