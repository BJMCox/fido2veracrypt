use super::*;

fn args(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_owned).collect()
}

fn parsed(line: &str) -> Command {
    parse(&args(line)).unwrap()
}

#[test]
fn each_command_parses_with_its_flags() {
    assert_eq!(
        parsed("create s.hc --size 2G --label yubikey"),
        Command::Create {
            container: "s.hc".into(),
            size: 2 << 30,
            label: "yubikey".into()
        }
    );
    assert_eq!(
        parsed("adopt s.hc --label token2"),
        Command::Adopt {
            container: "s.hc".into(),
            label: "token2".into()
        }
    );
    assert_eq!(
        parsed("open s.hc"),
        Command::Open {
            container: "s.hc".into()
        }
    );
    assert_eq!(
        parsed("close --force"),
        Command::Close {
            container: None,
            force: true
        }
    );
    assert_eq!(
        parsed("add-key s.hc --recovery --label spare"),
        Command::AddKey {
            container: "s.hc".into(),
            label: "spare".into(),
            recovery: true
        }
    );
    assert_eq!(
        parsed("remove-key s.hc --label a --label b"),
        Command::RemoveKey {
            container: "s.hc".into(),
            labels: vec!["a".into(), "b".into()]
        }
    );
    assert_eq!(
        parsed("rotate s.hc"),
        Command::Rotate {
            container: "s.hc".into()
        }
    );
    assert_eq!(parsed("status"), Command::Status { container: None });
    assert_eq!(
        parsed("list-keys s.hc"),
        Command::ListKeys {
            container: "s.hc".into()
        }
    );
    assert_eq!(
        parsed("completions bash"),
        Command::Completions { shell: Shell::Bash }
    );
    assert_eq!(parsed("--help"), Command::Help);
    assert_eq!(parsed("--version"), Command::Version);
    assert_eq!(parsed(""), Command::Help);
}

#[test]
fn sizes_take_binary_suffixes() {
    for (text, bytes) in [
        ("512", 512),
        ("4K", 4 << 10),
        ("50m", 50 << 20),
        ("1T", 1 << 40),
    ] {
        assert_eq!(parse_size(text).unwrap(), bytes, "{text}");
    }
    for text in ["", "G", "1.5G", "-1G", "1P", "99999999999T"] {
        assert!(parse_size(text).is_err(), "{text}");
    }
}

#[test]
fn usage_errors_name_the_problem() {
    for line in [
        "create s.hc --label k",
        "create s.hc --size 1G",
        "create --size 1G --label k",
        "open",
        "open a.hc b.hc",
        "open s.hc --force",
        "remove-key s.hc",
        "completions fish",
        "frobnicate",
        "create s.hc --size 1G --label",
        "add-key s.hc --label a --label b",
    ] {
        assert!(parse(&args(line)).is_err(), "{line} was accepted");
    }
}

#[test]
fn the_readme_lists_the_help_text() {
    let readme = include_str!("../../README.md");
    assert!(readme.contains(&format!("```text\n{HELP}```")));
}

#[test]
fn both_completion_scripts_name_every_command_and_flag() {
    let commands = [
        "create",
        "adopt",
        "open",
        "close",
        "add-key",
        "remove-key",
        "rotate",
        "status",
        "list-keys",
        "completions",
        "help",
    ];
    let flags = ["--size", "--label", "--force", "--recovery"];
    for script in [crate::commands::ZSH, crate::commands::BASH] {
        for word in commands.iter().chain(&flags) {
            assert!(script.contains(word), "{word}");
        }
    }
    for command in commands {
        assert!(HELP.contains(&format!("  {command}")), "{command}");
    }
}
