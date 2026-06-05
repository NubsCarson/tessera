//! Terminal presentation for the demo. Tokyo Night Storm palette, 24-bit color.
//! Colors degrade gracefully: if stdout is not a TTY (e.g. piped to a file),
//! escapes are still emitted but remain readable.

fn c(rgb: (u8, u8, u8), s: &str) -> String {
    format!("\x1b[38;2;{};{};{}m{s}\x1b[0m", rgb.0, rgb.1, rgb.2)
}
fn bold(s: &str) -> String {
    format!("\x1b[1m{s}\x1b[0m")
}

// Tokyo Night Storm
const FG: (u8, u8, u8) = (192, 202, 245);
const COMMENT: (u8, u8, u8) = (86, 95, 137);
const GREEN: (u8, u8, u8) = (158, 206, 106);
const RED: (u8, u8, u8) = (247, 118, 142);
const YELLOW: (u8, u8, u8) = (224, 175, 104);
const BLUE: (u8, u8, u8) = (122, 162, 247);
const MAGENTA: (u8, u8, u8) = (187, 154, 247);
const CYAN: (u8, u8, u8) = (125, 207, 255);

pub fn banner() {
    let bar = c(
        MAGENTA,
        "────────────────────────────────────────────────────────────",
    );
    println!("\n{bar}");
    println!(
        "  {}  {}",
        bold(&c(CYAN, "TESSERA")),
        c(
            COMMENT,
            "anonymous credentials as a trust layer for the web"
        )
    );
    println!(
        "  {}",
        c(
            FG,
            "admit a request on what it can prove — not on who, or where, it is"
        )
    );
    println!("{bar}");
}

pub fn step(title: &str, detail: &str) {
    println!("\n {} {}", c(BLUE, "▸"), bold(&c(FG, title)));
    println!("   {}", c(COMMENT, detail));
}

pub fn section(title: &str) {
    println!("\n {} {}", c(MAGENTA, "■"), bold(&c(MAGENTA, title)));
}

/// One request result. `ok` decides the check/cross and color.
pub fn result(ok: bool, what: &str, status: u16, detail: &str) {
    let (mark, color) = if ok { ("✓", GREEN) } else { ("✗", RED) };
    let code = if status == 0 {
        c(COMMENT, "—")
    } else if status == 200 {
        c(GREEN, "200")
    } else {
        c(RED, &status.to_string())
    };
    println!(
        "   {} {:<42} {}  {}",
        c(color, mark),
        c(FG, what),
        code,
        c(COMMENT, detail)
    );
}

pub fn summary() {
    let bar = c(
        COMMENT,
        "────────────────────────────────────────────────────────────",
    );
    println!("\n{bar}");
    println!(
        "  {} {}",
        c(GREEN, "✓"),
        bold(&c(
            FG,
            "Every decision came from the credential. The IP was never read."
        ))
    );
    println!(
        "    {}",
        c(
            COMMENT,
            "A site that checks Tessera has no reason to block Tor — so it doesn't have to."
        )
    );
    println!("{bar}");
}

pub fn note(msg: &str) {
    println!("\n   {} {}", c(YELLOW, "·"), c(COMMENT, msg));
}

pub fn tor_line(msg: &str) {
    println!("   {} {}", c(MAGENTA, "🧅"), c(FG, msg));
}
