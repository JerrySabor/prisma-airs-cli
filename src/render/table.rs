//! The TypeScript table (`formatOutput(rows, columns, 'table')`, R§2.3), padded by
//! display width instead of UTF-16 units (D53). Never coloured, never wrapped.

use super::width;

/// The table for `labels` over `rows` (cell texts from [`super::cell_text`]), without
/// a final newline. No rows → the empty string.
pub fn table(labels: &[&str], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let widths: Vec<usize> = labels
        .iter()
        .enumerate()
        .map(|(index, label)| {
            rows.iter()
                .map(|row| row.get(index).map_or(0, |cell| width(cell)))
                .fold(width(label), usize::max)
        })
        .collect();
    let line = |cells: &mut dyn Iterator<Item = &str>| -> String {
        cells
            .zip(&widths)
            .map(|(cell, &column)| {
                let pad = column.saturating_sub(width(cell));
                format!(" {cell}{} ", " ".repeat(pad))
            })
            .collect::<Vec<_>>()
            .join("│")
    };
    let mut lines = Vec::with_capacity(rows.len() + 2);
    lines.push(line(&mut labels.iter().copied()));
    lines.push(
        widths
            .iter()
            .map(|column| "─".repeat(column + 2))
            .collect::<Vec<_>>()
            .join("┼"),
    );
    for row in rows {
        let mut cells = (0..labels.len()).map(|index| row.get(index).map_or("", String::as_str));
        lines.push(line(&mut cells));
    }
    lines.join("\n")
}

/// A `Key │ Value` table of `(key, cell text)` rows (detail tables, `tenant read`).
pub fn key_value_table(rows: Vec<(String, String)>) -> String {
    let rows: Vec<Vec<String>> = rows
        .into_iter()
        .map(|(key, value)| vec![key, value])
        .collect();
    table(&["Key", "Value"], &rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(cells: &[&[&str]]) -> Vec<Vec<String>> {
        cells
            .iter()
            .map(|row| row.iter().map(|cell| (*cell).to_owned()).collect())
            .collect()
    }

    const PROFILE_COLUMNS: [&str; 4] = ["ID", "Name", "Active", "Revision"];

    /// R§3.1, captured from the TypeScript CLI.
    #[test]
    fn golden_profile_list() {
        let text = table(
            &PROFILE_COLUMNS,
            &rows(&[
                &["00000000-0000-4000-8000-000000000002", "alpha", "true", "2"],
                &["00000000-0000-4000-8000-000000000003", "beta", "true", "1"],
            ]),
        );
        assert_eq!(
            format!("{text}\n"),
            " ID                                   │ Name  │ Active │ Revision \n──────────────────────────────────────┼───────┼────────┼──────────\n 00000000-0000-4000-8000-000000000002 │ alpha │ true   │ 2        \n 00000000-0000-4000-8000-000000000003 │ beta  │ true   │ 1        \n"
        );
    }

    /// R§3.1 number formatting; the control-character row is D52 (the caller's
    /// `cell_text` replaces them, so the widths stay those of TS).
    #[test]
    fn golden_profile_numbers_and_replaced_controls() {
        let text = table(
            &PROFILE_COLUMNS,
            &rows(&[
                &[
                    "00000000-0000-4000-8000-000000000031",
                    "frac-rev",
                    "true",
                    "2.5",
                ],
                &[
                    "00000000-0000-4000-8000-000000000032",
                    "huge-rev",
                    "true",
                    "1e+21",
                ],
                &[
                    "00000000-0000-4000-8000-000000000033",
                    "ctl\u{fffd}[31mred\u{fffd}tab",
                    "true",
                    "1",
                ],
            ]),
        );
        assert_eq!(
            format!("{text}\n"),
            " ID                                   │ Name            │ Active │ Revision \n──────────────────────────────────────┼─────────────────┼────────┼──────────\n 00000000-0000-4000-8000-000000000031 │ frac-rev        │ true   │ 2.5      \n 00000000-0000-4000-8000-000000000032 │ huge-rev        │ true   │ 1e+21    \n 00000000-0000-4000-8000-000000000033 │ ctl\u{fffd}[31mred\u{fffd}tab │ true   │ 1        \n"
        );
    }

    /// R§3.1 edge rows: an empty ID cell and an empty Active cell (TS bytes); the
    /// wide row is padded by display width (D53).
    #[test]
    fn golden_profile_edges_and_display_width() {
        let long = "a-very-long-security-profile-name-that-goes-on-and-on-for-a-while-0123456789";
        let text = table(
            &PROFILE_COLUMNS,
            &rows(&[
                &["", "no-id-inactive", "false", ""],
                &[
                    "00000000-0000-4000-8000-000000000010",
                    "no-active-field",
                    "",
                    "0",
                ],
                &["00000000-0000-4000-8000-000000000005", long, "true", "3"],
                &[
                    "00000000-0000-4000-8000-000000000006",
                    "prøfile-日本語-🚀",
                    "true",
                    "1",
                ],
            ]),
        );
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(
            lines[2],
            "                                      │ no-id-inactive                                                               │ false  │          "
        );
        assert_eq!(
            lines[3],
            " 00000000-0000-4000-8000-000000000010 │ no-active-field                                                              │        │ 0        "
        );
        // 76 columns wide: 17 visible columns of text plus 59 spaces.
        assert_eq!(
            lines[5],
            format!(
                " 00000000-0000-4000-8000-000000000006 │ prøfile-日本語-🚀{} │ true   │ 1        ",
                " ".repeat(76 - 17)
            )
        );
        let header_width = width(lines[0]);
        assert!(
            lines.iter().all(|line| width(line) == header_width),
            "aligned"
        );
    }

    /// R§3.5: `tenant list`.
    #[test]
    fn golden_tenant_list() {
        let text = table(
            &["Tenant", "Selected", "TSG ID", "Config file"],
            &rows(&[
                &["prod", "true", "100", "/r/configs/prod.json"],
                &[
                    "a-much-longer-tenant-name",
                    "false",
                    "7",
                    "/r/a/much/longer/path/to/configs/staging.json",
                ],
            ]),
        );
        assert_eq!(
            format!("{text}\n"),
            " Tenant                    │ Selected │ TSG ID │ Config file                                   \n───────────────────────────┼──────────┼────────┼───────────────────────────────────────────────\n prod                      │ true     │ 100    │ /r/configs/prod.json                          \n a-much-longer-tenant-name │ false    │ 7      │ /r/a/much/longer/path/to/configs/staging.json \n"
        );
    }

    /// R§3.7: `tenant get --output table`, including the unset key's empty cell.
    #[test]
    fn golden_key_value_tables() {
        assert_eq!(
            key_value_table(vec![("mgmtTsgId".into(), "100".into())]),
            " Key       │ Value \n───────────┼───────\n mgmtTsgId │ 100   "
        );
        assert_eq!(
            key_value_table(vec![("mgmtClientSecret".into(), "[REDACTED]".into())]),
            " Key              │ Value      \n──────────────────┼────────────\n mgmtClientSecret │ [REDACTED] "
        );
        assert_eq!(
            key_value_table(vec![("defaultOutput".into(), String::new())]),
            " Key           │ Value \n───────────────┼───────\n defaultOutput │       "
        );
    }

    /// R§3.4: the topic detail table.
    #[test]
    fn golden_topic_detail() {
        let text = key_value_table(
            [
                ("topicId", "00000000-0000-4000-8000-000000000022"),
                ("topicName", "no-examples"),
                ("revision", "1"),
                ("active", ""),
                ("description", ""),
                ("examples", "[]"),
                ("createdBy", ""),
                ("updatedBy", ""),
                ("lastModifiedTs", ""),
                ("createdTs", ""),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
        );
        assert_eq!(
            format!("{text}\n"),
            " Key            │ Value                                \n────────────────┼──────────────────────────────────────\n topicId        │ 00000000-0000-4000-8000-000000000022 \n topicName      │ no-examples                          \n revision       │ 1                                    \n active         │                                      \n description    │                                      \n examples       │ []                                   \n createdBy      │                                      \n updatedBy      │                                      \n lastModifiedTs │                                      \n createdTs      │                                      \n"
        );
    }

    #[test]
    fn empty_rows_render_nothing_and_lines_end_with_a_space() {
        assert_eq!(table(&["A"], &[]), "");
        let text = table(&["A", "Bee"], &rows(&[&["x", ""]]));
        assert_eq!(text, " A │ Bee \n───┼─────\n x │     ");
        let lines: Vec<&str> = text.split('\n').collect();
        assert!(lines[0].starts_with(' ') && lines[0].ends_with(' '));
        assert!(!lines[1].starts_with(' ') && !lines[1].ends_with(' '));
        assert_eq!(lines[1].chars().count(), lines[0].chars().count());
    }
}
