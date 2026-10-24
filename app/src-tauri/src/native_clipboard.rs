use std::path::Path;
use std::process::{Command, Output, Stdio};

use objc2::rc::autoreleasepool;
use objc2::runtime::ProtocolObject;
use objc2_app_kit::{NSPasteboard, NSPasteboardItem, NSPasteboardTypeString};
use objc2_foundation::{NSArray, NSString};

use super::{clean_stderr, envelope_error, SecOutput};

const CONCEALED: &str = "org.nspasteboard.ConcealedType";

pub(super) fn copy_reference(args: &[String], has_stdin: bool) -> Option<&str> {
    match args {
        [cmd, reference, flag] if !has_stdin && cmd == "get" && flag == "--clip" => Some(reference),
        _ => None,
    }
}

pub(super) fn copy_secret(binary: &Path, reference: &str) -> Result<SecOutput, String> {
    let output = Command::new(binary)
        .args(["get", reference, "--json"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("запуск sec: {e}"))?;
    copy_output(output, |value| {
        write_concealed(&NSPasteboard::generalPasteboard(), value)
    })
}

fn copy_output(
    output: Output,
    write: impl FnOnce(&str) -> Result<(), String>,
) -> Result<SecOutput, String> {
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        let message = clean_stderr(&stderr);
        return Err(if message.is_empty() {
            envelope_error(&String::from_utf8_lossy(&output.stdout)).unwrap_or_else(|| {
                format!(
                    "sec завершился с кодом {}",
                    output.status.code().unwrap_or(-1)
                )
            })
        } else {
            message
        });
    }
    let response: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "sec вернул некорректный JSON при копировании".to_string())?;
    let data = if response.get("v").is_some() {
        if response["v"] != 1
            || response["command"] != "get"
            || response["exit"] != 0
            || !response["error"].is_null()
        {
            return Err("sec вернул ошибку или неподдерживаемый ответ при копировании".into());
        }
        &response["data"]
    } else {
        &response
    };
    let value = data["value"]
        .as_str()
        .ok_or_else(|| "в ответе sec отсутствует текстовое значение".to_string())?;
    write(value)?;
    Ok(SecOutput {
        stdout: "скопировано в буфер обмена (значение не показано)\n".into(),
        stderr,
    })
}

fn write_concealed(pasteboard: &NSPasteboard, value: &str) -> Result<(), String> {
    autoreleasepool(|_| {
        if value.is_empty() {
            pasteboard.clearContents();
            return Ok(());
        }
        let item = NSPasteboardItem::new();
        let text_type = unsafe { NSPasteboardTypeString };
        // Тип защиты должен попасть в тот же item до публикации: менеджер
        // истории может прочитать буфер сразу после writeObjects.
        if !item.setString_forType(&NSString::from_str(value), text_type)
            || !item.setString_forType(&NSString::from_str(""), &NSString::from_str(CONCEALED))
        {
            return Err("не удалось подготовить защищённую запись буфера обмена".into());
        }
        let items = NSArray::from_retained_slice(&[ProtocolObject::from_retained(item)]);
        pasteboard.clearContents();
        if !pasteboard.writeObjects(&items) {
            return Err("не удалось записать буфер обмена".into());
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use objc2::rc::Retained;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    struct TestBoard(Retained<NSPasteboard>);

    impl TestBoard {
        fn new() -> Self {
            Self(NSPasteboard::pasteboardWithUniqueName())
        }
    }

    impl Drop for TestBoard {
        fn drop(&mut self) {
            self.0.clearContents();
        }
    }

    fn output(stdout: &str, stderr: &str, code: i32) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn only_plain_copy_uses_native_clipboard() {
        let args = ["get", "app/K", "--clip"].map(String::from);
        assert_eq!(copy_reference(&args, false), Some("app/K"));
        assert_eq!(copy_reference(&args, true), None);
        for args in [
            vec!["get", "app/K", "--clip", "--once"],
            vec!["get", "app/K", "--clip", "--clear-after", "60s"],
            vec!["get", "app/K", "--clip", "--prev", "1"],
            vec!["get", "app/K", "--json"],
            vec!["otp", "app/K", "--clip"],
        ] {
            assert_eq!(
                copy_reference(
                    &args.into_iter().map(String::from).collect::<Vec<_>>(),
                    false
                ),
                None
            );
        }
    }

    #[test]
    fn copies_exact_value_without_returning_it_to_javascript() {
        for value in ["synthetic-秘密\n\n", "", "embedded\0synthetic"] {
            for response in [
                serde_json::json!({"value": value}),
                serde_json::json!({"v":1,"command":"get","exit":0,"data":{"value":value},"error":null}),
            ] {
                let mut copied = false;
                let result = copy_output(output(&response.to_string(), "", 0), |actual| {
                    assert_eq!(actual, value);
                    copied = true;
                    Ok(())
                })
                .unwrap();
                assert!(copied);
                assert_eq!(
                    result.stdout,
                    "скопировано в буфер обмена (значение не показано)\n"
                );
                assert!(result.stderr.is_empty());
            }
        }
    }

    #[test]
    fn invalid_responses_never_reach_clipboard_or_error_text() {
        for response in [
            "synthetic-private-value-not-json",
            r#"{"value":null,"extra":"synthetic-private-value"}"#,
            r#"{"v":2,"command":"get","exit":0,"data":{"value":"synthetic-private-value"},"error":null}"#,
            r#"{"v":1,"command":"get","exit":2,"data":{"value":"synthetic-private-value"},"error":null}"#,
            r#"{"v":1,"command":"get","exit":0,"data":{},"error":null}"#,
        ] {
            let error = copy_output(output(response, "", 0), |_| {
                panic!("unexpected clipboard write")
            })
            .err()
            .unwrap();
            assert!(!error.contains("synthetic-private-value"));
        }
        let error = copy_output(
            output("synthetic-private-value", "sec: not found", 3),
            |_| panic!("unexpected clipboard write"),
        )
        .err()
        .unwrap();
        assert_eq!(error, "not found");
        let error = copy_output(
            output(
                r#"{"v":1,"command":"get","exit":3,"data":null,"error":{"message":"missing key"}}"#,
                "",
                3,
            ),
            |_| panic!("unexpected clipboard write"),
        )
        .err()
        .unwrap();
        assert_eq!(error, "missing key");
    }

    #[test]
    fn clipboard_failure_is_returned() {
        let error = copy_output(
            output(r#"{"value":"synthetic-private-value"}"#, "", 0),
            |_| Err("clipboard failed".into()),
        )
        .err()
        .unwrap();
        assert_eq!(error, "clipboard failed");
    }

    #[test]
    fn named_pasteboard_contains_text_and_concealed_marker() {
        let board = TestBoard::new();
        for value in ["synthetic-秘密\n\n", "embedded\0synthetic"] {
            write_concealed(&board.0, value).unwrap();
            assert_eq!(
                board
                    .0
                    .stringForType(unsafe { NSPasteboardTypeString })
                    .unwrap()
                    .to_string(),
                value
            );
            assert!(board
                .0
                .dataForType(&NSString::from_str(CONCEALED))
                .is_some());
            assert_eq!(board.0.pasteboardItems().unwrap().len(), 1);
        }
        write_concealed(&board.0, "").unwrap();
        assert!(board
            .0
            .stringForType(unsafe { NSPasteboardTypeString })
            .is_none());
    }

    #[test]
    #[ignore = "requires an isolated synthetic CLI fixture"]
    fn benchmark_native_against_cli_clipboard() {
        use std::time::Instant;

        let binary = std::env::var("SEC_NATIVE_BENCH_CLI").unwrap();
        let name = std::env::var("SEC_NATIVE_BENCH_BOARD").unwrap();
        assert!(name.starts_with("org.kaidstor.sec.perf."));
        let store = std::env::var("SEC_STORE").unwrap();
        assert!(Path::new(&store)
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("sec-native-copy-"));
        assert_eq!(std::env::var("SEC_KEY").unwrap().len(), 64);
        let board = TestBoard(NSPasteboard::pasteboardWithName(&NSString::from_str(&name)));
        let mut cli = Vec::new();
        let mut native = Vec::new();
        for _ in 0..11 {
            let start = Instant::now();
            let old = Command::new(&binary)
                .args(["get", "perf/EXAMPLE", "--clip"])
                .output()
                .unwrap();
            assert!(old.status.success());
            cli.push(start.elapsed().as_secs_f64() * 1000.0);

            let start = Instant::now();
            let output = Command::new(&binary)
                .args(["get", "perf/EXAMPLE", "--json"])
                .output()
                .unwrap();
            let result = copy_output(output, |value| write_concealed(&board.0, value)).unwrap();
            native.push(start.elapsed().as_secs_f64() * 1000.0);
            assert!(!result.stdout.contains("synthetic-clipboard-measurement"));
            assert_eq!(
                board
                    .0
                    .stringForType(unsafe { NSPasteboardTypeString })
                    .unwrap()
                    .to_string(),
                "synthetic-clipboard-measurement"
            );
            assert!(board
                .0
                .dataForType(&NSString::from_str(CONCEALED))
                .is_some());
        }
        cli.sort_by(f64::total_cmp);
        native.sort_by(f64::total_cmp);
        println!(
            "native-copy-benchmark: {}",
            serde_json::json!({"samples":11,"cli_p50_ms":cli[5],"native_p50_ms":native[5],"cli_p95_ms":cli[10],"native_p95_ms":native[10]})
        );
        assert!(
            native[5] < cli[5] * 0.7,
            "native path did not improve clipboard latency"
        );
    }
}
