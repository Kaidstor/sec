use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tauri::Manager;

#[derive(Serialize)]
pub struct SecOutput {
    stdout: String,
    stderr: String,
}

/// Путь к бинарю sec: env SEC_BIN → brew (arm/intel) → go install → PATH.
/// GUI-приложение, запущенное из Finder, не наследует brew-PATH шелла,
/// поэтому кандидаты — абсолютные пути, как в raycast-расширении.
fn sec_binary() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("SEC_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
    }
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from("/opt/homebrew/bin/sec"),
        PathBuf::from("/usr/local/bin/sec"),
    ];
    if let Some(home) = dirs_home() {
        candidates.push(home.join("go/bin/sec"));
    }
    for c in candidates {
        if c.is_file() {
            return Ok(c);
        }
    }
    if let Ok(out) = Command::new("which").arg("sec").output() {
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !p.is_empty() {
                return Ok(PathBuf::from(p));
            }
        }
    }
    Err("бинарь sec не найден. Установи: brew install kaidstor/tap/sec — или задай путь в SEC_BIN.".into())
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// die() в CLI пишет "sec: <текст>" в stderr — префикс срезается для показа.
fn clean_stderr(s: &str) -> String {
    s.lines()
        .map(|l| l.strip_prefix("sec: ").unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

#[tauri::command]
async fn run_sec(args: Vec<String>, stdin: Option<String>) -> Result<SecOutput, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let bin = sec_binary()?;
        let mut cmd = Command::new(bin);
        cmd.args(&args)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| format!("запуск sec: {e}"))?;
        if let Some(input) = stdin {
            let mut pipe = child.stdin.take().ok_or("stdin недоступен")?;
            pipe.write_all(input.as_bytes())
                .map_err(|e| format!("stdin sec: {e}"))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("ожидание sec: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if out.status.success() {
            Ok(SecOutput { stdout, stderr })
        } else {
            let msg = clean_stderr(&stderr);
            if msg.is_empty() {
                Err(format!("sec завершился с кодом {}", out.status.code().unwrap_or(-1)))
            } else {
                Err(msg)
            }
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Показывает главное окно на старте: Regular-политика (фокус, Dock) на macOS.
fn reveal_window(app: &tauri::AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

/// Фронтенд вызывает это после первого отрисованного кадра. Окно создаётся
/// скрытым (visible: false), геометрию восстанавливает window-state-плагин —
/// показ готового содержимого убирает «растягивание» окна на старте.
#[tauri::command]
fn reveal_main_window(app: tauri::AppHandle) {
    reveal_window(&app);
}

/// Перезапуск после установки обновления. На macOS — `open -n` на бандл:
/// app.restart() порождает процесс мимо LaunchServices, и новое окно
/// оказывается позади остальных.
#[tauri::command]
fn relaunch_app(app: tauri::AppHandle) {
    #[cfg(target_os = "macos")]
    {
        // …/sec.app/Contents/MacOS/sec → …/sec.app
        let bundle = std::env::current_exe().ok().and_then(|exe| {
            let b = exe.ancestors().nth(3)?;
            b.extension()
                .is_some_and(|e| e == "app")
                .then(|| b.to_path_buf())
        });
        if let Some(bundle) = bundle {
            let spawned = Command::new("open").arg("-n").arg(&bundle).spawn().is_ok();
            if spawned {
                app.exit(0);
                return;
            }
        }
    }
    // Вне бандла (dev-запуск) или не macOS — обычный рестарт.
    app.restart();
}

/// Пункт «sec» в menu-bar: ЛКМ — показать окно, ПКМ — меню (Открыть/Выйти).
#[cfg(target_os = "macos")]
fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    let show = MenuItem::with_id(app, "show", "Открыть sec", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выйти", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;
    TrayIconBuilder::with_id("main")
        // template-иконка обязана быть чёрной с альфой: цвет задаёт сама
        // macOS под тему; цветная картинка станет сплошным силуэтом
        .icon(tauri::include_image!("icons/tray.png"))
        .icon_as_template(true)
        .menu(&menu)
        // ЛКМ открывает окно только пока меню на ЛКМ выключено: с
        // show_menu_on_left_click(true) Click-событие не приходит
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => reveal_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                reveal_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(
            tauri_plugin_window_state::Builder::new()
                .with_state_flags(
                    tauri_plugin_window_state::StateFlags::SIZE
                        | tauri_plugin_window_state::StateFlags::POSITION
                        | tauri_plugin_window_state::StateFlags::MAXIMIZED,
                )
                .build(),
        )
        .setup(|app| {
            #[cfg(target_os = "macos")]
            setup_tray(app)?;
            // страховка: если фронтенд не показал окно (JS-ошибка, зависшая
            // загрузка), показать его самим, чтобы не осталось невидимым
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if let Some(win) = handle.get_webview_window("main") {
                    if !win.is_visible().unwrap_or(true) {
                        reveal_window(&handle);
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![run_sec, reveal_main_window, relaunch_app])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // macOS: крестик прячет окно и убирает приложение из Dock
                // (Accessory), процесс живёт в menu-bar. Выход — из меню трея;
                // Cmd+Q у скрытого Accessory-приложения недоступен.
                #[cfg(target_os = "macos")]
                {
                    api.prevent_close();
                    let _ = window.hide();
                    let _ = window
                        .app_handle()
                        .set_activation_policy(tauri::ActivationPolicy::Accessory);
                }
                #[cfg(not(target_os = "macos"))]
                let _ = (window, api);
            }
        })
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        .run(|_app, _event| {
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = _event {
                reveal_window(_app);
            }
        });
}
