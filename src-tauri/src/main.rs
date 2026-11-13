#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(all(windows, feature = "vpn-client"))]
mod clipboard;
#[cfg(all(windows, feature = "vpn-client"))]
mod hello_unlock;

#[cfg(all(windows, feature = "vpn-client"))]
fn installed_window(window: &tauri::WebviewWindow) -> Result<isize, String> {
    let origin = window.url().ok().map(|url| url.origin().ascii_serialization());
    if window.label() != "main" || origin.as_deref() != Some("https://tauri.localhost") {
        return Err("This action requires the installed Vault.".into());
    }
    Ok(window.hwnd().map_err(|_| "No application window")?.0 as isize)
}

#[cfg(all(windows, feature = "vpn-client"))]
#[tauri::command]
async fn hello_enroll(window: tauri::WebviewWindow, input: Vec<u8>) -> Result<String, String> {
    let handle = installed_window(&window)?;
    tauri::async_runtime::spawn_blocking(move || hello_unlock::enroll(handle, input))
        .await.map_err(|_| "Windows Hello could not start.".to_string())?
}

#[cfg(all(windows, feature = "vpn-client"))]
#[tauri::command]
async fn hello_evaluate(window: tauri::WebviewWindow, credential_id: String, input: Vec<u8>) -> Result<tauri::ipc::Response, String> {
    let handle = installed_window(&window)?;
    let secret = tauri::async_runtime::spawn_blocking(move || hello_unlock::evaluate(handle, &credential_id, input))
        .await.map_err(|_| "Windows Hello could not start.".to_string())??;
    Ok(tauri::ipc::Response::new(secret.to_vec()))
}

#[cfg(all(windows, feature = "vpn-client"))]
#[tauri::command]
async fn copy_to_windows_clipboard(window: tauri::WebviewWindow, value: String, seconds: u64) -> Result<(), String> {
    use tauri::Manager;
    installed_window(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        window.state::<clipboard::Clipboard>().copy(&window, value, seconds)
    })
    .await
    .map_err(|_| "Could not copy to the Windows clipboard.".to_string())?
}

#[cfg(all(windows, feature = "vpn-client"))]
fn setup_tray(app: &tauri::App, window: tauri::WebviewWindow) -> tauri::Result<()> {
    use tauri::{
        menu::{Menu, MenuItem},
        tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
        WindowEvent,
    };

    fn show(window: &tauri::WebviewWindow) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }

    let show_item = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
    let exit_item = MenuItem::with_id(app, "exit", "Exit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show_item, &exit_item])?;
    let menu_window = window.clone();
    let click_window = window.clone();
    let tray = TrayIconBuilder::with_id("voltura-vault")
        .menu(&menu)
        .tooltip("Voltura Vault")
        .show_menu_on_left_click(false)
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "show" => show(&menu_window),
            "exit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(move |_, event| {
            if matches!(event, TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. }) {
                show(&click_window);
            }
        });
    let tray = match app.default_window_icon() {
        Some(icon) => tray.icon(icon.clone()),
        None => tray,
    };
    tray.build(app)?;

    let close_window = window.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::CloseRequested { api, .. } = event {
            if close_window.hide().is_ok() {
                api.prevent_close();
                let _ = close_window.eval("window.dispatchEvent(new Event('vault-tray-hide'))");
            }
        }
    });
    Ok(())
}

#[cfg(not(feature = "vpn-client"))]
fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("Vault application could not start");
}

#[cfg(feature = "vpn-client")]
fn main() {
    let builder = tauri::Builder::default();
    #[cfg(windows)]
    let builder = builder
        .manage(clipboard::Clipboard::default())
        .invoke_handler(tauri::generate_handler![hello_enroll, hello_evaluate, copy_to_windows_clipboard]);
    builder
        .setup(|app| {
            let window = &app.config().app.windows[0];
            let _window = tauri::WebviewWindowBuilder::from_config(app.handle(), window)?
                .on_navigation(|url| {
                    let bundled_scheme = if cfg!(windows) { "https" } else { "tauri" };
                    let bundled_host = if cfg!(windows) { "tauri.localhost" } else { "localhost" };
                    let bundled_port = if cfg!(windows) { Some(443) } else { None };
                    (url.scheme() == bundled_scheme
                        && url.host_str() == Some(bundled_host)
                        && url.port_or_known_default() == bundled_port
                        && url.username().is_empty()
                        && url.password().is_none())
                        || url.as_str().starts_with(if cfg!(windows) {
                            "blob:https://tauri.localhost/"
                        } else {
                            "blob:tauri://localhost/"
                        })
                })
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .build()?;
            #[cfg(windows)]
            setup_tray(app, _window)?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("Vault application could not start")
        .run(|_app, _event| {
            #[cfg(windows)]
            if matches!(_event, tauri::RunEvent::ExitRequested { .. }) {
                use tauri::Manager;
                let clipboard = _app.state::<clipboard::Clipboard>();
                for attempt in 0..5 {
                    if clipboard.expire(None) { break; }
                    if attempt < 4 {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
        });
}
