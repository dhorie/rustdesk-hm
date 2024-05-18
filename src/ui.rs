use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAABGdBTUEAALGPC/xhBQAACklpQ0NQc1JHQiBJRUM2MTk2Ni0yLjEAAEiJnVN3WJP3Fj7f92UPVkLY8LGXbIEAIiOsCMgQWaIQkgBhhBASQMWFiApWFBURnEhVxILVCkidiOKgKLhnQYqIWotVXDjuH9yntX167+3t+9f7vOec5/zOec8PgBESJpHmomoAOVKFPDrYH49PSMTJvYACFUjgBCAQ5svCZwXFAADwA3l4fnSwP/wBr28AAgBw1S4kEsfh/4O6UCZXACCRAOAiEucLAZBSAMguVMgUAMgYALBTs2QKAJQAAGx5fEIiAKoNAOz0ST4FANipk9wXANiiHKkIAI0BAJkoRyQCQLsAYFWBUiwCwMIAoKxAIi4EwK4BgFm2MkcCgL0FAHaOWJAPQGAAgJlCLMwAIDgCAEMeE80DIEwDoDDSv+CpX3CFuEgBAMDLlc2XS9IzFLiV0Bp38vDg4iHiwmyxQmEXKRBmCeQinJebIxNI5wNMzgwAABr50cH+OD+Q5+bk4eZm52zv9MWi/mvwbyI+IfHf/ryMAgQAEE7P79pf5eXWA3DHAbB1v2upWwDaVgBo3/ldM9sJoFoK0Hr5i3k4/EAenqFQyDwdHAoLC+0lYqG9MOOLPv8z4W/gi372/EAe/tt68ABxmkCZrcCjg/1xYW52rlKO58sEQjFu9+cj/seFf/2OKdHiNLFcLBWK8ViJuFAiTcd5uVKRRCHJleIS6X8y8R+W/QmTdw0ArIZPwE62B7XLbMB+7gECiw5Y0nYAQH7zLYwaC5EAEGc0Mnn3AACTv/mPQCsBAM2XpOMAALzoGFyolBdMxggAAESggSqwQQcMwRSswA6cwR28wBcCYQZEQAwkwDwQQgbkgBwKoRiWQRlUwDrYBLWwAxqgEZrhELTBMTgN5+ASXIHrcBcGYBiewhi8hgkEQcgIE2EhOogRYo7YIs4IF5mOBCJhSDSSgKQg6YgUUSLFyHKkAqlCapFdSCPyLXIUOY1cQPqQ28ggMor8irxHMZSBslED1AJ1QLmoHxqKxqBz0XQ0D12AlqJr0Rq0Hj2AtqKn0UvodXQAfYqOY4DRMQ5mjNlhXIyHRWCJWBomxxZj5Vg1Vo81Yx1YN3YVG8CeYe8IJAKLgBPsCF6EEMJsgpCQR1hMWEOoJewjtBK6CFcJg4Qxwicik6hPtCV6EvnEeGI6sZBYRqwm7iEeIZ4lXicOE1+TSCQOyZLkTgohJZAySQtJa0jbSC2kU6Q+0hBpnEwm65Btyd7kCLKArCCXkbeQD5BPkvvJw+S3FDrFiOJMCaIkUqSUEko1ZT/lBKWfMkKZoKpRzame1AiqiDqfWkltoHZQL1OHqRM0dZolzZsWQ8ukLaPV0JppZ2n3aC/pdLoJ3YMeRZfQl9Jr6Afp5+mD9HcMDYYNg8dIYigZaxl7GacYtxkvmUymBdOXmchUMNcyG5lnmA+Yb1VYKvYqfBWRyhKVOpVWlX6V56pUVXNVP9V5qgtUq1UPq15WfaZGVbNQ46kJ1Bar1akdVbupNq7OUndSj1DPUV+jvl/9gvpjDbKGhUaghkijVGO3xhmNIRbGMmXxWELWclYD6yxrmE1iW7L57Ex2Bfsbdi97TFNDc6pmrGaRZp3mcc0BDsax4PA52ZxKziHODc57LQMtPy2x1mqtZq1+rTfaetq+2mLtcu0W7eva73VwnUCdLJ31Om0693UJuja6UbqFutt1z+o+02PreekJ9cr1Dund0Uf1bfSj9Rfq79bv0R83MDQINpAZbDE4Y/DMkGPoa5hpuNHwhOGoEctoupHEaKPRSaMnuCbuh2fjNXgXPmasbxxirDTeZdxrPGFiaTLbpMSkxeS+Kc2Ua5pmutG003TMzMgs3KzYrMnsjjnVnGueYb7ZvNv8jYWlRZzFSos2i8eW2pZ8ywWWTZb3rJhWPlZ5VvVW16xJ1lzrLOtt1ldsUBtXmwybOpvLtqitm63Edptt3xTiFI8p0in1U27aMez87ArsmuwG7Tn2YfYl9m32zx3MHBId1jt0O3xydHXMdmxwvOuk4TTDqcSpw+lXZxtnoXOd8zUXpkuQyxKXdpcXU22niqdun3rLleUa7rrStdP1o5u7m9yt2W3U3cw9xX2r+00umxvJXcM970H08PdY4nHM452nm6fC85DnL152Xlle+70eT7OcJp7WMG3I28Rb4L3Le2A6Pj1l+s7pAz7GPgKfep+Hvqa+It89viN+1n6Zfgf8nvs7+sv9j/i/4XnyFvFOBWABwQHlAb2BGoGzA2sDHwSZBKUHNQWNBbsGLww+FUIMCQ1ZH3KTb8AX8hv5YzPcZyya0RXKCJ0VWhv6MMwmTB7WEY6GzwjfEH5vpvlM6cy2CIjgR2yIuB9pGZkX+X0UKSoyqi7qUbRTdHF09yzWrORZ+2e9jvGPqYy5O9tqtnJ2Z6xqbFJsY+ybuIC4qriBeIf4RfGXEnQTJAntieTE2MQ9ieNzAudsmjOc5JpUlnRjruXcorkX5unOy553PFk1WZB8OIWYEpeyP+WDIEJQLxhP5aduTR0T8oSbhU9FvqKNolGxt7hKPJLmnVaV9jjdO31D+miGT0Z1xjMJT1IreZEZkrkj801WRNberM/ZcdktOZSclJyjUg1plrQr1zC3KLdPZisrkw3keeZtyhuTh8r35CP5c/PbFWyFTNGjtFKuUA4WTC+oK3hbGFt4uEi9SFrUM99m/ur5IwuCFny9kLBQuLCz2Lh4WfHgIr9FuxYji1MXdy4xXVK6ZHhp8NJ9y2jLspb9UOJYUlXyannc8o5Sg9KlpUMrglc0lamUycturvRauWMVYZVkVe9ql9VbVn8qF5VfrHCsqK74sEa45uJXTl/VfPV5bdra3kq3yu3rSOuk626s91m/r0q9akHV0IbwDa0b8Y3lG19tSt50oXpq9Y7NtM3KzQM1YTXtW8y2rNvyoTaj9nqdf13LVv2tq7e+2Sba1r/dd3vzDoMdFTve75TsvLUreFdrvUV99W7S7oLdjxpiG7q/5n7duEd3T8Wej3ulewf2Re/ranRvbNyvv7+yCW1SNo0eSDpw5ZuAb9qb7Zp3tXBaKg7CQeXBJ9+mfHvjUOihzsPcw83fmX+39QjrSHkr0jq/dawto22gPaG97+iMo50dXh1Hvrf/fu8x42N1xzWPV56gnSg98fnkgpPjp2Snnp1OPz3Umdx590z8mWtdUV29Z0PPnj8XdO5Mt1/3yfPe549d8Lxw9CL3Ytslt0utPa49R35w/eFIr1tv62X3y+1XPK509E3rO9Hv03/6asDVc9f41y5dn3m978bsG7duJt0cuCW69fh29u0XdwruTNxdeo94r/y+2v3qB/oP6n+0/rFlwG3g+GDAYM/DWQ/vDgmHnv6U/9OH4dJHzEfVI0YjjY+dHx8bDRq98mTOk+GnsqcTz8p+Vv9563Or59/94vtLz1j82PAL+YvPv655qfNy76uprzrHI8cfvM55PfGm/K3O233vuO+638e9H5ko/ED+UPPR+mPHp9BP9z7nfP78L/eE8/stRzjPAAAAIGNIUk0AAHomAACAhAAA+gAAAIDoAAB1MAAA6mAAADqYAAAXcJy6UTwAAAAJcEhZcwAAD2EAAA9hAag/p2kAABlLSURBVHic7V1rrCXFcf56zrn73rDECeyahV2eixdsJwZF/hEhgx3sWOFHgAQbot3INrYxsRUpEAsTYRQCIhaxiPPLNrECChEvo8g/TGIZoyjJL0iUELBhF9iFuw8elpdl17CPe6fz45yeqa6uqu455752uSVdTU93dU11f1XVNT1z5jrvPTRyW/edCuAqAJcAOA/ASQCWqR3mg5xSbs5d3Kbxq+0ubcseh4WqI79TeCQ+iX9QPgTnXgfwLBx+AocH/V+snIRCTjIAt3XfOgB3ArgaQF/rPO+UA5OCp/GYdbMNvtNBD8dxjGRQnILDP8HhJv+1lXvAKDEAt3XfFQDuAbCGMy8YEj2dl8cE3zmjLdPHAt/y5oSH8I7P9yYcrvU3rXwEhCp64rbuux7Aw1gEvz0vAt/Z4NM/Ll/lIbw58J3Al8pbA4eH3J1vX09G3kYAt3XflQAeIl0WHo0DflGdEfKlOt6n0njosdC4JH1G4UsNycPhD/2fr3gEGBqA27rvFADP4FjxfNEQlJCqlbuAnwOzS7KXBZ3INUHvyBfXvwngfH/jit1B9b/CsQg+94Cc15Z6UNGxA/jOzQ74TuBL/sTosAYOtw+qtvxiPYAdWIjZvujpvOyUeqQTKNUdf8le3jEGdVMATu9jcJ//7gbf5KFHcj0t2bPkjxKFcnyqbAH8uNwH3FV9DDZ5FhaNA35RnTLZWj8J/NIooYHetI1hJFrEKTekj/UBvB8LiTSPbs6VkKqVEz4D/ByYCy3Zy103Z0gO5/UB/DoWCuXA1Lyels26WQa/63qvtjG+co822kUdT+pjIezti57Oy2OCfzwke3mPtvVL65fOf/I3DvhFdcJkS/xO6XPsJ3uGLD/P2f98gJ/tz8AvjRIa6E3bCEbSxaMlmaYsD7j5vP0TwabnwoRZfRO+AvA1MI+/ZI/U+4hnfgwgB6bm9bRs1s0y+MdesieCD7g5NgDR03l5TPAXkz2l3rN+bo4jwDjgF9UJky3xC5MAYPaTvVH4JF1Hig4MfDKOuTEAzaObc6fzjQp+tv+wz0y9ttW0jWAkXTxakmnK0sGfGwPoCr7GrwJbAL4G5rGc7GWjQ7reS/1n1wByYFKlNB6zbpbBP46SPU3G7BiA6Om8PCb485HsdY0QXTw6qtMBy8uSkz1N1swbwDjgF9UJky3xS5MAxODnDKULWOPwdQDMlmWs94qsmTUAzaObc6fzjQq+duR9judkj4Z8ST/D2GbOADTwHStYgEvttH8p+BzMxWRPKA9OZsYASsAvBVyqm631PhxnItkrNSbNo3Myx0z2NFnjGYAzzhc6+BKgSZsgt9RIsiAMCyNHh27JnmbAoxvAOOAX1QmTLfFLkwAsJnslxoZRDUDz6OZcUMjqWwK+dgzlmf5BJpc7qkcnfZSxlcgaI9nT2rsbQA5Mzeu1cgJoB/A5mAvnB5lKH82jC3QcM9nT2rsZwEyAbxqBM9oyfY7HZK+pHz/Z03QsMwBnnM80+CaP0mcx2bPHq163ZB9AAH/v35yAtSdWIjsA3PLoO7jtscOFRqBMttaP92HJ3l2/uwR/9tH0PVf+FQQP4OAhjxNuOxj1Nz21lK8LCJasFcDOa5c3unsANRtPOH/y1Rp/9IMjraycAQ9101GknbmAEhoXfKf9DftUaN/Zy+jmWTmcr1jmsOXCCTIhGVA5H782B18bQ8Qr8XnAeVz/wX6jrwV+Oz4lOijgw1kGIAHIB5mjLh5UdBwWcus9IQ5+oDB5110wkXrqKB4tgZ/llQBr1/tr3tdTwebnXrtWct14DKkBcIC1co6sCJDbctX6AFnwPbluDnwAuOC0HnBSVQ5qdpJLooPCR5O903tYu9pF+krg1+Svc1QCNwAOsAh+3gq81C/nRebRAF/wKhrmAR38UH/7B/ploErXjPpIHs15nTIHPuK96+xepC8FW1sS7Egjj6E1gFLwS6NAAjAbuMhj9OE7e2LfVLkc+B7AFz48IcukoEr6UgPRwAfjE/Vnmf7yCpdv6plgJ0uAel1DrypMKwc7AZ8MsCtJk8iP4t+wj5bsaeATHSXwaXQIx5VLHa7+zb4NqgquwGMZUlTvGfgDg//iB1rwue7WuQg+rWfgDw6ip2cULyHNg4qOgterR5dYOV8C0mw5nbzrPjQhG5NmqIEvGx2Cjrydbe6QMVxzbr8z+FESKIEPciQLv7wEOFLQDMQibYKKjgXgC5MW2miYb5Ij2OB7ABec2gN+jRmTCW5pdJAihLGzt7GHtatT/UrORYegeoVoGqhyyhIQCqOA3/AbFmh5MpBP9rh8fh3I6z0tS5N56/snMtekuhboJxqFZ7yxrG+cVSX6SckfPW/5Db3iDwIC1YBXWQIU8Nkk62SAo4I/POfrvdiXGZcRBeh6n/OkL/zWhKxv5PXKJIPzSboJj3Epz3KH3z+nW/LXRjlDL+b19EevbAlwrSBpcF1IAlr8c62Flv4aVzUMHfxA1oSuWupw+Qe1W0JhXoqjg5zs8Wt8ZsTkrzEUSS8OPuOrTMXByoURwHMZFphUSYufep/KQ3Rgx+ApBw55czftT5K7AaTXVY1aAR8KD+Pdssne+Xt8srbXfz4nFvjDctWUJMCBVGgpzQT4dNKyPIMq75wIfqBDU8C2N2p5KxXAh9b3gPdQIHXATI+WwBejw/BvYw9rV7lIX6r/oy9M44QlUNujW0Eh2dOiZtUZ/C6GIIJPJmsmv6tLDQVymAx1//zcVMTDeW8+r090Na5tRgcv8ymR5PYz0+SPnn99Z222NzKT9Z7px8YhJ4FSOKF1JaSCH5QDmyCpj+RVkl4ukp1LmG59cgoHDnuV9/MXTmQBs6ODkOxZ41jucMXZafIXzvce9MBkGrWSZUAL+ca1q6iRduCd+cAN8panzFCyl3j98LwenpqT9Y7Hv26fFm+pPIDVSx0+eb6QC/A5SOpJsteMmYGf6A9sOb9vJn/ffaFurqmCT0lI9rR57hYB4kKeuCePm+wlgxEmFzb44bNY33xuSs0DagBbz630a5cke2p0SMd7+emVCuxbRzwefm4acA7rVso8QGv4WrKXjmMwz+lOoBkBXNxuURfwJW+WeCRdpDZkbp0c8PT2aWx/o1bzgEvO6AO/yoEWPDoHfsLLxntahbNPdKquP5qsgcOtLBH8UDCSPc1xqjxzGBADxyLeZzaSPUNn6zaP8t7z9FGVvwZw4+a+fs2m3C3Zi+bGAbdlkr+/3Fk3/WthfDXlN50r1MXzXBABhMkuocA7i8mexK/lANL98refrfHWMBmUdt+u2SzcDUjgR/oZ4+Cyljlcelqlgr9tnwd2k+gi8ERjs64NIImajj8O1pSVeHI0y8meHBkGp9bavqRHrnvI40cvTqsJ2NpfcbiYRoHmWqMlezw6XHNeDyuWuETHcP7QK3XUf9VEzEP7ideOdJCxrMQOoTAi+PHTKU0ppyplhi3VWAd80y7O6HmmXwd5wz7X/u+UumfgAXz2nF4KfnRdLToI42Xju3xjlegYrn/wiMcj2+q2TwWsWuJU8JMlIHIcHUslAhjgl0aAUm+WeCRdLM/iOsPKA5i83TX+a/e0uGFUA7j49B5JBtl6T2VJeknjDbxC8kf1fGxXDRzyDfgaX6hPbr3DnACxfkxPFgFc3tu6UKlSKsCuOx8Kk0DS/4HhngAHf9DH4yubejCf5FFdorJTDfiWM9Lkj177jm0x+FD4ajDqMs+IIoDi9dKkl5DmzTm5jccI4Eu6MY/OJYETfd4f+IefDXYGJfBrB1yzmS8DyjhKo8Myh0+cKid/NYDtb3rg53UM/vIqDfmEfDQ3TtGJHIdUmeDz4/DPMyEiSeCboIe/jJFEfMIkw04CfSIHwCHgoZ9NRzy1840xnbza4cL39ZBN9pqyHR2u2qwnfwBwxwt1uq070Z6K4PNrk/lQnbca/N+YMvAlAQrdcdky3HGZ/fMszZolHmvzQ9vIofXZR6fO4ebt0/jj3xj+Esel0eBLZ/XwmedrHXQiy24H/mBDJeoMAAeOeDz9MqmhmzswwA8X6AA+YN0FqMdCKzAUHQd8ni3zNukOIJEXRaXhyZ4aT+2pE/CDnI9s7AEnGt5vgU//1lc460R5T98DuH9HDQz3JviTPD5XyXMAK7IGqtBuF8PaCUyObiTwuaI58OVELD3XbvM0/uh673FpqHTA/S9OmfKuDbeESRQg8jJLwy3Gvj8AfPflWn+MK/AnxA2OUsWEOf40UOrcDBDpiwYZ4oqWgM/bcxl9aT315ih3aP48HvqfKRw44lV5WzZJTwidADSEOgcsc/idU+WtXwB48g0P/IL0ofJWp/yUvIgboYpZxLBoLwFB8QC+JFhTyDi3wJdC/Djga94cj7Pd3HnguWl1aVm7GtiwqUf6KeDTMlkarjy3ijZz+JjvfqUW+rbyTM/nY6JUOZVP3wpGq/hsgE9DvZQMjQO+tv7nwIcDbntmuuHlxlMDuOmMKgJV9/hQbo3kyg36vv/Box7PT3rZi6VwrhHlY+t9IhNmBFDAzyjC13vLswEZ0FHAl8BS+65wLfg8nO/zeHKv/vbNRzb0gPBxDDP0O0R5xnqHs9c4USYA3BuSP2spyREHn4d8wVD7UUe6pjVChIEqFAZ20w8P46//44hgwU6oQzc+SVdSd+NvT+CGD09E+iTRYClgPcm79afT+ME6PVnbcmYP9/33lKEjiQ7D49c26hs5HsC92wXwiYw1qzokXxL4yrFKFHfI/yCTEc/00wcTQyFdwM+G1RR8qp92K+idT59SsnD+023TTTLIl5QawNZzKkPHWBYcgOUOl65vAeTgP/WGB37JoxEbbykpyZ52bG8Du7y2xQaQnEeTI0wIB40bidge6gRDIn9xtp+CH+UBxs7e3/2f8Zh4lcOys9kyII11WL7snEHyl+gzLN+1i20wRXLJeHOUWe/Tow9JYAfwhVevtfOijZHAZ3o80snIeD/A9/R948UXLht2Egwo/H3vxWl1CagB3Hk63xNQxlABnz5Nv/Xbf9RjxwtS9k8cAsChjBEkH+UoAB9wqEZ6Zw+F4OdApXzJtXgfG7Aga3pY5g90aN2GpUqkoeU3PZ56VU8GLzm1AtYEkJwwLgzm9L0OZ61Jb/2CrH/cWcsOwWWVUm4ugQZ8uAC79vUNRalcpu+lCR3Fo7knFEYH6YEOBWBKHWMoD0C94fn2lpDLAIArz1B2BgP4AL66oV37pSTwvhfJbSjCeBX9cmR5fVTXzlXV+esbRBktq23KpaCq4BpeH/HGBsLXe2nd1Q20lfXq9nrwowzIy8DnzlSSwYD5MoePr48f/FBZT/7cAwe9Pl6iZ24JaEjF0IttmYdBTlZKGVBTnwM1qZP6lESHoGPbXrsUfHpHAKDT93S+t70W7wQA4ORVDjiTJINAtFX+yXN6WDXh1Ln6yks0/LPxSsccWeCHE9ZmvBSaTkY4it4OlgdYoKrGIVzb5E35vLO3gPXoxAxz+Hf/jjQZpPK+sWEYBYQfZF69Xgf/raMemKyRe2evGHw6rujYrvd6BEj+BGsRooD5QEcDVZOneLRuSFIkkcM1jwbTiV6SrOHffo+fsN/lUXkfXR+SQTLwygHvbXf+aNQIMu7c7vPzzMRmyQJf4RGWANkTuBLWnv5010+bN0angA/GJ+o2WONy4AM0SS2LNH+6LU0G6XV+LyR65OsbN7BbPxB+AHhi0n7wExG/v9cokWHM+/DIlgDFE5iiibdDC7EMVHWSBZ7i6OBBExzP9JOeEdTFkWao2y6PPSwZpGO+9owq/k3eUodPnOJU8H+81wNvC9eix0D8V74KtXmNnOw1JEcAl4LAmZmRmOATvvwkl0SHoCNvZ5HGOfNpYN0cSyJNPIZ7XqpF8GsA61Y6YEN7R/DxsyqsnIgRo/N1y27i/dIxUKnnBzKSPS3CVFayp4GVe2zrZzTZE4xTAn8IavCE3DsF+UgTX/PR5+t2fEwmANx+WmvIn17fzjB/TrL3bQ9MZryUP8YttgMDSy5ryJfeBahRwEWCtP12ep6f5Ny1tejAH5zEsiR9ots487qKXoc9fry7hZw7wcdOqYBVDljnsGmNi65P6Vsv+/SaHHxaoUWHhLS5ill4Xd+0GD4pw6J0a5O/zQplZ1xHuGbCy7yHLTVUH0235i4g0cEJdcNyBXx1+zSeOiV9qSPIvnRDhfNWpW2U/k168BMo9zCnhDKA83LfBsMJdYODtQyIHhbkWVZqeqGwZSrIovsAkm4+6JdcVx9rc3+/x2P3Lz3WrZTv76/b6LByiQ5+k/xR2YHmAXyAfym0EHxKxWtsabInPudPkz0xhDLj1HSL9wEyY2WbO9/e4UXwAWDtSodVE8IkDemWnSz5I3Ijkgy0lDS8FCdLN4KAdIKR8lg5QLrVagAWXZMBIYEvRof2Lwd+tETB6WNVPrX2wxfkPIBeQ6K9b3vgdbJ8AXKypxh1kRGYgNP21hmrdCKdfHFS1jZE6LEUMDs68IRJkcWupyZ/oEuAoZf1qbUjHg/vTG8JLfAB4O5XBPBpRWbOs6SBH9UNhZJ68rsA1pjxWL4TmDwsyb22lY0OdrKnyZpy+RdEpzXw2xkZlsk1Cd9dky38OeAD/fsOYjJdXttynMkgzWgcqWD1VfHkEiOxtlsBsg+QkykCQXb2Gq9n+klyhdvUSCd2LuqV+a5uw/eax/Nv+mLwH5ysgaNMLtXDPLLIUUKF4ANhIyhUmGEo9lQVfK5IDjAOftRPiw683I6BbgWrO4G8v7TeZ+bk3j2l8AN/G3hHAZ87SY5yToa4XKmTK4E/bM9m2SZggkfnwJf0ooZE2tvtXlvHpg9/27rwU2tPvFTjwFFkae/bHnjDd0/2pCd5OeIyeH/BEIzbQLQTLLSrdwD8YpLXJ9caLdnTXlbJgX848Hf8rm5kxEeAx/by+4CUvjlZx8oZRqWC39kIXNxfkjE8V24DiSChXdz/R7wBUypr7E+tMV5v6EjPR/mu7uDYXvvu3fll4D93Eh7V23nduOCzfgr4gHgbCOTe0adZtrQfMJ0MTJI1ZrKnTN400le3xKeVzQxkDC5qY8C85rFtvyR0QA/s8sBRwbjEY+YBkcsbWxZ8x87Bfx4OQAyrwqRkk0ATsPGTPYs397RypO/qSl7pgC++rC8D39rjE375KCR70hzkiPNaUaCp/voBn4DPhZV4dNJHk8Ut3fboSJ7ZntFLS/ZU/YXraryNTMSVoifzo5DslfSLykp/7ZwQeRpogN8ZsELwradvnYwtIyu33ovjLNCPUukPMpM6wRBz/Whfi0c6Z9Qf2aOTdsCWlUn2pHLO2CRZnK8k2eN11njpkcuFwlcC8EyDnwE+UPuVsJwnmKATpZJ2Zb3PySqKDoyP691lc8fSUTpyuVD4JEfg4BUBTsszAz4gvRCSm4xOgBVu7iT9MmDlvLR0vZfkaTz0SOVSKgW/s7fTOpfqMSL4gPVGUDFgmoEsJnvxcX6TPY36+qSUAFYI/rsx2UuAEgzR5Gd9LR7pvJDaT8RoHp20Ix5QVC/c9y4me+VtYjkD/ojAB2JLgObRXNkM+GZ04OWS6MD4+MQtJnsjU/d9gHdbssdDfkm/2VjvVb7xSN8HSAalGchCSPZc+uEnaxych/MGmpdkL+P10vkYlN8HMKPDMZzsWV7fXMMA3wKws7eTvhaPdD4mle8DRPVzmOzx9oWY7Fnrfa6uKWfAn2HgA9kGkAPfjA68XBIdGF8p+BZAmlfOBfglYHL9cvwzTPo+gPEBBjs6kLIpS+qjADUfyZ7lwRz8Um8XQZ0/8AHxp2GaRx8HyZ7q9ayyxJOPsWRPI7YRVAh+kUcboGqyePs4632Oh8uFwmcB2NnbSV+LRzqfJUr3AaIJLvtBZpFHi4ZgALWY7M0JGfsABet91B7KGbBKvPR4S/YcqbA8fY7BB4D+YrKHtKyBX+rtIqhKf+18jkh4GDRKsucy7QWyFpO9eaE+HA7DYelAkcVkTwSws7eTvhaPdD63dLiCw+v8U2vF7+hrHm2Bz9vHTfZmA/yOn1qTyxnwHVI9555er+D8MwDIZLKJtTzabCd8UjtQ/mvcRK7glTMJPgfPMkixnc2Nxj//9GwF4PEZ9ehIluKlytc3bNDDdQvBH+XrG7kfaECoS9pdyrswwQeAxys4PAiHKRV8Wp6JpSFJ9hRAE7AEr5T4gLJkzwJf45FkNWVmnJxHOp9fmgLwQOW/vGIXnLtfnVAJVJPXMKTk17gCnwiOy/NQuTnwuV50fFxmkUE4pd44n3+631/U2xUguRkO+zt7NHidAdQo6z2AxWRvVmg/gJuBISz++uW74fA5AN70aC06SOCDHEfa2XOYk2RPNWbhOkk766/xLyyaBvApf1FvN0Cg8dctfwQOX0b4yFYO1GgSFC8dK9lTeOgxjGAmvr5RBDhtF/ovfPA9gC/5i3r/Eiqc9/Hvzt133rkCcPfAYU3eMwQPynm9KQ8y+KrXs0rLUDTwc96b1DmdVztfGLQfwGf9Rb3v08rk/5H6zy//Phw2w+E+AFN66B8DfNVDXZ4nklsAvma0XGbO4I5d8KcA3AdgMwcfECJA1Pj3h06Fw6cAXAyH8+FwMoAlM77eA5i3zZ1cXVPOgL9wgD8C4DUAzwB4AsAD/qLepMb8/+wgpNtTtaGDAAAAAElFTkSuQmCC".into()
    }
}
