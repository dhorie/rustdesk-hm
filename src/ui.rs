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
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAABGdBTUEAALGPC/xhBQAACklpQ0NQc1JHQiBJRUM2MTk2Ni0yLjEAAEiJnVN3WJP3Fj7f92UPVkLY8LGXbIEAIiOsCMgQWaIQkgBhhBASQMWFiApWFBURnEhVxILVCkidiOKgKLhnQYqIWotVXDjuH9yntX167+3t+9f7vOec5/zOec8PgBESJpHmomoAOVKFPDrYH49PSMTJvYACFUjgBCAQ5svCZwXFAADwA3l4fnSwP/wBr28AAgBw1S4kEsfh/4O6UCZXACCRAOAiEucLAZBSAMguVMgUAMgYALBTs2QKAJQAAGx5fEIiAKoNAOz0ST4FANipk9wXANiiHKkIAI0BAJkoRyQCQLsAYFWBUiwCwMIAoKxAIi4EwK4BgFm2MkcCgL0FAHaOWJAPQGAAgJlCLMwAIDgCAEMeE80DIEwDoDDSv+CpX3CFuEgBAMDLlc2XS9IzFLiV0Bp38vDg4iHiwmyxQmEXKRBmCeQinJebIxNI5wNMzgwAABr50cH+OD+Q5+bk4eZm52zv9MWi/mvwbyI+IfHf/ryMAgQAEE7P79pf5eXWA3DHAbB1v2upWwDaVgBo3/ldM9sJoFoK0Hr5i3k4/EAenqFQyDwdHAoLC+0lYqG9MOOLPv8z4W/gi372/EAe/tt68ABxmkCZrcCjg/1xYW52rlKO58sEQjFu9+cj/seFf/2OKdHiNLFcLBWK8ViJuFAiTcd5uVKRRCHJleIS6X8y8R+W/QmTdw0ArIZPwE62B7XLbMB+7gECiw5Y0nYAQH7zLYwaC5EAEGc0Mnn3AACTv/mPQCsBAM2XpOMAALzoGFyolBdMxggAAESggSqwQQcMwRSswA6cwR28wBcCYQZEQAwkwDwQQgbkgBwKoRiWQRlUwDrYBLWwAxqgEZrhELTBMTgN5+ASXIHrcBcGYBiewhi8hgkEQcgIE2EhOogRYo7YIs4IF5mOBCJhSDSSgKQg6YgUUSLFyHKkAqlCapFdSCPyLXIUOY1cQPqQ28ggMor8irxHMZSBslED1AJ1QLmoHxqKxqBz0XQ0D12AlqJr0Rq0Hj2AtqKn0UvodXQAfYqOY4DRMQ5mjNlhXIyHRWCJWBomxxZj5Vg1Vo81Yx1YN3YVG8CeYe8IJAKLgBPsCF6EEMJsgpCQR1hMWEOoJewjtBK6CFcJg4Qxwicik6hPtCV6EvnEeGI6sZBYRqwm7iEeIZ4lXicOE1+TSCQOyZLkTgohJZAySQtJa0jbSC2kU6Q+0hBpnEwm65Btyd7kCLKArCCXkbeQD5BPkvvJw+S3FDrFiOJMCaIkUqSUEko1ZT/lBKWfMkKZoKpRzame1AiqiDqfWkltoHZQL1OHqRM0dZolzZsWQ8ukLaPV0JppZ2n3aC/pdLoJ3YMeRZfQl9Jr6Afp5+mD9HcMDYYNg8dIYigZaxl7GacYtxkvmUymBdOXmchUMNcyG5lnmA+Yb1VYKvYqfBWRyhKVOpVWlX6V56pUVXNVP9V5qgtUq1UPq15WfaZGVbNQ46kJ1Bar1akdVbupNq7OUndSj1DPUV+jvl/9gvpjDbKGhUaghkijVGO3xhmNIRbGMmXxWELWclYD6yxrmE1iW7L57Ex2Bfsbdi97TFNDc6pmrGaRZp3mcc0BDsax4PA52ZxKziHODc57LQMtPy2x1mqtZq1+rTfaetq+2mLtcu0W7eva73VwnUCdLJ31Om0693UJuja6UbqFutt1z+o+02PreekJ9cr1Dund0Uf1bfSj9Rfq79bv0R83MDQINpAZbDE4Y/DMkGPoa5hpuNHwhOGoEctoupHEaKPRSaMnuCbuh2fjNXgXPmasbxxirDTeZdxrPGFiaTLbpMSkxeS+Kc2Ua5pmutG003TMzMgs3KzYrMnsjjnVnGueYb7ZvNv8jYWlRZzFSos2i8eW2pZ8ywWWTZb3rJhWPlZ5VvVW16xJ1lzrLOtt1ldsUBtXmwybOpvLtqitm63Edptt3xTiFI8p0in1U27aMez87ArsmuwG7Tn2YfYl9m32zx3MHBId1jt0O3xydHXMdmxwvOuk4TTDqcSpw+lXZxtnoXOd8zUXpkuQyxKXdpcXU22niqdun3rLleUa7rrStdP1o5u7m9yt2W3U3cw9xX2r+00umxvJXcM970H08PdY4nHM452nm6fC85DnL152Xlle+70eT7OcJp7WMG3I28Rb4L3Le2A6Pj1l+s7pAz7GPgKfep+Hvqa+It89viN+1n6Zfgf8nvs7+sv9j/i/4XnyFvFOBWABwQHlAb2BGoGzA2sDHwSZBKUHNQWNBbsGLww+FUIMCQ1ZH3KTb8AX8hv5YzPcZyya0RXKCJ0VWhv6MMwmTB7WEY6GzwjfEH5vpvlM6cy2CIjgR2yIuB9pGZkX+X0UKSoyqi7qUbRTdHF09yzWrORZ+2e9jvGPqYy5O9tqtnJ2Z6xqbFJsY+ybuIC4qriBeIf4RfGXEnQTJAntieTE2MQ9ieNzAudsmjOc5JpUlnRjruXcorkX5unOy553PFk1WZB8OIWYEpeyP+WDIEJQLxhP5aduTR0T8oSbhU9FvqKNolGxt7hKPJLmnVaV9jjdO31D+miGT0Z1xjMJT1IreZEZkrkj801WRNberM/ZcdktOZSclJyjUg1plrQr1zC3KLdPZisrkw3keeZtyhuTh8r35CP5c/PbFWyFTNGjtFKuUA4WTC+oK3hbGFt4uEi9SFrUM99m/ur5IwuCFny9kLBQuLCz2Lh4WfHgIr9FuxYji1MXdy4xXVK6ZHhp8NJ9y2jLspb9UOJYUlXyannc8o5Sg9KlpUMrglc0lamUycturvRauWMVYZVkVe9ql9VbVn8qF5VfrHCsqK74sEa45uJXTl/VfPV5bdra3kq3yu3rSOuk626s91m/r0q9akHV0IbwDa0b8Y3lG19tSt50oXpq9Y7NtM3KzQM1YTXtW8y2rNvyoTaj9nqdf13LVv2tq7e+2Sba1r/dd3vzDoMdFTve75TsvLUreFdrvUV99W7S7oLdjxpiG7q/5n7duEd3T8Wej3ulewf2Re/ranRvbNyvv7+yCW1SNo0eSDpw5ZuAb9qb7Zp3tXBaKg7CQeXBJ9+mfHvjUOihzsPcw83fmX+39QjrSHkr0jq/dawto22gPaG97+iMo50dXh1Hvrf/fu8x42N1xzWPV56gnSg98fnkgpPjp2Snnp1OPz3Umdx590z8mWtdUV29Z0PPnj8XdO5Mt1/3yfPe549d8Lxw9CL3Ytslt0utPa49R35w/eFIr1tv62X3y+1XPK509E3rO9Hv03/6asDVc9f41y5dn3m978bsG7duJt0cuCW69fh29u0XdwruTNxdeo94r/y+2v3qB/oP6n+0/rFlwG3g+GDAYM/DWQ/vDgmHnv6U/9OH4dJHzEfVI0YjjY+dHx8bDRq98mTOk+GnsqcTz8p+Vv9563Or59/94vtLz1j82PAL+YvPv655qfNy76uprzrHI8cfvM55PfGm/K3O233vuO+638e9H5ko/ED+UPPR+mPHp9BP9z7nfP78L/eE8/stRzjPAAAAIGNIUk0AAHomAACAhAAA+gAAAIDoAAB1MAAA6mAAADqYAAAXcJy6UTwAAAAJcEhZcwAAD2EAAA9hAag/p2kAABtoSURBVHic7Z15vB1Flce/p+8LWchjkS2SCSQQkhAISFh1/LywCcOAKPrRceUFGAT8KC44LigghEUEBWQTBJFPhBHEUZFlcGGc0QERBWFYBJJACCFglAuGkPW9nj/u7b7d1edUV9933xL0fD73dd2qU1Wn6nfOqXOru+tJHMe8nkiOqY8CtgemIOwAsh2wHcKmwBsQtgU2AUYhabUYoQ9YgbAMeAVYjvAsyHMIC4HFCAvjKzZdP+SDGkSSDV0BZG59KrAnwj7ALsBuCG9slpIBWU9788TNW4rwKPAIwm+B38WXbbqwMyMZHtrgFEB662MQeoADgUOAPXSQBwi+iKcsd/0dwq+BnyPyi/iSTVZXGM6w0wajANJbfxvwPoTDgW1aBVmmTKIT4Ht5ste0vxeJuAP4fnzRJnf6RzQyaEQrgPTWJwMfBI4GpuUAgWrgB+UVXH6AEmTqRLmyRcB8hBviCzd5yh3bSKERqQDSWz8Y+AjwbhrTalt0+t2x2soewAO+eW0molL+HwKXxxds8gtGGI0oBZDe+lHAKcA/5gvK0h0P9joJfnZJuRe4OD6/+2ZGCI0IBZDeeg9wJrB/vsBl1NJDFuxVA9+KJxrX3yB8KT6ve9g9wrAqgPTWdwe+CLynWOj5PvzBng5+WftFnpsRzo3P6X6IYaJhUQDprdeAM4DTdAbP95EX7BnXDPjly8PXED4fzxs/5JtMQ64A0lt/K3AtME1nMNLpd9Wl2umhXu8Tfi/oTruNvIXAJ+Kzxt/OEFJUztI5kt76V4BfURX8dNJEtygwJtjlG2TwRWzws59su628HRFukzNevYghpCHxANJb3wn4HjBbZ/B87/R6r5aV1Gk/2DMU0qMkjfQDwDHxGeMfZpBp0D2A9NbnAo8yGOBb1l5YuwPXY62OFeyVgV/gST6l4IMwG5GHZN7KkxhkGlQFkN76WcB1wCidwfM9BPzSvFB3bNSJFH7LS5S1K1KUx1KShE+4Qs5eeT6DSIO2BEhv/bs0tnENBiOdfjdcqpUu8Bnge68BLt/l9/FYSlKVT7glPnXj4k/lDlDHFUB66+OA24ADbKaytGH12bQ3b5DBr7rem2UOn7+9BxEOiz+/8Yt0kDqqANJb3wK4h5Ao3/3eKfA3rGBP5zPryHMI+8SfG7eMDlHHFEB661sD9wPb6Qye72XgB+Upk63xi1GnMzt7WbAGzqfJKiwF9og/O245HaCOBIFN8O8lBHxRvieZnQRfnE+hfrNOxNAEe5psLVA94EvLQzTyJiLcJxe+tjUdoAF7AOmtjwUep/EcnsJgpNPvhku10gU+A3zvtZkYecGev998egkwKz5l3CsMgDrhAX5JVfA1C7D4TQvO1NfKOgH+wHb2PBat8BXa9oIPMAnhbgZIA1IA6a3fAuxTLKDckrPgWTxeDzBI4GcBMMsMWVQgPTKbiiDFcrUtmS0XrfohA6C2FaC5yfPuYoHnexn4pdaT1C2xtsI1UycLvm9yQ+UKBbXMojXwTd5cW++US1ZdQJvUVgwgvfX3AjcVC4x0+l1svqC8Clbv1qmy3ifffbzt/CLwKrcxtpC2JAY4Oj553HwqUmUFkN76tsDSYkFZWpkwH3+BrwL4LpgbdrCX4TXBT/K3jz827lkqUDtLwF2FnBDwtYFDycQk10EGvxPBnsZXyNPqBIKf/ymogQ9I5aCwkgJIb/1cYNdWRkYgrLSU83g9gHjKSuoMZbCn8fnacy1a+6RtidJW7PAKCDvKFasupgIFLwHSW58FtO5Pi8ugpQ3wg/IUi9T4xajjBntqHQN8Nc9jqaF8mqxeXqut2MkvjGO/+KSx9xFAVTzAT9KUC4gGXtmE4ctTwPdaCS2r03b2tL5Gzs6eH/yC1XvAb31+RCAFKYD01k8j2ezRALQEL+N3rz7wfXUqBXsOAF5FK1GSHJ8BagF8ozzHq7XlrPfa0tBKT5CrVgU9R1C6BEhvfRvghbTxtEBLSzmPVwnEU1ZSZ6hu42p8Ze1pim2mtX4LwV6AXIDI5Pj4MYvxUIgHuDLXAVa6Q+Bbg/HVeb0Ge4AR7PmVqTXeb1JCXg8gvfVpCE/kM7W0AX5QnmFBVj23zogO9gylDm6rZL33ydXK3zs+bszvMKjLKmhWvi6TTmnZ1zdlwua28zj9B6uY959rsu0U2igFv02rv+CfN+IzB40xZcvSq6tjuue9mm+3XVA1viqKlMtvGuU4If7XsUFjue+Ffva7da0m93xgZ6ueiaLMrR8MvCUntJs2KG7HgoKufvBDZMvS+DHCMXuNKoLajkWHgp/j9YAvMG93v30WSJd7hly3+kirii8GOCdtKNtBFWHctDVBQdfOgp/QSXuOskHXQDWVI/mIUd9NK3xOsHfsjDYVoNjv2VYVVQFkbv1NwD46+NKy8FChctcSF+qrU/aMvmR4A2nv7WqwVRQGqtZnro5m0S6vGHOQD/ZmTe5i2+6KWm17mlly/ZoDtCqWBzjDAj/Y0goAOwNXeTx1rNu4uTrtuYGr9/N4geyYTXClxdeWdygGexfsWqs0BnPZbfX5Za1eQQHkmPqWCO9sZWRarQK+W98HtGXJQvWdvTbo/cla6wPVBFfhCfYO7s5eU+HHCIdOrqYARbmSMaT5PTJ/zbZuFc0DHFcqeCVhSsBXr4rVm1fJgVBpeWrS+NHCZ97SVezftPgMX6l3SGR0y7WdvUb6rKrBX0IFBS7IdYJbRVOAk1ogO1ZfdXKH4rGtdpRToffOHJWX2bR4pW+vd9A8hH9n77jpbVh/0h5Kn0lZROFdw5wCyDH1fZHkAc8OgJ/UCwJf/OBr1qfxtEl7T6rBdrWSPrOyBsinKoV/Z++oGbXqwV9KHrkac7qV3LhmTrZG3gOkLsIAP3CS47aCvYxEBYtx6zjKNUDwE7p6VycWKPThWJfJa3kHZWfP4Tthxzat35IF8ihHklsG0iI5tt4FclQODG3yqwjjXtWPtDQ09OgVUzHakDND79+tCza2xq/kB3sHI9hz+3hDxKHbd0ABbPABjpKb1o6mWCw9CJupgLc7wSFgZqXw8fse22pHNoXGjxY+vVvNVlK3H4vPBR+Dx+E9c6of/BVrPXduNYMogg/CGISDKbAI++cac9Od8AC5awD42Ukr5dGEL1L9Nf/t74/sngSDSVM2YF6L1sBXvUPr86lZtgKsWBvzaD3g6S2h5U0Tigpe85C0KMN2RNpAtjErz0OxWy93zUzWIJy+UfYzsK8/5v4lfWb59K0imBQRApjfO8Q6n+FJ3jG9RvdGtvDXL+j3Dyxp0wU+cuRrXA9KWQDkuJe3IHvqtuZOclYWQCb4mZ61Cc3V0axKk0vybZfQpQ/6T2O7efaoUsD83iHosa1c3hdK9v0//kTACXK6y9f63kVuWbtDq4pwoNfatYGXkWUpnQz2tMkNoPkPr+fVNbY7PWxqDcYqY8j1oylIJthLx6zI57a7ecS+E+z7cr95sR9eqfD+RuT0qc/hftDSmdlOoQ1MKPi5azMxFM/ol1CtOTmX3b/O5Bk/Wjh3r1F23yHBnukdiuO9bKbf+s9+sq81VoPSpc8FH4xxyGxoQTIrzAMIoRNdCXzNmjUeTRanrCwG6Gp6ny886nepR02rKX0rFl0GfoG3ON6jd7Ktf8XamNsX9YPApI1LBlcM9ow5FGi+1JssAbvYzMmAHHBKKVNnqI9aCxCNl2J+tsBWghlbRuyzU83uM01XC/Zy8ylw4ix/8Hfh4/3FsVqD8hpXkpfO80z54bpaJMe//A/AZNsDKA2HUOqSFEE0azYFzg5GivK4/BVkO/Mh+9cAwCnTa/k5KMhWPdhzvUPvFP9v/7Oe6cvJXEpl89wq2wJhh4jsf+KwhHXLSiiGwQ/2VM9QLl8t9UbC/y7o4/m/2sHVe3fugrGaRbcZ7LneYULEftvY7v/O5/rhr3HQuNS+czKoWM6MECYVKiSJNsAvCGRdBxrsFZQ1w+ehWkSu3+sf8ccC5+zR5fTVfrDnju/SHfzW/54nM9YfwcSyGMA0HBPL7SM09x9yG7eMQq1Z49FkKbP44AA1396pD6zz/iScu0tXhj/wGX3N8t3xjRV6p9rWv3RlzMql/Sn4IcPyGo57bXwmRkjzZK90QCXWVoVChTIBlsp8QQ+EZOuvhjsX2rHAtt3CHlMivHfysrLk0mIq8Ik7Rt7g76qFFcBXxxYwz409T7bMaXNZpZAJzgZ+llBWu6nFKOBrsjkWXUZdyoskFzzlDwa/MstdBoxxVPAOJ0/z//af92SfvrPno+w8qzLhztGWEcI2JvjuNXCS9fq6JRTaDg72MkpSQTlryq+S+xf28cc/23vth0ypNYNBKcqnpku8w9YRO29uC3vjoj7I3vmLBMYHKkCV5TuSLbtAtg4CX2vAoHOPGMO5R4S9nTMspAB25aPruWTORmaVebuP4rTfrgvwSoaCZPJunOEP/j74bEYZs5s7pVQJfIDxEdI8yj1YCUJdwAimnFdqfPnGH/u8weCxM5THxbJpH/jZz5iIIybZC/tjL8fwfFMBtDt5QeNS+k4oIrucbBwh1MLAl9cH+ADjKLrK1TD/j/5g8F3Tazq4ydxYS1aaFk7f2b/zd9HCPvs2bghpS2dCkdOYNFbEcYVKBffVFMZ90GBDpbGRMt6Yjz7s3xP4yFTlaSEtDlEVofHlX7b37Puvi7nm2cw+Q7a90UalJsUqbhmKHI1oJCVC6C90mBtIBnyt4Q2VcuNsTvrL/dy3zA4GD92+Bm+IMvUM8LPpDPgbT4qYuZk9gdct6oc17r2FZmGJAhTGlCX3F0SGr2HTZev93wL4zcm+YYH/J+GZO9ZyoNoWn6RbSnL1ZL/7/MSCft2KNXdukb3eF9tseoBVSoEN/utBCcZJC3zHnV/68Hrvw5efmlUrgp9N55aGzDo+VviAZ+v33uUxvOpuNjEw8F2XX1TU/i5gpbrep40UKpXS5+9Yw/m/WqtosCh5VOPTZM3knfPWUZz6Zv1/VCW0x2h40HMn7+KH+zhtL32jpnsj4chpNW59qs8jY0ZBmtfTSt72uXZJv3du5mxUIfjSwNevKyKEl3KCC+UvZIZQYUIqgl/qVovgh8rX796ldCz69JJl4NTpWjCot5V8TtjRH/xdu6DPnm8RpthbFHnSgz3ruiJCWJYTPPRc3TJKB6NPSDEvoyRqeZKnKJLG56H+tK4U5QN4uZ+7FttKsO+ECDbXxqW0JVCbGHnv5H31CeWhj2yboXPuX++Va/xSBCyv/MxeCbUeC9cnxATVtHiKk9Gm9QNMG9OsZCmQwMce93uBS2d0hY0hgp9M87v/s5f058fhGgQBN7nESZeDD8jyCJHGf6Cq8sxeCIWAmuUr9OXW8QOWthVA246O/HIJLHi2j6Wv2sFg79TsuwOijIvGnI4WDptou/87nu+HlbE+DrfNECqbS0jAB+HPEfB0W/9EYaCChFi0awmh3qGEYnOMSboB6jVP2l6geyPhhJmuF8h8mnN6Won1H77IeeTLt2SWkc/qc3npXC2MiHjW1hRDqBKyjytJPg6oJrgeq8/xtviCD4gwFbTV1pcf8y8Dc7dXdhQht1t6wg7+hz54wX1plOIYaXNcuWuslT0V0fi/9UZF0YUKFcQC1SrXwC/llcqyBZyn06A1Mf/u+UWw3zYRbJ3ZGYQc+IdMqXmDvyufyWz8DNZTWEDq8otlT0fAM4hzFrA2Ge0IY4FqKofSt5e3yFfJUty2FLk/87TfC3xjctMLKC9kfnI7/2/3cxb2U/LMXjWjU+un671btgJhQRR/fZMY4eH8wBVtqeAF4sImC7pFq+AqwqqKpHmSCq9P5eSyvdLzz/XzuOet3Lk7RI2HRbINRwLd/uDvhsV9sL5VJS+TIwttPOoGefCLPL+PD+5am0j4QG5yNWEylatbmQJ+oY+MJbTlHeL8QD0Uu3KVeJpLPI+MdW8kHJ/c4Ysk3UD7kueuH8CHnnPPDXD6z5K7uWNRoQ3PvMOD0Hoz6A+Nq2EJrqChggxisNfKV07fKKE42NM02rvq6X7v/YFPTq0V3sb97PSShz7+5P70c64JNdvtLxlWK65Rg70WtfIehXTVkl8GPbMHQROc4yud5BDv0MzQwM/xBspm9VXot5m5JuY7i+zbxDM3E9iiJd9BkyO6R9myXLA4s/GjXRMKeRA0S3awp+F6DzQVIL6g+0WER9QKFlh+SUosntYEB3kHzUPoL2hUXp5MT5Pv8+Rn/Ac0fHen1nGz8zwHPa1YF/OdJSVW6t7GDdYDxUjc+o30kvigrseTrhK605wUqAC+8jPLnGQlP8g7lLygESJfJU8D/Lmf3/zJVoIjJ0YwWqBbePOWtiDXLu6H9cZDH2DeyascBNrgg/DjXHfNzJ+abkP7jRoijDrJjnWZvJZ3KDlqLZRUxfTIFcG3n7UVoHuU8MWpERd73vYB+NRSxfoTKruTF0I64G5bP0+7zDD/N/BKASycCa6iAIXOFYsO9g5hR62193OJYlsO+ADferKPFevsYPADEyOO9Tz1c89fYnjZeeYvobI7eSFkgZ/PWwn8LO02ScTnda9D+HFugpNKFYVR99pDgz3VCsOPWgumgqIbbTmbO199wh8M+oK/q5c6wV+m3YJs2jWErPlo5d0dH9j1Wtq1U7nxT4Z8O3ZtCeMBzGfRGviqd2hTNsQeq3HU2tmLA07rUmjFupjrn+7Py6gFe4ZSV/Js2XSxrSuzVXIKEJ/TfS8iL+guUunEJ0goYF7v0M7pG+VUug/gO2ptZdy4hVuRzlvobFSFPLZVdc6tttK0LI8P6LozW624YAmX5wRoc5KDgz3TO7R3+kbYz0CPXAFHrR3ueZvYovOWZupUeWyrqlezwQco/Ht5TQGusC02VCLFosvAT/MHePpGKGlyWeC7fC/GjVu5gXT7C/2N0CvbblYO7zV8i7vQZppOx/INl7WgAPFZ419Cmv8iPjfhDlgeKn8eQGkvAT9Xz/IOblpRkDL5svW19V7rJ5N3RYVY4Nzn43y7CYWA35yDtp9zaM3h/8T71xa77PpvFuFMFfxcwwGCqIApFl0GfoE3+6kGfkFGdwYCj1o7d1GYB3jutZh7nu8PDvY08IPJbSNf/xytiqoA8ZfH30t6i7gN8LO8mtW7bQ3wqLWq4KceIOxcXQUsgbUx3/VsDCV0+ZL+vHAepTLBr6wEkq8PT8f7136qsdu7FsKpOSusMMnqVqvVVgeOWsvyBbvK8HN1nbJW3x9eWq4AX8neQzCt3c0bKPhOPeHfrCqmAsSnj78d4RF1UqoIZALWoaPWNJCqUNi5uroHezHmMc8ZvvOf64d1inKpV/8NojjoYRcV/GfiObUfWDX8G9fCh9MGK0xyfifQAD/XruUd3HSIdwiUD6qcq9uS0eH5qicYPPr5uMCvX83HtiqMS4q8jfTR3lq+/x4OIOesvA3h8LwwAcKWrfdpvRKLzrbnLS+Rywr2TPmVfi3etE3ymZrR+MCvUi+XNurDf8VzagfiofI3DoUT89ZmAKZZfbYciuAPJNjTvIMlV5VgL5engO/KkbZLPjOo/WR8JTwm+JKv7/LA8ZRQqQLEp278HPC1IdvZq6JsWluuXB0I9kyeXLsl4LtyWdeyvDQtZTxXxHNqCymh0iUgZTz/tZeAzb0KoAJmrPda/VBQc2nRy6Ha5o5PRu3qtovBV7iWPLbltqOmS8FfCWwa99RK96yrnPhzeClgoeCbFp9pC195kha93LiTZ4KffqQlo8uTvWbbzVIo+D4ltNLaHNr87woBHyooQPy5cfciXFacSDEACzxXt1DPsNRCWwZQVYI9dxwuj8ubtklndvZ84GttafWLdb8V9+ibPhoFLwFphQtfW4iwQw7UgsCe9b7Am6Q9lhHaVtl6r7VHgHxZCj99o5ynLC9Ni5+n9f2ZuKc2hQpU/dA34Z8KgOWs/u/B3pCCnxfpCCpSZQWITxn3FMjcIjjaY1sO+GraAD/XFrYiuaMYyM6ednXbxeArXD07e5aStQN+i06Ke2qPUpHaOvYx/vTY6xEuSIV4PQd75Uet6eBrXs1t26f0bn2rboOuintq36QNqhwD5CpfsuoOJD4sP7gAi4Yw7+CbxJzqSutQK5evkCdFHpc3oWHZ2Sux+uL3u+Oe2kG0SQNSAAC59LWHgN0KFp1cyzTb5PW01Ylgz2eZaR8e8IOUwVOmpiuDvzDuqU1lANSJk38PRFg2aMGeW96pYM+tl6WqwV74C5nFvDRdAn7RQ9WBtzJAGrACxB8f9xdE9oLMUTOgg+otz/Bp5a60IynYc8HzeSE17cyNj79BLwF7xz21FwolFWnAS0Da0BWr3ojwAMKERkZSQLnrda3ULQ/d3NHas3iyV7Bdvrf+INzJM/lSWgHsEfeU7/OHUMcOf48/OnYZwj7AC0EWnbNaCQRfBrazp/GBf703vUsngj2lvh/85cBenQIfOqgAAPGJY5cgzEZ4MAeqBn6aFr3cBT9z+kaBrwCOlPNk27XAd6+5PPGUefqUTIYP7CL4jwFvintqTxZKBkAdWwIKDX9r9Y8Q3tH4gjFBhneAsGDPzQPbk2SvbrsYfJbVW2368tJ0CfhF4AHuAt4e99Tsf3neJg2aAgDINasvQThZB64N8Eutc5jALwNTMhk+S9fBvzLuqX1ULekADaoCAMi3V38CuLgAvjaJf0vBXrnLB/hM3FP7mlrSIRp0BQCQ61bPRrgBZEbBkjWrRwa2s2davZMZYslDv7MHsAh4f9xT+22hpMPU0SDQoviYMQ8gsivClaXg/z3Y+yYwcyjAhyHyALkO5685ErgEYTLw92CvRS8AH4t77Gf4B4OGxANkKf7w6FsRZgCXv+529tJyyfNa/C26Fpg+1ODDMHiAXOc3rtkbOJ1IjghzyR5gslcYic/oa9/vAs6Ie2r3MUw0rAqQCnHT2rcD8xB2b2TgX+8tnoQ6EeyVWe/A1vtHgDPjntotDDONCAVISL6/di7wcYTZjYykwFkeUK4JVXX5VcvUdDD4j9P4XX8pI4RGlAIkJLesfQfCScChr5Ng7xfANXFP7XuMMBqRCpCQ/Me63Wm8oPo+hImNzKTQYR7IY1tWHSttrfd5/mUINwPz457a7xmhNKIVICH50bqNgKMQPgS8Dcn8J92RFeytoXEK500IN8c9tTXegY0A2iAUIEty67oJwIHA/kTMAZnWKjSuubyOB3tP0Thl9ZfA3fGc2rIKwxl22uAUwCW5bf1uwL4IewJ7IkwFNhukYO8V4HGE/wMeBn4d71/7w4AHMYy0wSuAS3LH+k0QpgDTEXYEJiHxBJCtaLzcujkwBqFGAnHjbx/CahqPW72CsBx4kcajbgtAFgBPxQfU/jr0oxo8+n9b5d1HHZoaGgAAAABJRU5ErkJggg==".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
