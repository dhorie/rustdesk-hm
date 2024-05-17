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
        "data:image/png;base64,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".into()
    }
}
