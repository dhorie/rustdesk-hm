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
