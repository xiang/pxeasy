#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use pxeasy_core::{
    AppController, AppEvent, LaunchRequest, SessionHandle, SessionInfo, SessionState,
};

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("pxeasy")
            .with_inner_size([640.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "pxeasy",
        options,
        Box::new(|_cc| Ok(Box::new(PxeApp::default()))),
    )
}

#[derive(Default)]
struct PxeApp {
    source_path: String,
    session: Option<SessionHandle>,
    logs: Vec<String>,
}

impl PxeApp {
    fn start(&mut self) {
        self.logs.clear();
        match AppController::new().start(LaunchRequest {
            source_path: self.source_path.clone().into(),
            interface: None,
            bind_ip: None,
            ipxe_boot_file: None,
        }) {
            Ok(session) => self.session = Some(session),
            Err(msg) => self.logs.push(format!("[pxeasy] Error: {msg}")),
        }
    }

    fn poll_events(&mut self) {
        // Collect without holding a borrow on self.session while mutating self.logs.
        let mut events = Vec::new();
        if let Some(session) = &self.session {
            while let Ok(event) = session.try_recv_event() {
                events.push(event);
            }
        }

        let mut terminal = false;
        for event in events {
            match event {
                AppEvent::StateChanged(SessionState::Running(info)) => {
                    push_session_info(&mut self.logs, &info);
                }
                AppEvent::StateChanged(SessionState::Stopped) => {
                    self.logs.push("[pxeasy] Stopped".to_string());
                    terminal = true;
                }
                AppEvent::StateChanged(SessionState::Failed(msg)) => {
                    self.logs.push(format!("[pxeasy] Error: {msg}"));
                    terminal = true;
                }
            }
        }

        if terminal {
            if let Some(session) = self.session.take() {
                // Monitor thread has already exited after sending the terminal event,
                // so this join is nearly instant.
                session.wait();
            }
        }
    }
}

impl eframe::App for PxeApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_events();
        let running = self.session.is_some();

        egui::Panel::top("file_picker").show_inside(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Image:");
                let browse_w = 70.0;
                let text_w =
                    (ui.available_width() - browse_w - ui.spacing().item_spacing.x).max(1.0);
                ui.add_enabled(
                    !running,
                    egui::TextEdit::singleline(&mut self.source_path).desired_width(text_w),
                );
                if ui
                    .add_enabled(!running, egui::Button::new("Browse…"))
                    .clicked()
                {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("ISO images", &["iso"])
                        .pick_file()
                    {
                        self.source_path = path.display().to_string();
                    }
                }
            });
            ui.add_space(4.0);
        });

        egui::Panel::bottom("controls").show_inside(ui, |ui| {
            ui.add_space(4.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(4.0);
                if running {
                    if ui.button("Stop").clicked() {
                        if let Some(session) = &self.session {
                            session.stop();
                        }
                    }
                } else if ui
                    .add_enabled(!self.source_path.is_empty(), egui::Button::new("Start"))
                    .clicked()
                {
                    self.start();
                }
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.logs {
                        ui.label(egui::RichText::new(line).monospace());
                    }
                });
        });

        if running {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

fn push_session_info(logs: &mut Vec<String>, info: &SessionInfo) {
    logs.push(format!("[pxeasy] Detected: {}", info.label));
    logs.push(format!(
        "[pxeasy] Interface: {} ({})",
        info.interface, info.ip
    ));
    logs.push(format!(
        "[pxeasy] DHCP:      listening on {}",
        info.dhcp_addr
    ));
    logs.push(format!(
        "[pxeasy] TFTP:      listening on {}",
        info.tftp_addr
    ));
    logs.push(format!("[pxeasy] HTTP:      http://{}", info.http_addr));
    if let Some(nfs) = info.nfs_addr {
        logs.push(format!("[pxeasy] NFS:       listening on {}", nfs));
    }
    if let (Some(smb), Some(share)) = (info.smb_addr, info.smb_share_name.as_deref()) {
        logs.push(format!("[pxeasy] SMB:       \\\\{}\\{}", smb.ip(), share));
    }
    logs.push("[pxeasy] Ready — waiting for PXE clients".to_string());
}
