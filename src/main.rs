use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;

use eframe::egui::ComboBox;
use eframe::egui::{self, Ui};
use pcap::Device;

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

struct AppState {
    devices: Vec<Device>,
    device_to_ips: HashMap<String, Vec<String>>, // Mapping from device name to its IP addresses
    selected_ip: String,                         // Newly added to store the selected IP
    devices_names: Vec<String>,
    selected_device_name: String,
    capture_started: Arc<AtomicBool>,
    captured_packets: Arc<Mutex<Vec<Arc<PacketInfo<'static>>>>>,
}

struct PacketInfo<'a> {
    src_ip: IpAddr,
    dest_ip: IpAddr,
    src_port: u16,
    dest_port: u16,
    tcp_packet: TcpPacket<'a>,
}

impl Default for AppState {
    fn default() -> Self {
        let (devices, device_to_ips) = list_devices();
        Self {
            devices_names: devices.iter().map(|d| d.name.clone()).collect(),
            devices,
            selected_device_name: String::new(),
            capture_started: Arc::new(AtomicBool::new(false)),
            captured_packets: Arc::new(Mutex::new(vec![])),
            device_to_ips,
            selected_ip: String::new(),
        }
    }
}
fn start_capture(
    selected_device_name: String,
    capture_started: Arc<AtomicBool>,
    captured_packets: Arc<Mutex<Vec<Arc<PacketInfo<'static>>>>>,
) {
    // use pcap to capture packets
    let cap = match pcap::Capture::from_device(selected_device_name.as_str()) {
        Ok(cap) => cap,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    // open the capture
    let mut cap = match cap.immediate_mode(true).open() {
        Ok(cap) => cap,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    println!("Starting capture on {}", selected_device_name);
    loop {
        // check if the capture has been stopped
        if !capture_started.load(std::sync::atomic::Ordering::Relaxed) {
            println!("Capture stopped");
            break;
        }
        let packet_data = match cap.next_packet() {
            Ok(packet) => packet.data.to_vec(),
            Err(e) => {
                eprintln!("Error: {}", e);
                continue;
            }
        };

        // get the packet's TCP header
        let eth_packet = EthernetPacket::new(&packet_data).unwrap();
        let eth_packet_payload_data = eth_packet.payload().to_vec();

        // Parse IPv4 packet
        if let Some(ip_packet) = Ipv4Packet::new(&eth_packet_payload_data) {
            // Check if the next level protocol is TCP
            if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                // Parse TCP packet
                if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                    let shared_tcp_packet = Arc::new(PacketInfo {
                        src_ip: IpAddr::V4(ip_packet.get_source()),
                        dest_ip: IpAddr::V4(ip_packet.get_destination()),
                        src_port: tcp_packet.get_source(),
                        dest_port: tcp_packet.get_destination(),
                        tcp_packet: TcpPacket::owned(tcp_packet.packet().to_vec()).unwrap(),
                    });
                    // Extract and print the payload
                    let payload = tcp_packet.payload();

                    if !payload.is_empty() {
                        if let Ok(payload_str) = std::str::from_utf8(payload) {
                            captured_packets
                                .lock()
                                .unwrap()
                                .push(shared_tcp_packet.clone());

                            println!("------ Packet ------");
                            println!(
                                "Packet: {}:{} -> {}:{}, SEQ: {}",
                                ip_packet.get_source(),
                                tcp_packet.get_source(),
                                ip_packet.get_destination(),
                                tcp_packet.get_destination(),
                                tcp_packet.get_sequence()
                            );
                            println!("HTTP payload: {}", payload_str);
                            println!("----------");
                            println!();
                        }
                    }
                }
            }
        }
    }
}

impl AppState {
    fn network_interface_ui(&mut self, ui: &mut Ui) {
        // ui.label("Select a network device:");

        ui.set_min_height(300.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (device_name, ips) in &self.device_to_ips {
                // ui.label(format!("Device: {}", device_name));

                let selected_device = self.selected_device_name == *device_name;

                if ui.selectable_label(selected_device, device_name).clicked() {
                    self.selected_device_name = device_name.clone();
                    self.selected_ip = String::new();
                }
                // ui.indent("    ", |ui| {
                // Indent IPs under the device name
                for ip in ips {
                    let selected_ip = self.selected_ip == *ip;
                    if ui.selectable_label(selected_ip, ip).clicked() {
                        self.selected_device_name = device_name.clone();
                        self.selected_ip = ip.clone();
                    }
                }
                ui.separator();
            }
        });

        ComboBox::from_label(String::new())
            .selected_text({
                if self.selected_device_name.is_empty() {
                    "None".to_string()
                } else {
                    self.selected_device_name.clone()
                }
            })
            .show_ui(ui, |ui| {
                for device_name in &self.devices_names {
                    ui.selectable_value(
                        &mut self.selected_device_name,
                        device_name.to_string(),
                        device_name,
                    );
                }
            });

        // use the selected device to capture packets
        if self
            .capture_started
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            ui.label("Capturing packets...");
            if ui
                .button("Stop")
                .on_hover_text("Stop capturing packets")
                .clicked()
            {
                self.capture_started
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            }
        } else {
            ui.label("Click to start capturing packets");
        }
        if !self.selected_device_name.is_empty()
            && !self
                .capture_started
                .load(std::sync::atomic::Ordering::Relaxed)
            && ui
                .button("Start")
                .on_hover_text("Start capturing packets")
                .clicked()
        {
            match self
                .devices
                .iter()
                .find(|d| d.name == *self.selected_device_name)
            {
                Some(_) => {
                    self.capture_started
                        .store(true, std::sync::atomic::Ordering::Relaxed);

                    let captured_packets = self.captured_packets.clone();
                    let device_name = self.selected_device_name.clone();
                    let capture_started = self.capture_started.clone();

                    thread::spawn(|| {
                        start_capture(device_name, capture_started, captured_packets);
                    });
                }
                None => {
                    eprintln!("Error: Selected Device not found");
                }
            }
        }
    }
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::Grid::new("main_grid")
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    ui.heading("Network Sequence Visualizer");
                    ui.end_row();

                    ui.vertical(|ui| {
                        self.network_interface_ui(ui);
                    });

                    ui.vertical(|ui| {
                        ui.heading("Captured Packets");
                        ui.separator();

                        ui.push_id("captured_packets", |ui| {
                            egui::ScrollArea::vertical().show(ui, |ui| {
                                let captured_packets = self.captured_packets.lock().unwrap();
                                for packet_info in captured_packets.iter().rev().take(100) {
                                    let key_str = format!(
                                        "{}:{} -> {}:{} : SEQ {}",
                                        packet_info.src_ip,
                                        packet_info.src_port,
                                        packet_info.dest_ip,
                                        packet_info.dest_port,
                                        packet_info.tcp_packet.get_sequence()
                                    );
                                    ui.label(key_str).on_hover_text({
                                        let payload = packet_info.tcp_packet.payload();
                                        if payload.is_empty() {
                                            "No payload".to_string()
                                        } else {
                                            String::from_utf8(payload.to_vec()).unwrap()
                                        }
                                    });
                                }
                            });
                        });
                    });
                });
        });
    }
}

fn list_devices() -> (Vec<Device>, HashMap<String, Vec<String>>) {
    let mut device_to_ips = HashMap::new();
    let devices = match Device::list() {
        Ok(devices) => devices,
        Err(e) => {
            eprintln!("Error: {}", e);
            vec![]
        }
    };
    for device in devices.iter() {
        let mut addr_list = vec![];
        for address in &device.addresses {
            let ip = match address.addr {
                IpAddr::V4(ip) => ip.to_string(),
                IpAddr::V6(ip) => ip.to_string(),
            };
            addr_list.push(ip)
        }
        device_to_ips.insert(device.name.clone(), addr_list);
    }
    (devices, device_to_ips)
}

fn main() {
    let mut options = eframe::NativeOptions {
        maximized: true,
        initial_window_size: Some(egui::Vec2::new(800.0, 600.0)),
        ..Default::default()
    };
    options.maximized = true;
    options.initial_window_size = Some(egui::Vec2::new(800.0, 600.0));
    let result = eframe::run_native(
        "Network Sequence Visualizer",
        options,
        Box::new(|_cc| Box::<AppState>::default()),
    );

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
