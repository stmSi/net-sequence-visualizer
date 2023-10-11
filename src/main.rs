use std::collections::HashMap;
use std::net::IpAddr;
use std::thread;

use eframe::egui;
use eframe::egui::ComboBox;
use pcap::Device;

// Define a type for a unique key per TCP stream
type StreamKey = (IpAddr, IpAddr, u16, u16);


struct AppState {
    devices: Vec<Device>,
    devices_names: Vec<String>,
    selected_device_name: String,
    capture_started: bool,
    tcp_streams: HashMap<StreamKey, Vec<u8>>,
    rtshark: Option<rtshark::RTShark>,
}

fn start_capture(selected_device_name: String) {
    // let out_path = "/tmp/out.pcap";
    let builder = rtshark::RTSharkBuilder::builder()
        .input_path(selected_device_name.as_str())
        .live_capture()
        .decode_as("tcp.port==8080,http2")
        .decode_as("tcp.port==8081,http2")
        // .output_path(out_path)
        .display_filter("http.request or http.response");

    // Start a new TShark process
    let mut rtshark = match builder.spawn() {
        Err(err) => {
            eprintln!("Error running tshark: {err}");
            return;
        }
        Ok(rtshark) => rtshark,
    };

    // read packets until the end of the PCAP file
    while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
        eprintln!("Error parsing TShark output: {e}");
        None
    }) {
        for layer in packet.clone() {
            println!("Layer: {}", layer.name());
            if layer.name() == "http" {
                println!("\t{:?}", layer);
            }

            if layer.name() == "json" {
                // println!("\t{:?}", layer);
                println!("\t{:?}", layer);
            }
            // for metadata in layer {
            //     println!("\t{}", metadata.display());
            // }
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            devices: list_devices(),
            devices_names: list_devices().iter().map(|d| d.name.clone()).collect(),
            selected_device_name: String::new(),
            capture_started: false,
            tcp_streams: HashMap::new(),
            rtshark: None,
        }
    }
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Network Sequence Visualizer");
            ui.label("Select a network device:");

            // let selected_device_name = match self.selected_device_name.clone() {
            //     Some(device_name) => device_name.to_string(),
            //     None => "Selected None".to_string(),
            // };

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
            if self.capture_started {
                ui.label("Capturing packets...");
            } else {
                ui.label("Click to start capturing packets");
            }
            if !self.selected_device_name.is_empty() {
                if !self.capture_started {
                    if ui
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
                                self.capture_started = true;
                                let device_name = self.selected_device_name.clone();
                                thread::spawn(|| {
                                    start_capture(device_name);
                                    println!("Starting capture");
                                });
                            }
                            None => {
                                eprintln!("Error: Selected Device not found");
                            }
                        }
                    }
                }
            }
        });
    }
}

fn list_devices() -> Vec<Device> {
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
        println!(
            "Found device: {}, IP: \n\t{}",
            device.name,
            addr_list.join("\n\t")
        );
        println!();
    }
    devices
}

fn main() {
    let mut options = eframe::NativeOptions::default();
    options.maximized = true;
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
