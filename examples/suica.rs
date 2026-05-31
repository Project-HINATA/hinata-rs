use hinata::find_devices;
use hinata::pn532::gen_felica_poll_initial_data;
use hinata::card::PassiveTarget;
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct StationInfo {
    line_name: String,
    station_name: String,
}

// Embed the pre-generated static mapping table
static STATION_MAP: &[(u8, u8, u8, &str, &str)] = include!("ekicode_data.rs");

fn load_ekicode() -> HashMap<(u8, u8, u8), StationInfo> {
    STATION_MAP
        .iter()
        .map(|&(region, line_code, station_code, line_name, station_name)| {
            (
                (region, line_code, station_code),
                StationInfo {
                    line_name: line_name.to_string(),
                    station_name: station_name.to_string(),
                },
            )
        })
        .collect()
}


fn parse_suica_history(block: &[u8], ekicode_map: &HashMap<(u8, u8, u8), StationInfo>) -> String {
    if block.len() < 16 {
        return "Invalid block size".to_string();
    }
    let console_type = block[0];
    let process_type = block[1];
    let _payment_type = block[2];
    let _entry_exit_type = block[3];
    
    // Bytes 4-5 are the Date (stored in a packed big-endian format)
    let date_raw = ((block[4] as u16) << 8) | (block[5] as u16);
    let year = (date_raw >> 9) & 0x7F;
    let month = (date_raw >> 5) & 0x0F;
    let day = date_raw & 0x1F;
    
    // Bytes 6-7 (Entry Line/Station) and Bytes 8-9 (Exit Line/Station)
    let entry_line = block[6];
    let entry_station = block[7];
    let exit_line = block[8];
    let exit_station = block[9];
    
    // Bytes 10-11: Balance (stored in little-endian order)
    let balance = (block[10] as u32) | ((block[11] as u32) << 8);
    
    // Bytes 13-14: Sequence Number (big-endian)
    let seq = ((block[13] as u32) << 8) | (block[14] as u32);
    
    // Byte 15 upper 4 bits store the Region Code
    let region = block[15] >> 4;

    let console_str = match console_type {
        0x03 => "Ticket Machine (精算機/券売機)",
        0x05 => "Fare Adjustment Machine (乗越精算機)",
        0x07 => "Ticket Issuing Machine (新規発行机)",
        0x08 => "Window Terminal (窓口控除)",
        0x09 => "Mobile Phone (携帯電話)",
        0x0d => "Bus (Flat Fare) (均一運賃バス)",
        0x0f => "Bus (Distance Fare) (多区间运区バス)",
        0x12 => "Vending Machine (自販机)",
        0x16 => "Automatic Gate (自動改札機)",
        0x17 => "Simple Gate (簡易改札機)",
        0x18 => "Window Terminal (窓口端末)",
        0x19 => "Simple Ticket Gate (簡易入金改札機)",
        0x1a => "Simple Gate (IC改札窓口)",
        0x1b => "Mobile Terminal (モバイル端末)",
        0x1c => "Transfer Adjustment Machine (乗継精算機)",
        0x1f => "Simple Deposit Machine (簡易入金机)",
        0x46 => "E-Money/Shopping Terminal (物販端末)",
        0x4b => "Simple Shopping Terminal (簡易物販端末)",
        _ => "Unknown Terminal (未知终端)",
    };

    let process_str = match process_type {
        0x01 => "Ride / Fare Payment (運賃支払)",
        0x02 => "Charge / Top-up (チャージ)",
        0x03 => "Ticket Purchase (乗車券購入)",
        0x04 => "Fare Adjustment (精算)",
        0x05 => "Entry Adjustment (入場精算)",
        0x06 => "Window Adjustment (窓口精算)",
        0x07 => "New Card Issued (新規発行)",
        0x08 => "Deduction (控除)",
        0x0c => "Window Deduction (窓口控除)",
        0x0d => "Bus Ride (Flat Fare) (バス等均一運賃)",
        0x0f => "Bus Ride (Distance) (バス等多区間運賃)",
        0x10 => "Reissue (再発行)",
        0x11 => "Reissue (再発行)",
        0x13 => "Auto Charge (オートチャージ)",
        0x46 => "Shopping / Purchase (物販)",
        0x48 => "Points Top-up (ポイントチャージ)",
        0x4b => "Entry Shopping (入場物販)",
        _ => "Unknown Process (未知处理)",
    };

    let is_shopping = process_type == 0x46 || process_type == 0x4b || console_type == 0x46 || console_type == 0x4b;

    let station_info = if is_shopping {
        // Shopping transaction: Line and Station bytes represent Hour and Minute or Category
        format!("Store/Time: {:02}:{:02}", entry_line, entry_station)
    } else {
        let entry_station_str = match ekicode_map.get(&(region, entry_line, entry_station)) {
            Some(info) => format!("{} ({})", info.station_name, info.line_name),
            None => format!("Line 0x{:02X}, Station 0x{:02X}", entry_line, entry_station),
        };
        
        let exit_station_str = match ekicode_map.get(&(region, exit_line, exit_station)) {
            Some(info) => format!("{} ({})", info.station_name, info.line_name),
            None => format!("Line 0x{:02X}, Station 0x{:02X}", exit_line, exit_station),
        };

        format!("{} ──► {}", entry_station_str, exit_station_str)
    };

    format!(
        "Date: 20{:02}/{:02}/{:02} | {} | {} | {} | Balance: {} JPY | Seq: #{} | Region: {:02X}",
        year, month, day, console_str, process_str, station_info, balance, seq, region
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("==================================================");
    println!("          HINATA Suica Balance & Station Reader   ");
    println!("==================================================");

    println!("Loading Japanese Station Code Map (ekicode.csv)...");
    let ekicode_map = load_ekicode();
    println!("Successfully loaded {} station mapping records.", ekicode_map.len());

    println!("\nFinding Hinata reader devices...");
    let builders = find_devices(vec![]).await?;
    if builders.is_empty() {
        println!("Error: No Hinata reader devices found.");
        return Ok(());
    }

    println!("Found {} reader device(s). Connecting to the first one...", builders.len());
    let mut device = builders[0].build(false)?;
    
    println!("Successfully connected to device: {}", device.get_device_name());
    let firmware = device.get_firmware_timestamp().await?;
    println!("Firmware timestamp: {}", firmware);

    println!("\n>>> Please place your Suica card on the reader... <<<");

    // Poll for FeliCa targets using Suica's system code 0x0003
    let initial_data = gen_felica_poll_initial_data(0x0003, 0x00);
    
    loop {
        // brty = 1 is FeliCa 212kbps. max_tg = 1.
        let targets = match device.pn532().in_list_passive_target(1, 1, &initial_data).await {
            Ok(t) => t,
            Err(_) => {
                // Ignore timeout/communication errors while searching, and retry
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                continue;
            }
        };

        if targets.is_empty() {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            continue;
        }

        if let PassiveTarget::Felica(felica) = &targets[0] {
            let idm = felica.get_idm();
            let pmm = felica.get_pmm();
            println!("\n==================================================");
            println!("Card Detected!");
            println!("IDm (Hardware ID): {}", idm.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "));
            println!("PMm (Parameters) : {}", pmm.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "));

            // Suica service code for history is 0x090f.
            // We pass 0x0f09 because the library serializes using `to_be_bytes()` which writes [0x0f, 0x09] (little-endian of 0x090f).
            let service_code = 0x0f09;
            
            println!("\nReading and parsing card history/balance (reading 20 blocks one-by-one)...");
            println!("==========================================================================================");
            
            for block_index in 0..20 {
                // 2-byte block list element for block_index (Service Index 0) is [0x80, block_index].
                // We pass 0x8000 | block_index because `to_be_bytes()` writes [0x80, block_index].
                let block_element = 0x8000 | block_index;

                match device.pn532().felica_read_without_encryption(1, idm, &[service_code], &[block_element]).await {
                    Ok(response) => {
                        // response[0] is the PN532 status (0x00 on success).
                        // response[1] is FeliCa response length.
                        // response[2] is Response Code (0x07).
                        // response[3..11] is IDm.
                        // response[11] is Status Flag 1 (0x00).
                        // response[12] is Status Flag 2 (0x00).
                        // response[13] is Number of Blocks (0x01).
                        // response[14..30] is the 16-byte Block Data.
                        if response.len() >= 30 {
                            let status1 = response[11];
                            let status2 = response[12];
                            if status1 == 0 && status2 == 0 {
                                let block_data = &response[14..30];
                                let hex_str = block_data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                                
                                // Parse and decode the 16-byte block using the ekicode map
                                let parsed_info = parse_suica_history(block_data, &ekicode_map);
                                
                                println!("Block {:02} [Raw: {}]", block_index, hex_str);
                                println!("         └─► {}", parsed_info);
                            } else {
                                println!("Block {:02}: Read ended (Status Flag 1 = {:02X}, Status Flag 2 = {:02X})", block_index, status1, status2);
                                break;
                            }
                        } else {
                            println!("Block {:02}: Response too short or invalid. Bytes: {:02X?}", block_index, response);
                            break;
                        }
                    }
                    Err(e) => {
                        println!("Block {:02}: Failed to read: {:?}", block_index, e);
                        break;
                    }
                }
                // Sleep briefly to avoid overwhelming the device/card and respect packet limits
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
            println!("==========================================================================================");
            break;
        }
    }

    Ok(())
}
