use hinata::card::PassiveTarget;
use hinata::error::HinataResult;
use hinata::find_devices;
use hinata::pn532::{Pn532, Pn532Port};
use tokio::time::{sleep, Duration};

const TUNION_INFO_READ_ATTEMPTS: usize = 3;
const TUNION_INFO_RETRY_DELAY: Duration = Duration::from_millis(50);

fn parse_tunion_history(block: &[u8]) -> String {
    if block.len() < 23 {
        return "Invalid record block size".to_string();
    }
    
    // Bytes 0-1: Offline Transaction Sequence Number (big-endian)
    let seq = ((block[0] as u16) << 8) | (block[1] as u16);
    
    // Bytes 5-8: Transaction Amount (big-endian cents)
    let amount_cents = ((block[5] as u32) << 24)
        | ((block[6] as u32) << 16)
        | ((block[7] as u32) << 8)
        | (block[8] as u32);
    let amount_yuan = amount_cents as f64 / 100.0;
    
    // Byte 9: Transaction Type Code
    let type_code = block[9];
    
    // Bytes 10-15: Terminal ID (6 bytes in BCD/HEX)
    let terminal_id = block[10..16]
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join("");
    
    // Bytes 16-19: Transaction Date (YYYYMMDD in BCD format)
    let date_str = format!(
        "{:02X}{:02X}/{:02X}/{:02X}",
        block[16], block[17], block[18], block[19]
    );
    
    // Bytes 20-22: Transaction Time (HHMMSS in BCD format)
    let time_str = format!(
        "{:02X}:{:02X}:{:02X}",
        block[20], block[21], block[22]
    );

    let type_str = match type_code {
        0x09 => {
            if amount_cents == 0 {
                "Subway Entry (地铁进站)"
            } else {
                "Ride Payment (乘车扣费)"
            }
        }
        0x06 => "Payment (消费)",
        0x02 | 0x01 => "Recharge (充值/圈存)",
        0x05 => "Fare Adjustment (退款/精算)",
        _ => "Other (其他)",
    };

    format!(
        "Date/Time: {} {} | Type: {} | Amount: {:.2} CNY | Terminal ID: {} | Seq: #{}",
        date_str, time_str, type_str, amount_yuan, terminal_id, seq
    )
}

async fn read_card_info_with_retry<P: Pn532Port>(
    pn532: &mut Pn532<'_, P>,
) -> HinataResult<Vec<u8>> {
    let read_info = [0xB0, 0x95, 0x00, 0x1E];
    let mut last_result = None;

    for attempt in 0..TUNION_INFO_READ_ATTEMPTS {
        match pn532.in_data_exchange(1, 0x00, &read_info).await {
            Ok(response) if response.len() >= 33 => return Ok(response),
            result => last_result = Some(result),
        }

        if attempt + 1 < TUNION_INFO_READ_ATTEMPTS {
            sleep(TUNION_INFO_RETRY_DELAY).await;
        }
    }

    last_result.expect("at least one T-Union info read attempt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hinata::error::Error;
    use hinata::pn532::Pn532Command;
    use std::collections::VecDeque;

    struct SequencePort {
        responses: VecDeque<HinataResult<Vec<u8>>>,
        requests: Vec<(Pn532Command, Vec<u8>)>,
    }

    #[async_trait]
    impl Pn532Port for SequencePort {
        async fn request(
            &mut self,
            command: Pn532Command,
            payload: &[u8],
        ) -> HinataResult<Vec<u8>> {
            self.requests.push((command, payload.to_vec()));
            self.responses.pop_front().unwrap()
        }
    }

    #[tokio::test]
    async fn card_info_read_retries_short_responses_and_errors() {
        let expected = vec![0; 33];
        let mut port = SequencePort {
            responses: VecDeque::from([
                Ok(vec![0; 8]),
                Err(Error::Timeout("transient".into())),
                Ok(expected.clone()),
            ]),
            requests: Vec::new(),
        };

        let response = read_card_info_with_retry(&mut Pn532::new(&mut port))
            .await
            .unwrap();

        assert_eq!(response, expected);
        assert_eq!(port.requests.len(), 3);
    }

    #[tokio::test]
    async fn card_info_read_stops_after_first_complete_response() {
        let expected = vec![0; 33];
        let mut port = SequencePort {
            responses: VecDeque::from([Ok(expected.clone()), Ok(vec![1; 33])]),
            requests: Vec::new(),
        };

        let response = read_card_info_with_retry(&mut Pn532::new(&mut port))
            .await
            .unwrap();

        assert_eq!(response, expected);
        assert_eq!(port.requests.len(), 1);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("==================================================");
    println!("         HINATA China T-Union Reader              ");
    println!("==================================================");

    println!("Finding Hinata reader devices...");
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

    println!("\n>>> Please place your China T-Union card on the reader... <<<");

    loop {
        // brty = 0 is ISO14443A (Type A CPU card). max_tg = 1.
        let targets = match device.pn532().in_list_passive_target(0, 1, &[]).await {
            Ok(t) => t,
            Err(_) => {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                continue;
            }
        };

        if targets.is_empty() {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            continue;
        }

        if let PassiveTarget::Iso14443a(iso_a) = &targets[0] {
            let uid = iso_a.get_uid();
            println!("\n==================================================");
            println!("Card Detected (ISO 14443A Type A CPU Card)!");
            println!("UID: {}", uid.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "));
            println!("SAK: 0x{:02X}", iso_a.get_sak());
            println!("ATQA: 0x{:04X}", iso_a.get_aqta());

            // 1. SELECT China T-Union Electronic Purse AID: A0 00 00 06 32 01 01 05
            // SELECT APDU: 00 A4 04 00 08 A0 00 00 06 32 01 01 05
            println!("\nSelecting China T-Union Application...");
            let select_aid = [0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x32, 0x01, 0x01, 0x05];
            
            let select_res = match device.pn532().in_data_exchange(1, 0x00, &select_aid).await {
                Ok(res) => res,
                Err(e) => {
                    println!("Failed to select application AID: {:?}", e);
                    break;
                }
            };

            // Checking APDU status (last two bytes of response, ignoring PN532 status in select_res[0])
            if select_res.len() >= 3 {
                let sw1 = select_res[select_res.len() - 2];
                let sw2 = select_res[select_res.len() - 1];
                if sw1 == 0x90 && sw2 == 0x00 {
                    println!("Successfully selected China T-Union App!");
                } else {
                    println!("Error selecting App: Status Words = {:02X} {:02X}", sw1, sw2);
                    println!("This card might not be a China T-Union card.");
                    break;
                }
            } else {
                println!("Select App response too short: {:02X?}", select_res);
                break;
            }

            // 2. READ CARD BASIC INFO: READ BINARY on SFI 0x15 (Public Application Information File)
            // SFI 0x15: READ BINARY APDU is `00 B0 95 00 1E` (reads 30 bytes)
            println!("Reading Card Information (SFI 0x15)...");
            let info_result = {
                let mut pn532 = device.pn532();
                read_card_info_with_retry(&mut pn532).await
            };
            match info_result {
                Ok(info_res) => {
                    if info_res.len() >= 33 {
                        let sw1 = info_res[info_res.len() - 2];
                        let sw2 = info_res[info_res.len() - 1];
                        if sw1 == 0x90 && sw2 == 0x00 {
                            // Bytes 10 to 19 of the 30-byte public info file store the Application Serial Number in BCD/HEX
                            let asn_bytes = &info_res[11..21];
                            let raw_asn_str = asn_bytes.iter().map(|b| format!("{:02X}", b)).collect::<String>();
                            
                            // Typically, a China T-Union card number has 19 digits.
                            // The 10-byte BCD formatted ASN yields 20 digits, often with a leading zero.
                            let card_number = if raw_asn_str.starts_with('0') {
                                &raw_asn_str[1..]
                            } else {
                                &raw_asn_str
                            };
                            
                            // Bytes 21 to 24 store the start date (YYYYMMDD in BCD)
                            let start_date = format!(
                                "{:02X}{:02X}/{:02X}/{:02X}",
                                info_res[21], info_res[22], info_res[23], info_res[24]
                            );
                            
                            // Bytes 25 to 28 store the expiry date (YYYYMMDD in BCD)
                            let expiry_date = format!(
                                "{:02X}{:02X}/{:02X}/{:02X}",
                                info_res[25], info_res[26], info_res[27], info_res[28]
                            );

                            println!("--------------------------------------------------");
                            println!("T-Union Card No : {}", card_number);
                            println!("Validity Period : {} ~ {}", start_date, expiry_date);
                            println!("--------------------------------------------------");
                        } else {
                            println!("Failed to read card info: Status Words = {:02X} {:02X}", sw1, sw2);
                        }
                    } else {
                        println!("Read card info response too short: {:02X?}", info_res);
                    }
                }
                Err(e) => {
                    println!("Failed to communicate for card info: {:?}", e);
                }
            }

            // 3. READ BALANCE: 80 5C 00 02 04
            println!("Reading card balance...");
            let read_bal = [0x5C, 0x00, 0x02, 0x04];
            match device.pn532().in_data_exchange(1, 0x80, &read_bal).await {
                Ok(bal_res) => {
                    if bal_res.len() >= 7 {
                        let sw1 = bal_res[bal_res.len() - 2];
                        let sw2 = bal_res[bal_res.len() - 1];
                        if sw1 == 0x90 && sw2 == 0x00 {
                            // bal_res[0] is PN532 status (0x00).
                            // bal_res[1..5] is the 4-byte balance in cents (big-endian).
                            let balance_cents = ((bal_res[1] as u32) << 24)
                                | ((bal_res[2] as u32) << 16)
                                | ((bal_res[3] as u32) << 8)
                                | (bal_res[4] as u32);
                            let balance_yuan = balance_cents as f64 / 100.0;
                            println!("T-Union Balance  : {:.2} CNY", balance_yuan);
                            println!("--------------------------------------------------");
                        } else {
                            println!("Failed to read balance: Status Words = {:02X} {:02X}", sw1, sw2);
                        }
                    } else {
                        println!("Read balance response too short: {:02X?}", bal_res);
                    }
                }
                Err(e) => {
                    println!("Failed to communicate for balance: {:?}", e);
                }
            }

            // 4. READ TRANSACTION RECORDS: 00 B2 [Rec No] C4 00 (Read from SFI 0x18)
            println!("Reading transaction history (up to 10 records)...");
            println!("==========================================================================================");
            
            for rec_num in 1..=10 {
                let read_record = [0xB2, rec_num, 0xC4, 0x00];
                match device.pn532().in_data_exchange(1, 0x00, &read_record).await {
                    Ok(rec_res) => {
                        if rec_res.len() >= 26 {
                            let sw1 = rec_res[rec_res.len() - 2];
                            let sw2 = rec_res[rec_res.len() - 1];
                            if sw1 == 0x90 && sw2 == 0x00 {
                                // rec_res[0] is PN532 status (0x00)
                                // rec_res[1..rec_res.len()-2] is the record block (at least 23 bytes)
                                let record_data = &rec_res[1..rec_res.len() - 2];
                                let hex_str = record_data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                                
                                let parsed_info = parse_tunion_history(record_data);
                                println!("Record {:02} [Raw: {}]", rec_num, hex_str);
                                println!("          └─► {}", parsed_info);
                            } else {
                                // If status is not 90 00, it means we've reached the end of the history records or they don't exist
                                println!("Record {:02}: Read ended (Status Words = {:02X} {:02X})", rec_num, sw1, sw2);
                                break;
                            }
                        } else {
                            // If response is short, we stop
                            let sw1 = if rec_res.len() >= 2 { rec_res[rec_res.len() - 2] } else { 0 };
                            let sw2 = if rec_res.len() >= 2 { rec_res[rec_res.len() - 1] } else { 0 };
                            println!("Record {:02}: Read ended / file not found (Status Words = {:02X} {:02X})", rec_num, sw1, sw2);
                            break;
                        }
                    }
                    Err(_) => {
                        println!("Record {:02}: Failed to read due to communication error", rec_num);
                        break;
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
            println!("==========================================================================================");
            break;
        }
    }

    Ok(())
}
