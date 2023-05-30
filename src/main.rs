use std::io::prelude::*;
use std::path::Path;

use saito_core::core::data::block::{Block, BlockType};
use saito_core::core::data::transaction::{Transaction, TransactionType, TRANSACTION_SIZE};
use std::io::{Error, ErrorKind};
use saito_core::core::data::hop::HOP_SIZE;
use saito_core::core::data::slip::{Slip, SlipType, SLIP_SIZE};

pub const BLOCK_HEADER_SIZE: usize = 245;

//use saito_core::common::defs::SaitoHash;
//use saito_core::common::defs::Timestamp;
use hex::FromHex;
use std::fs;
use std::io::{self, Read};

use log::{debug, error, info, trace, warn};

use saito_core::common::defs::{
    Currency, SaitoHash, SaitoPrivateKey, SaitoPublicKey, SaitoSignature, SaitoUTXOSetKey,
    Timestamp, UtxoSet, GENESIS_PERIOD, MAX_STAKER_RECURSION,
};



fn main() {
    println!("...analyse tx...");
    //analyseTx()
    let path = "1685355604168-51c5ef4f5d5ad7052d7e09e8821f5fb5fd628c9defffc70dccf2a58616563957.sai";
    analyseblock(path.to_string());

    // match analyseblock() {
    //     Ok(_) => println!("Successfully analysed the block."),
    //     Err(e) => eprintln!("An error occurred: {}", e),
    // }

    match readDir() {
        Ok(_) => println!("ok"),
        Err(e) => eprintln!("error {}", e)
    }
}

fn readDir() -> std::io::Result<()> {
    // Specify the directory
    let directory_path = "/Users/ben/projects/saito/blocks";

    for entry in fs::read_dir(directory_path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            // let mut file = fs::File::open(&path)?;

            // let mut buffer = Vec::new();
            // file.read_to_end(&mut buffer)?;            

            // Convert PathBuf to String
            match path.into_os_string().into_string() {
                Ok(path_string) => {
                    
                    analyseblock(path_string);
                }
                Err(_) => println!("Path contains non-unicode characters"),
            }

            //analyseblock(path.to_string());

            // match String::from_utf8(buffer) {
            //     Ok(contents) => println!("Contents:\n{}", contents),
            //     Err(e) => println!("Non-UTF8 file detected: {}", e),
            // }
        }
    }

    Ok(())
}

fn analyseTx() {
    let mut tx = Transaction::default();

    let mut input_slip = Slip::default();
    input_slip.public_key = <SaitoPublicKey>::from_hex(
        "dcf6cceb74717f98c3f7239459bb36fdcd8f350eedbfccfbebf7c0b0161fcd8bcc",
    )
    .unwrap();
    input_slip.amount = 0;
    input_slip.block_id = 0;
    input_slip.tx_ordinal = 0;
    input_slip.amount = 123;

    let mut output_slip = Slip::default();
    output_slip.public_key = <SaitoPublicKey>::from_hex(
            "dcf6cceb74717f98c3f7239459bb36fdcd8f350eedbfccfbebf7c0b0161fcd8bcc",
    )
    .unwrap();    
    output_slip.block_id = 0;
    output_slip.tx_ordinal = 0;

    //tx.add_from_slip(input1);
    //tx.add_to_slip(output1);
    tx.from.push(input_slip);
    tx.to.push(output_slip);
}

fn analyseblock(path: String) -> io::Result<()> {

    
    
    //TODO 
    //instantiate a block
    //write a block to disk
    //read a block to disk
    println!("\n.... analyse a block.....");
    println!("File: {}", path);

    
    let bytes = fs::read(path)?;

    let transactions_len: u32 = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    let id: u64 = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
    let timestamp: Timestamp = Timestamp::from_be_bytes(bytes[12..20].try_into().unwrap());
    pub type Timestamp = u64;
    println!("transactions_len: {}", transactions_len);
    println!("id: {}", id);
    //println!("{}", data[12..16]);
    // for byte in &data[12..20] {
    //     println!("{}", byte);
    // }
    println!("timestamp: {}", timestamp);

    let previous_block_hash: SaitoHash = bytes[20..52].try_into().unwrap();
    let creator: SaitoPublicKey = bytes[52..85].try_into().unwrap();
    let merkle_root: SaitoHash = bytes[85..117].try_into().unwrap();
    let signature: SaitoSignature = bytes[117..181].try_into().unwrap();

    let treasury: Currency = Currency::from_be_bytes(bytes[181..189].try_into().unwrap());
    let staking_treasury: Currency =
        Currency::from_be_bytes(bytes[189..197].try_into().unwrap());

    let burnfee: Currency = Currency::from_be_bytes(bytes[197..205].try_into().unwrap());
    let difficulty: u64 = u64::from_be_bytes(bytes[205..213].try_into().unwrap());

    let avg_income: Currency = Currency::from_be_bytes(bytes[213..221].try_into().unwrap());
    let avg_variance: Currency = Currency::from_be_bytes(bytes[221..229].try_into().unwrap());
    let avg_atr_income: Currency = Currency::from_be_bytes(bytes[229..237].try_into().unwrap());
    let avg_atr_variance: Currency =
        Currency::from_be_bytes(bytes[237..245].try_into().unwrap());

    // let mut s = String::new();
    // for byte in &previous_block_hash {
    //     s.push_str(&format!("{:02x}", byte));
    // }
    // println!("{}", s);
    println!("transactions_len: {}", transactions_len);

    let mut start_of_transaction_data = BLOCK_HEADER_SIZE;

    //let mut transactions = vec![];
    let inputs_len: u32 = u32::from_be_bytes(
        bytes[start_of_transaction_data..start_of_transaction_data + 4]
            .try_into()
            .unwrap(),
    );

    let outputs_len: u32 = u32::from_be_bytes(
        bytes[start_of_transaction_data + 4..start_of_transaction_data + 8]
            .try_into()
            .unwrap(),
    );

    let message_len: usize = u32::from_be_bytes(
        bytes[start_of_transaction_data + 8..start_of_transaction_data + 12]
            .try_into()
            .unwrap(),
    ) as usize;
    let path_len: usize = u32::from_be_bytes(
        bytes[start_of_transaction_data + 12..start_of_transaction_data + 16]
            .try_into()
            .unwrap(),
    ) as usize;

    println!("inputs_len: {}", inputs_len);
    println!("outputs_len: {}", outputs_len);
    
    let mut start_of_transaction_data = BLOCK_HEADER_SIZE;
    println!("start_of_transaction_data: {}", start_of_transaction_data);

    let end_of_transaction_data = start_of_transaction_data
        + TRANSACTION_SIZE
        + ((inputs_len + outputs_len) as usize * SLIP_SIZE)
        + message_len
        + path_len as usize * HOP_SIZE;

    println!("end_of_transaction_data: {}", end_of_transaction_data);
    
    //TODO serialize/deserialize tx

    // let transaction = Transaction::deserialize_from_net(
    //     &bytes[start_of_transaction_data..end_of_transaction_data].to_vec(),
    // )?;

    Ok(())

}

// let mut block = Block::new();
    // block.id = 10;
    // block.timestamp = 1637034582;
    // let hex_string = "bcf6cceb74717f98c3f7239459bb36fdcd8f350eedbfccfbebf7c0b0161fcd8b";

    // let hash = <SaitoHash>::from_hex(hex_string);

    // // block.previous_block_hash = <SaitoHash>::from_hex(
    // //     "bcf6cceb74717f98c3f7239459bb36fdcd8f350eedbfccfbebf7c0b0161fcd8b",
    // // )
    // // .unwrap();
    // // block.merkle_root = <SaitoHash>::from_hex(
    // //     "ccf6cceb74717f98c3f7239459bb36fdcd8f350eedbfccfbebf7c0b0161fcd8b",
    // // )
    // // .unwrap();
    // // block.creator = <SaitoPublicKey>::from_hex(
    // //     "dcf6cceb74717f98c3f7239459bb36fdcd8f350eedbfccfbebf7c0b0161fcd8bcc",
    // // )
    // // .unwrap();
    // //block.signature = <[u8; 64]>::from_hex("c9a6c2d0bf884be6933878577171a3c8094c2bf6e0bc1b4ec3535a4a55224d186d4d891e254736cae6c0d2002c8dfc0ddfc7fcdbe4bc583f96fa5b273b9d63f4").unwrap();
    // block.burnfee = 50000000;
    // block.difficulty = 0;
    // block.treasury = 0;
    // block.staking_treasury = 0;
    

    // println!("id: {}", block.id);
    // println!("timestamp: {}", block.timestamp);
    // println!("hash {:?}", hash);
    
    // let serialized_body = block.serialize_for_signature();
    //println!("{:?}", serialized_body);    

    //println!("{}", std::str::from_utf8(&hash).unwrap());
    
   
    //block.deserialize_from_net(&data);

    //let block2 = Block::deserialize_from_net(data)?;
    //println!("id: {}", block2.id);


//transactions.push(transaction);

    // 
    // for _n in 0..transactions_len {
    //     if bytes.len() < start_of_transaction_data + 16 {
    //         warn!(
    //             "block buffer is invalid to read transaction metadata. length : {:?}",
    //             bytes.len()
    //         );
    //         return Err(Error::from(ErrorKind::InvalidData));
    //     }
    //     let inputs_len: u32 = u32::from_be_bytes(
    //         bytes[start_of_transaction_data..start_of_transaction_data + 4]
    //             .try_into()
    //             .unwrap(),
    //     );
    //     let outputs_len: u32 = u32::from_be_bytes(
    //         bytes[start_of_transaction_data + 4..start_of_transaction_data + 8]
    //             .try_into()
    //             .unwrap(),
    //     );
    //     let message_len: usize = u32::from_be_bytes(
    //         bytes[start_of_transaction_data + 8..start_of_transaction_data + 12]
    //             .try_into()
    //             .unwrap(),
    //     ) as usize;
    //     let path_len: usize = u32::from_be_bytes(
    //         bytes[start_of_transaction_data + 12..start_of_transaction_data + 16]
    //             .try_into()
    //             .unwrap(),
    //     ) as usize;
    //     let end_of_transaction_data = start_of_transaction_data
    //         + TRANSACTION_SIZE
    //         + ((inputs_len + outputs_len) as usize * SLIP_SIZE)
    //         + message_len
    //         + path_len as usize * HOP_SIZE;

    //     if bytes.len() < end_of_transaction_data {
    //         warn!(
    //             "block buffer is invalid to read transaction data. length : {:?}",
    //             bytes.len()
    //         );
    //         return Err(Error::from(ErrorKind::InvalidData));
    //     }
    //     let transaction = Transaction::deserialize_from_net(
    //         &bytes[start_of_transaction_data..end_of_transaction_data].to_vec(),
    //     )?;
    //     transactions.push(transaction);
    //     start_of_transaction_data = end_of_transaction_data;
    // }

    //println!("previous_block_hash: {}", previous_block_hash);
    // println!("creator: {}", creator);
    // println!("merkle_root: {}", merkle_root);
    // println!("signature: {}", signature);

    // if let Ok(s) = std::str::from_utf8(&bytes) {
    //     println!("{}", previous_block_hash);
    // } else {
    //     println!("Data is not valid UTF-8");
    // }
