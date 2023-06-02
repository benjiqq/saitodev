//https://chat.openai.com/share/46d1ad91-41d7-41a2-8212-2205e6f64939
#![allow(warnings)]
mod analyse;


/////////////
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream, tungstenite::protocol::Message};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use saito_rust::saito::rust_io_handler::RustIOHandler;


use futures::{StreamExt, SinkExt}; // for the 'next' and 'send' functions

//use std::time::Duration;
use std::thread;

use saito_core::common::defs::{
    Currency, SaitoHash, SaitoPrivateKey, SaitoPublicKey, SaitoSignature, SaitoUTXOSetKey,
    Timestamp, UtxoSet, GENESIS_PERIOD, MAX_STAKER_RECURSION,
};

use saito_core::core::data::crypto::generate_keys;
use std::sync::Arc;
use saito_core::core::data::wallet::Wallet;
use tokio::sync::RwLock;
use saito_rust::saito::io_event::IoEvent;
use saito_core::{lock_for_read, lock_for_write};
use saito_core::common::defs::{
    push_lock, LOCK_ORDER_BLOCKCHAIN,
    LOCK_ORDER_CONFIGS, LOCK_ORDER_PEERS, LOCK_ORDER_WALLET,
};

#[tokio::main(flavor = "multi_thread")]
async fn main() {

    //create wallet
    let public_key: SaitoPublicKey =
        hex::decode("03145c7e7644ab277482ba8801a515b8f1b62bcd7e4834a33258f438cd7e223849")
            .unwrap()
            .try_into()
            .unwrap();
    let private_key: SaitoPrivateKey =
        hex::decode("ddb4ba7e5d70c2234f035853902c6bc805cae9163085f2eac5e585e2d6113ccd")
            .unwrap()
            .try_into()
            .unwrap();

    let keys = generate_keys();
    println!("{:?}", keys);
    let wallet = Arc::new(RwLock::new(Wallet::new(keys.1, keys.0)));
    let  channel_size = 1000;
    {
        let mut wallet = wallet.write().await;
        let (sender, _receiver) = tokio::sync::mpsc::channel::<IoEvent>(channel_size);
        Wallet::load(&mut wallet, Box::new(RustIOHandler::new(sender, 1))).await;
    }

    let output_slips_per_input_slip: u8 = 100;
    let unspent_slip_count;
    let available_balance;

    {
        let (wallet, _wallet_) = lock_for_read!(wallet, LOCK_ORDER_WALLET);

        unspent_slip_count = wallet.get_unspent_slip_count();
        available_balance = wallet.get_available_balance();
        println!("available_balance: {}", available_balance);
    }

    // let mut transaction =
    //     Transaction::create(&mut wallet, public_key, payment, fee, false)
    //         .unwrap();
    // transaction.generate_total_fees(0, 0);

    //create slips
    //sign

    // sender
    // .send(IoEvent {
    //     event_processor_id: 0,
    //     event_id: 0,
    //     event: NetworkEvent::OutgoingNetworkMessageForAll {
    //         buffer: Message::Transaction(tx).serialize(),
    //         exceptions: vec![],
    //     },
    // })
    // .await
    // .unwrap();

    //create a transaction

    //analyse from disk doesnt work
    //println!("runAnalyse.....");
    //analyse::runAnalyse();
}

//#[tokio::main]
async fn runConnect() -> Result<(), Box<dyn std::error::Error>> {

    //get blockheight
    
    let url = "ws://127.0.0.1:12101/wsopen"; // replace with your websocket server url
    println!("Connect to {:?}", url);

    // connect to the server
    let (ws_stream, response) = connect_async(url).await.expect("Failed to connect");
    println!("Connected to the server");
    println!("Response HTTP code: {}", response.status());
    println!("Response contains the following headers:");
    for (ref h, _v) in response.headers() {
        println!(">> {}", h);
    }

    // WebSocketStream splits into a sink and a stream
    let (mut write, mut read) = ws_stream.split();

    // Read messages from the server
    // while let Some(message) = read.next().await {
    //     let message = message?;
    //     println!("Received a message: {}", message.to_text()?);
    // }

    // Read messages from the server

    //handle_handshake_challenge

    while let Some(Ok(message)) = read.next().await {
        println!("wait for next message");
        
        match message {
            Message::Text(text) => {
                println!("Received a text message: {}", text);
            },
            Message::Binary(bin) => {
                println!("Received a binary message: {:?}", bin);

                let response = "....nothing";
                let mut response_bytes = response.as_bytes().to_vec(); // convert the string to bytes
                //7 will indicate ping message
                response_bytes[0] = 7;
                println!("{:?}" , response_bytes);
                write.send(Message::Binary(response_bytes)).await.unwrap();

                println!("Sleeping for 1 second...");
                sleep(Duration::from_secs(1)).await;
                println!("Done sleeping!");    
            
                //write.send(Message::Text(response.into())).await?;
            },
            _ => {},
        }
    }

    Ok(())
}

