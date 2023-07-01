use byteorder::{LittleEndian, WriteBytesExt};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod db;

pub const DPOW_SIGCHANNEL: u32 =
    b's' as u32 | (b'i' as u32) << 8 | (b'g' as u32) << 16 | (b's' as u32) << 24;
pub const DPOW_SIGBTCCHANNEL: u32 = !DPOW_SIGCHANNEL;
pub const DPOW_TXIDCHANNEL: u32 =
    b't' as u32 | (b'x' as u32) << 8 | (b'i' as u32) << 16 | (b'd' as u32) << 24;
pub const DPOW_BTCTXIDCHANNEL: u32 = !DPOW_TXIDCHANNEL;

pub const FIRST_PARTY: [&str; 64] = [
    "blackice_DEV",
    "blackice_AR",
    "blackice_EU",
    "blackice_NA",
    "alien_NA",
    "alien_EU",
    "alien_SH",
    "alienx_NA",
    "alright_EU",
    "alright_DEV",
    "artem.pikulin_AR",
    "batman_AR",
    "blackice2_AR",
    "ca333_EU",
    "caglarkaya_EU",
    "chmex_AR",
    "chmex_EU",
    "chmex_NA",
    "chmex_SH",
    "chmex2_SH",
    "cipi_AR",
    "cipi_EU",
    "cipi_NA",
    "colmapol_EU",
    "computergenie_EU",
    "computergenie_NA",
    "computergenie2_NA",
    "dimxy_AR",
    "dimxy_DEV",
    "emmaccen_DEV",
    "fediakash_AR",
    "gcharang_AR",
    "gcharang_SH",
    "gcharang_DEV",
    "kmdude_SH",
    "marmara_AR",
    "marmara_EU",
    "mcrypt_SH",
    "nodeone_NA",
    "nodeone2_NA",
    "ozkanonur_NA",
    "pbca26_NA",
    "pbca26_SH",
    "phit_SH",
    "ptyx_SH",
    "shamardy_SH",
    "sheeba_SH",
    "sheeba2_SH",
    "smdmitry_AR",
    "smdmitry_EU",
    "smdmitry_SH",
    "smdmitry2_AR",
    "strob_SH",
    "tonyl_AR",
    "tonyl_DEV",
    "van_EU",
    "webworker01_EU",
    "webworker01_NA",
    "who-biz_NA",
    "yurri-khi_DEV",
    "dragonhound_AR",
    "dragonhound_EU",
    "dragonhound_NA",
    "dragonhound_DEV",
];

//https://stackoverflow.com/questions/68583968/how-to-deserialize-a-c-struct-into-a-rust-struct
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[repr(C)]
pub struct IguanaPacketHeader {
    #[serde(with = "BigArray")]
    pub sig: [u8; 64],
    pub packethash: [u8; 32],
    pub nonce: u32,
    pub packetlen: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[repr(C)]
pub struct DpowNanoUtxo {
    pub srcutxo: [u8; 32],
    pub destutxo: [u8; 32],
    pub bestmask: [u8; 8],
    pub recvmask: [u8; 8],
    pub pendingcrc1: u32,
    pub pendingcrc2: u32,
    pub paxwdcrc: u32,
    pub srcvout: u16,
    pub destvout: u16,
    #[serde(with = "BigArray")]
    pub sig1: [u8; 128],
    #[serde(with = "BigArray")]
    pub sig2: [u8; 128],
    pub siglens: [u8; 2],
    pub pad: u8,
    pub bestk: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[repr(C)]
pub struct DpowNanoMsgHdr {
    pub srchash: [u8; 32],
    pub desthash: [u8; 32],
    pub ratify: DpowNanoUtxo,
    pub notarize: DpowNanoUtxo,
    pub channel: u32,
    pub height: u32,
    pub size: u32,
    pub datalen: u32,
    pub crc32: u32,
    pub myipbits: [u8; 4],
    pub numipbits: u32,
    #[serde(with = "BigArray")]
    pub ipbits: [[u8; 4]; 512], // this should be set to 512 for mainnet or 3p networks
    pub symbol: [u8; 16],
    pub senderind: u8,
    pub senderind2: u8,
    pub version1: u8,
}

pub fn now_sec() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

// iguana grinds hashes until it finds one starting with 00
// presumably as a rate limiter
// TODO: this is a direct port of iguana's logic but it could fail gracefully
pub fn packethash_pow(buffer: &Vec<u8>) -> Result<(u32, [u8; 32]), ()> {
    for i in 0..10000 {
        let hash = get_packethash(&buffer, &i, &(buffer.len() as u32)).unwrap();
        if hash[0] == 0 {
            return Ok((i, hash));
        }
    }
    Err(())
}

pub fn get_packethash(buffer: &Vec<u8>, nonce: &u32, packetlen: &u32) -> Result<[u8; 32], ()> {
    let mut preimage: Vec<u8> = Vec::new();
    preimage.write_u32::<LittleEndian>(*nonce).unwrap();
    preimage.write_u32::<LittleEndian>(*packetlen).unwrap();
    preimage.extend(buffer);

    let mut hasher = Sha256::new();
    hasher.update(&preimage);
    let result: [u8; 32] = hasher.finalize().into();

    Ok(result)
}

pub fn validate_packethash(header: &IguanaPacketHeader, buffer: &Vec<u8>) -> Result<(), ()> {
    let result = get_packethash(&buffer, &header.nonce, &header.packetlen).unwrap();

    if result == header.packethash {
        Ok(())
    } else {
        Err(())
    }
}

// validate the signature in the header signed the packethash
// does not validate packethash; must be used in conjunction with validate_packethash
pub fn validate_packet_signature(header: &IguanaPacketHeader) -> Result<PublicKey, ()> {
    let secp = Secp256k1::new();

    // recovery id is always 0 in iguana
    let recovery_id = RecoveryId::from_i32(0).unwrap();
    let recoverable_signature =
        RecoverableSignature::from_compact(&header.sig, recovery_id).unwrap();
    let message = Message::from_slice(&header.packethash).unwrap();

    // Recover the public key
    let public_key = secp
        .recover_ecdsa(&message, &recoverable_signature)
        .unwrap();
    let signature = Signature::from_compact(&header.sig).unwrap();

    secp.verify_ecdsa(&message, &signature, &public_key)
        .unwrap();
    Ok(public_key)
}

pub fn produce_packethash_signature(packethash: [u8; 32], sk: &SecretKey) -> Result<[u8; 64], ()> {
    let secp = Secp256k1::new();
    let message = Message::from_slice(&packethash).unwrap();

    // iguana does sign_ecdsa_recoverable_with_noncedata but this is not neccesary for our purposes
    let signature = secp.sign_ecdsa_recoverable(&message, &sk);

    let (_recovery_id, sig) = signature.serialize_compact();
    Ok(sig)
}
