// SPDX-License-Identifier: Apache-2.0

// Credit to: https://github.com/fortanix/rust-sgx/tree/master/aesm-client
// for examples of AESM Requests.

use crate::protobuf::aesm_proto::{
    Request, Request_GetQuoteExRequest, Request_GetQuoteSizeExRequest, Request_InitQuoteExRequest,
    Request_SelectAttKeyIDRequest, Response, Response_GetQuoteExResponse,
    Response_GetQuoteSizeExResponse, Response_InitQuoteExResponse, Response_SelectAttKeyIDResponse,
};
use crate::syscall::{SGX_DUMMY_QUOTE, SGX_DUMMY_TI, SGX_QUOTE_SIZE, SGX_TI_SIZE};

use std::io::{Error, ErrorKind, Read, Write};
use std::mem::size_of;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::vec::Vec;

use protobuf::Message;
use sgx::attestation_types::report::Report;

const AESM_SOCKET: &str = "/var/run/aesmd/aesm.socket";

const AK_ID_LIST: [u8; 264] = [
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x8c, 0x4f,
    0x57, 0x75, 0xd7, 0x96, 0x50, 0x3e, 0x96, 0x13, 0x7f, 0x77, 0xc6, 0x8a, 0x82, 0x9a, 0x00, 0x56,
    0xac, 0x8d, 0xed, 0x70, 0x14, 0x0b, 0x08, 0x1b, 0x09, 0x44, 0x90, 0xc5, 0x7b, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

pub fn get_algorithm_id(key_id: &Vec<u8>) -> u32 {
    const ALGORITHM_OFFSET: usize = 154;

    let mut bytes: [u8; 4] = Default::default();
    bytes.copy_from_slice(&key_id[ALGORITHM_OFFSET..ALGORITHM_OFFSET + 4]);
    u32::from_le_bytes(bytes)
}

fn get_ak_id(out_buf: &mut [u8]) -> Result<Vec<u8>, Error> {
    // If unable to connect to the AESM daemon, return dummy value
    let mut stream = match UnixStream::connect(AESM_SOCKET) {
        Ok(s) => s,
        Err(_) => {
            out_buf.copy_from_slice(&SGX_DUMMY_TI);
            return Ok(Vec::new());
        }
    };

    // Select an Attestation Key
    let mut req = Request::new();
    let mut msg = Request_SelectAttKeyIDRequest::new();
    msg.set_timeout(1_000_000);
    msg.set_att_key_id_list(AK_ID_LIST.to_vec());
    req.set_selectAttKeyIDReq(msg);

    // Set up Writer
    let mut buf_wrtr = vec![0u8; size_of::<u32>()];
    match req.write_to_writer(&mut buf_wrtr) {
        Ok(_) => {}
        Err(e) => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid Select Att Key ID Request: {:#?}", e),
            ));
        }
    }

    let req_len = (buf_wrtr.len() - size_of::<u32>()) as u32;
    (&mut buf_wrtr[0..size_of::<u32>()]).copy_from_slice(&req_len.to_le_bytes());

    // Send Request to AESM daemon
    stream.write_all(&buf_wrtr)?;
    stream.flush()?;

    // Receive Response
    let mut res_len_bytes = [0u8; 4];
    stream.read_exact(&mut res_len_bytes)?;
    let res_len = u32::from_le_bytes(res_len_bytes);

    let mut res_bytes = vec![0; res_len as usize];
    stream.read_exact(&mut res_bytes)?;

    // Parse Response and extract AttKeyID
    let mut pb_msg: Response = protobuf::parse_from_bytes(&res_bytes)?;
    let mut res: Response_SelectAttKeyIDResponse = pb_msg.take_selectAttKeyIDRes();

    if res.get_errorCode() != 0 {
        panic!(
            "Received error code {:?} in Select Att Key ID Response",
            res.get_errorCode()
        );
    }

    let attkeyid = res.take_selected_att_key_id();

    assert!(attkeyid != &[]);
    eprintln!(
        "Attestation Key ID found successfully: {}",
        get_algorithm_id(&attkeyid)
    );

    Ok(attkeyid)
}

/// Fills the Target Info of the QE into the output buffer specified and
/// returns the number of bytes written.
fn get_ti_pub_key_id_size(out_buf: &mut [u8], akid: Vec<u8>) -> Result<u64, Error> {
    assert_eq!(out_buf.len(), SGX_TI_SIZE, "Invalid size of output buffer");

    // If unable to connect to the AESM daemon, return dummy value
    let mut stream = match UnixStream::connect(AESM_SOCKET) {
        Ok(s) => s,
        Err(_) => {
            out_buf.copy_from_slice(&SGX_DUMMY_TI);
            return Ok(0);
        }
    };

    // Set an Init Quote Ex Request
    let mut req = Request::new();
    let mut msg = Request_InitQuoteExRequest::new();
    msg.set_timeout(1_000_000);
    msg.set_b_pub_key_id(false);
    msg.set_att_key_id(akid);
    req.set_initQuoteExReq(msg);

    // Set up Writer
    let mut buf_wrtr = vec![0u8; size_of::<u32>()];
    match req.write_to_writer(&mut buf_wrtr) {
        Ok(_) => {}
        Err(e) => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid Init Quote Ex Request: {:#?}", e),
            ));
        }
    }

    let req_len = (buf_wrtr.len() - size_of::<u32>()) as u32;
    (&mut buf_wrtr[0..size_of::<u32>()]).copy_from_slice(&req_len.to_le_bytes());

    // Send Request to AESM daemon
    stream.write_all(&buf_wrtr)?;
    stream.flush()?;

    // Receive Response
    let mut res_len_bytes = [0u8; 4];
    stream.read_exact(&mut res_len_bytes)?;
    let res_len = u32::from_le_bytes(res_len_bytes);

    let mut res_bytes = vec![0; res_len as usize];
    stream.read_exact(&mut res_bytes)?;

    // Parse Response and extract TargetInfo
    let mut pb_msg: Response = protobuf::parse_from_bytes(&res_bytes)?;
    let res: Response_InitQuoteExResponse = pb_msg.take_initQuoteExRes();

    if res.get_errorCode() != 0 {
        panic!(
            "Init Quote Ex Reponse has error code: {}",
            res.get_errorCode()
        );
    }

    Ok(res.get_pub_key_id_size())
}

/// Fills the Target Info of the QE into the output buffer specified and
/// returns the number of bytes written.
fn get_ti(out_buf: &mut [u8], akid: Vec<u8>) -> Result<usize, Error> {
    assert_eq!(out_buf.len(), SGX_TI_SIZE, "Invalid size of output buffer");

    let buf_size = get_ti_pub_key_id_size(out_buf, akid.clone())?;

    // If unable to connect to the AESM daemon, return dummy value
    let mut stream = match UnixStream::connect(AESM_SOCKET) {
        Ok(s) => s,
        Err(_) => {
            out_buf.copy_from_slice(&SGX_DUMMY_TI);
            return Ok(SGX_TI_SIZE);
        }
    };

    // Set an Init Quote Ex Request
    let mut req = Request::new();
    let mut msg = Request_InitQuoteExRequest::new();
    msg.set_timeout(1_000_000);
    msg.set_b_pub_key_id(true);
    msg.set_buf_size(buf_size);
    msg.set_att_key_id(akid);
    req.set_initQuoteExReq(msg);

    // Set up Writer
    let mut buf_wrtr = vec![0u8; size_of::<u32>()];
    match req.write_to_writer(&mut buf_wrtr) {
        Ok(_) => {}
        Err(e) => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid Init Quote Ex Request: {:#?}", e),
            ));
        }
    }

    let req_len = (buf_wrtr.len() - size_of::<u32>()) as u32;
    (&mut buf_wrtr[0..size_of::<u32>()]).copy_from_slice(&req_len.to_le_bytes());

    // Send Request to AESM daemon
    stream.write_all(&buf_wrtr)?;
    stream.flush()?;

    // Receive Response
    let mut res_len_bytes = [0u8; 4];
    stream.read_exact(&mut res_len_bytes)?;
    let res_len = u32::from_le_bytes(res_len_bytes);

    let mut res_bytes = vec![0; res_len as usize];
    stream.read_exact(&mut res_bytes)?;

    // Parse Response and extract TargetInfo
    let mut pb_msg: Response = protobuf::parse_from_bytes(&res_bytes)?;
    let res: Response_InitQuoteExResponse = pb_msg.take_initQuoteExRes();

    if res.get_errorCode() != 0 {
        panic!(
            "Init Quote Ex Reponse has error code: {}",
            res.get_errorCode()
        );
    }

    let ti = res.get_target_info();
    eprintln!("ti = {:?}", ti);
    eprintln!("ti.len() = {:?}", ti.len());

    assert_eq!(
        ti.len(),
        out_buf.len(),
        "Unable to copy TargetInfo to buffer"
    );

    out_buf.copy_from_slice(ti);
    eprintln!("TargetInfo obtained and Init succeeded.");
    Ok(ti.len())
}

fn get_quote_size(akid: Vec<u8>) -> Result<usize, std::io::Error> {
    // If unable to connect to the AESM daemon, return dummy value
    let mut stream = match UnixStream::connect(AESM_SOCKET) {
        Ok(s) => s,
        Err(_) => {
            return Ok(7);
        }
    };

    // Set a Get Quote Size Ex Request
    let mut req = Request::new();
    let mut msg = Request_GetQuoteSizeExRequest::new();
    msg.set_att_key_id(akid);
    msg.set_timeout(1_000_000);
    req.set_getQuoteSizeExReq(msg);

    // Set up Writer
    let mut buf_wrtr = vec![0u8; size_of::<u32>()];
    match req.write_to_writer(&mut buf_wrtr) {
        Ok(_) => {}
        Err(e) => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid Get Quote Size Ex Request: {:#?}", e),
            ));
        }
    }

    let req_len = (buf_wrtr.len() - size_of::<u32>()) as u32;
    (&mut buf_wrtr[0..size_of::<u32>()]).copy_from_slice(&req_len.to_le_bytes());

    //    let mut o = [0u8; 512];
    //    get_ti(&mut o, akid.clone());

    // Send Request to AESM daemon
    stream.write_all(&buf_wrtr)?;
    stream.flush()?;

    // Receive Response
    let mut res_len_bytes = [0u8; 4];
    stream.read_exact(&mut res_len_bytes)?;
    let res_len = u32::from_le_bytes(res_len_bytes);

    let mut res_bytes = vec![0; res_len as usize];
    stream.read_exact(&mut res_bytes)?;

    // Parse Response and extract Quote Size
    let mut pb_msg: Response = protobuf::parse_from_bytes(&res_bytes)?;
    let res: Response_GetQuoteSizeExResponse = pb_msg.take_getQuoteSizeExRes();

    if res.get_errorCode() != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "Error found in Quote Size. Error code: {:?}",
                res.get_errorCode()
            ),
        ));
    }

    let size = res.get_quote_size();
    if size == 0 {
        panic!("Could not get quote size");
    }

    eprintln!("Quote size found successfully: {:?}", size);

    Ok(size as usize)
}

/// Fills the Quote obtained from the AESMD for the Report specified into
/// the output buffer specified and returns the number of bytes written.
fn get_quote(
    report: &[u8],
    size: usize,
    akid: Vec<u8>,
    out_buf: &mut [u8],
) -> Result<usize, std::io::Error> {
    assert_eq!(
        out_buf.len(),
        SGX_QUOTE_SIZE,
        "Invalid size of output buffer"
    );

    // If unable to connect to the AESM daemon, return dummy value
    let mut stream = match UnixStream::connect(AESM_SOCKET) {
        Ok(s) => s,
        Err(_) => {
            out_buf.copy_from_slice(&SGX_DUMMY_QUOTE);
            return Ok(SGX_QUOTE_SIZE);
        }
    };

    // Set a Get Quote Request
    let mut req = Request::new();
    let mut msg = Request_GetQuoteExRequest::new();
    msg.set_report(report[0..432].to_vec());
    msg.set_att_key_id(akid);
    msg.set_buf_size(size as u32);
    msg.set_timeout(1_000_000);
    req.set_getQuoteExReq(msg);

    // Set up Writer
    let mut buf_wrtr = vec![0u8; size_of::<u32>()];
    match req.write_to_writer(&mut buf_wrtr) {
        Ok(_) => {}
        Err(e) => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid Get Quote Ex Request: {:#?}", e),
            ));
        }
    }

    let req_len = (buf_wrtr.len() - size_of::<u32>()) as u32;
    (&mut buf_wrtr[0..size_of::<u32>()]).copy_from_slice(&req_len.to_le_bytes());

    // Send Request to AESM daemon
    stream.write_all(&buf_wrtr)?;
    stream.flush()?;

    // Receive Response
    let mut res_len_bytes = [0u8; 4];
    stream.read_exact(&mut res_len_bytes)?;
    let res_len = u32::from_le_bytes(res_len_bytes);

    let mut res_bytes = vec![0; res_len as usize];
    stream.read_exact(&mut res_bytes)?;

    // Parse Response and extract Quote
    let mut pb_msg: Response = protobuf::parse_from_bytes(&res_bytes)?;
    let mut res: Response_GetQuoteExResponse = pb_msg.take_getQuoteExRes();
    if res.get_errorCode() != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "Error found in Quote. Error code: {:?}",
                res.get_errorCode()
            ),
        ));
    }
    let quote = res.take_quote();
    if quote.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Error: No data in Quote",
        ));
    }

    assert_eq!(quote.len(), out_buf.len(), "Unable to copy Quote to buffer");
    out_buf.copy_from_slice(&quote);
    eprintln!("quote len: {:?}", quote.len());
    eprintln!("quote:\n {:?}", quote);

    Ok(quote.len())
}

/// Returns the number of bytes written to the output buffer. Depending on
/// whether the specified nonce is NULL, the output buffer will be filled with the
/// Target Info for the QE, or a Quote verifying a Report.
pub fn get_attestation(
    nonce: usize,
    nonce_len: usize,
    buf: usize,
    buf_len: usize,
) -> Result<usize, Error> {
    static mut ak_id: Option<Vec<u8>> = None;

    let out_buf: &mut [u8] = unsafe { from_raw_parts_mut(buf as *mut u8, buf_len) };

    if nonce == 0 {
        let akid = get_ak_id(out_buf).unwrap();
        assert!(!akid.is_empty());
        eprintln!("nonce=0, akid = {:?}", &akid);
        unsafe {
            ak_id.replace(akid.clone());
        }
        get_ti(out_buf, akid)
    } else {
        let akid = unsafe { ak_id.as_ref().unwrap().clone() };
        assert!(!akid.is_empty());
        eprintln!("akid = {:?}", &akid);
        let size = get_quote_size(akid.clone()).unwrap();
        assert!(size != 0);
        eprintln!("nonce_len = {}", nonce_len);
        let report: &[u8] = unsafe { from_raw_parts(nonce as *const u8, nonce_len) };
        get_quote(report, size, akid.clone(), out_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These values were generated by the QE in its TargetInfo.
    const EXPECTED_MRENCLAVE: [u8; 32] = [
        0xb2, 0xc1, 0xfe, 0x35, 0x7d, 0x7b, 0x10, 0x20, 0x54, 0x4f, 0xac, 0x33, 0x64, 0xc3, 0xf9,
        0xb8, 0x98, 0xc1, 0x75, 0x8d, 0xb4, 0x1, 0x1e, 0x9d, 0x65, 0x2e, 0x40, 0xec, 0xd1, 0x86,
        0x14, 0xbc,
    ];

    const SAMPLE_REPORT: [u8; 512] = [
        3, 9, 255, 255, 2, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 3, 0,
        0, 0, 0, 0, 0, 0, 22, 58, 88, 16, 125, 53, 233, 100, 17, 24, 200, 65, 26, 64, 74, 60, 66,
        222, 31, 118, 51, 69, 13, 209, 195, 223, 173, 140, 243, 230, 253, 139, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 177, 61, 135,
        106, 93, 83, 83, 127, 211, 215, 39, 124, 55, 194, 56, 135, 20, 122, 50, 245, 219, 208, 129,
        97, 51, 211, 47, 101, 75, 245, 153, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 223, 31,
        156, 246, 241, 143, 199, 153, 178, 215, 41, 71, 144, 22, 86, 106, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 50, 201, 146, 54, 60, 3, 200, 185, 0, 187, 66, 32, 117, 71, 150,
        242, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn req_ti() {
        let output = [1u8; SGX_TI_SIZE];
        assert_eq!(
            get_attestation(0, 0, output.as_ptr() as usize, output.len()).unwrap(),
            SGX_TI_SIZE
        );
        assert!(output[0..32].eq(&EXPECTED_MRENCLAVE) || output.eq(&SGX_DUMMY_TI));
    }

    #[test]
    fn req_quote() {
        let output = [1u8; SGX_QUOTE_SIZE];
        assert_eq!(
            get_attestation(
                SAMPLE_REPORT.as_ptr() as usize,
                SAMPLE_REPORT.len(),
                output.as_ptr() as usize,
                output.len()
            )
            .unwrap(),
            SGX_QUOTE_SIZE
        );
    }
}
