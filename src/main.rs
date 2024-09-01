#[allow(unused_imports)]
use std::net::UdpSocket;

#[derive(Debug, Default)]
enum OpCode {
    #[default]
    /// Query [RFC1035]
    Query,
    /// IQuery (Inverse Query, OBSOLETE) [RFC3425]
    IQuery,
    /// Status [RFC1035]
    Status,
    /// Unassigned
    Unassigned,
    /// Notify [RFC1996]
    Notify,
    /// Update [RFC2136]
    Update,
    /// DNS Stateful Operations (DSO) [RFC8490]
    DSO,
}

impl OpCode {
    fn to_bytes(&self) -> u8 {
        match self {
            OpCode::Query => 0,
            OpCode::IQuery => 1,
            OpCode::Status => 2,
            OpCode::Unassigned => unreachable!(),
            OpCode::Notify => 4,
            OpCode::Update => 5,
            OpCode::DSO => 6,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Default)]
enum RCode {
    #[default]
    /// No Error [RFC1035]
    NoError,
    /// FormErr Format Error [RFC1035]
    FormErr,
    /// ServFail Server Failure [RFC1035]
    ServFail,
    /// NXDomain Non-Existent Domain [RFC1035]
    NXDomain,
    /// NotImp Not Implemented [RFC1035]
    NotImp,
    /// Refused Query Refused [RFC1035]
    Refused,
}

impl RCode {
    fn to_bytes(&self) -> u8 {
        match &self {
            RCode::NoError => 0,
            RCode::FormErr => 1,
            RCode::ServFail => 2,
            RCode::NXDomain => 3,
            RCode::NotImp => 4,
            RCode::Refused => 5,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
struct DNSHeader {
    /// should be random
    packet_id: u16,
    /// true for reply (bit to 1), else false (bit to zero)
    qr: bool,
    /// 4 bits operation code
    opcode: OpCode,
    /// Authrotitative answer
    aa: bool,
    /// Truncation
    tc: bool,
    /// recursion desired
    rd: bool,
    /// recursion available
    ra: bool,
    /// 3 reserved bits
    z: u8,
    /// 4 bits Response code
    rcode: RCode,
    /// Number of questions in the Question section
    qdcount: u16,
    /// Number of records in the Answer section
    ancount: u16,
    /// Number of records in the Authority section
    nscount: u16,
    /// Number of records in the Additional section
    arcount: u16,
}

impl Default for DNSHeader {
    fn default() -> Self {
        Self {
            packet_id: 1234,
            qr: true,
            opcode: OpCode::default(),
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: RCode::default(),
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
}

impl DNSHeader {

    /// Build the DNS header network representation
    fn to_bytes(&self) -> [u8; 12] {
        // rfc 1535, sec 4.1.1
        //                                 1  1  1  1  1  1
        //   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    QDCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ANCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    NSCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ARCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        let mut res = [0_u8; 12];

        // packet_id
        let b = self.packet_id.to_be_bytes();
        res[0] = b[0];
        res[1] = b[1];

        // qr, opcode, aa, tc, rd
        let mut t: u8 = 0;
        if self.qr {
            t += 1 << 7;
        }
        t += self.opcode.to_bytes() << 3;
        if self.aa {
            t += 1 << 2;
        }
        if self.tc {
            t += 1 << 1;
        }
        if self.rd {
            t += 1;
        }
        res[2] = t;

        // ra, z, rcode
        t = self.z << 6;
        if self.ra {
            t += 1 << 7;
        }
        t += self.rcode.to_bytes();
        let b = t.to_be_bytes();
        res[3] = b[0];

        // counts
        let b = self.qdcount.to_be_bytes();
        res[4] = b[0];
        res[5] = b[1];
        let b = self.ancount.to_be_bytes();
        res[6] = b[0];
        res[7] = b[1];
        let b = self.nscount.to_be_bytes();
        res[8] = b[0];
        res[9] = b[1];
        let b = self.arcount.to_be_bytes();
        res[10] = b[0];
        res[11] = b[1];

        res
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let response = DNSHeader::default().to_bytes();
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
