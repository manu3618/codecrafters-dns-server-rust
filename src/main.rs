use std::fmt;
use std::iter;
#[allow(unused_imports)]
use std::net::UdpSocket;
use std::str::FromStr;

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

#[derive(Debug, Default)]
enum RRType {
    #[default]
    /// A 1 a host address
    A,
    /// NS 2 an authoritative name server
    NS,
    /// MD 3 a mail destination (Obsolete - use MX)
    MD,
    /// MF 4 a mail forwarder (Obsolete - use MX)
    MF,
    /// CNAME 5 the canonical name for an alias
    CName,
    /// SOA 6 marks the start of a zone of authority
    SOA,
    /// MB 7 a mailbox domain name (EXPERIMENTAL)
    MB,
    /// MG 8 a mail group member (EXPERIMENTAL)
    MG,
    /// MR 9 a mail rename domain name (EXPERIMENTAL)
    MR,
    /// NULL 10 a null RR (EXPERIMENTAL)
    NULL,
    /// WKS 11 a well known service description
    WKS,
    /// PTR 12 a domain name pointer
    PTR,
    /// HINFO 13 host information
    HInfo,
    /// MINFO 14 mailbox or mail list information
    MInfo,
    /// MX 15 mail exchange
    MX,
    /// TXT 16 text strings
    TXT,
}

impl RRType {
    fn to_bytes(&self) -> [u8; 2] {
        let b: u16 = match self {
            RRType::A => 1,
            RRType::NS => 2,
            RRType::MD => 3,
            RRType::MF => 4,
            RRType::CName => 5,
            RRType::SOA => 6,
            RRType::MB => 7,
            RRType::MG => 8,
            RRType::MR => 9,
            RRType::NULL => 10,
            RRType::WKS => 11,
            RRType::PTR => 12,
            RRType::HInfo => 13,
            RRType::MX => 15,
            RRType::TXT => 16,
            _ => unreachable!(),
        };
        b.to_be_bytes()
    }
}

#[derive(Debug, Default)]
enum Class {
    #[default]
    /// IN 1 the Internet
    IN,
    /// CS 2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS,
    /// CH 3 the CHAOS class
    CH,
    /// HS 4 Hesiod [Dyer 87]
    HS,
}
impl Class {
    fn to_bytes(&self) -> [u8; 2] {
        let b: u16 = match self {
            Class::IN => 1,
            Class::CS => 2,
            Class::CH => 3,
            Class::HS => 4,
            _ => unreachable!(),
        };
        b.to_be_bytes()
    }
}

#[derive(Debug, Default)]
struct Label {
    length: u8,
    value: String,
}

struct LabelParsingError;

impl FromStr for Label {
    type Err = LabelParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('.') || s.len() > 255 {
            Err(LabelParsingError)
        } else {
            Ok(Self {
                length: s.len() as u8,
                value: s.into(),
            })
        }
    }
}

impl Label {
    fn to_bytes(&self) -> Vec<u8> {
        let mut r = Vec::new();
        r.push(self.length);
        r.extend(self.value.as_bytes());
        r
    }
}

#[derive(Debug, Default)]
struct CName(Vec<Label>);

impl FromStr for CName {
    type Err = LabelParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let r: Result<Vec<_>, Self::Err> = s.split('.').map(Label::from_str).collect();
        match r {
            Ok(c) => Ok(Self(c)),
            Err(e) => Err(e),
        }
    }
}

impl fmt::Display for CName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(
            &self
                .0
                .iter()
                .map(|label| label.value.clone())
                .collect::<Vec<_>>()
                .join("."),
        )
    }
}

impl CName {
    fn to_bytes(&self) -> Vec<u8> {
        self.0
            .iter()
            .flat_map(|l| l.to_bytes())
            .chain(iter::once(0))
            .collect()
    }
}

#[derive(Debug, Default)]
struct ResourceRecord {
    cname: CName,
    rrtype: RRType,
    class: Class,
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
