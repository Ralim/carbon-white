use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPSubnet {
    ip_address: IpAddr,
    mask: u8,
}

impl IPSubnet {
    /// The base address of this subnet.
    pub fn ip_address(&self) -> IpAddr {
        self.ip_address
    }

    /// The prefix length of this subnet (0-32 for IPv4, 0-128 for IPv6).
    pub fn prefix_len(&self) -> u8 {
        self.mask
    }

    /// True when this subnet matches every address of its address family (`/0`).
    pub fn is_default_route(&self) -> bool {
        self.mask == 0
    }
}

/// Formats a subnet as `ip/prefix`, omitting the prefix when it is a bare host
/// (`/32` for IPv4, `/128` for IPv6)
impl fmt::Display for IPSubnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let max_mask = match self.ip_address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if self.mask == max_mask {
            write!(f, "{}", self.ip_address)
        } else {
            write!(f, "{}/{}", self.ip_address, self.mask)
        }
    }
}
impl IPSubnet {
    // Test if the given IP address is within this subnet
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.ip_address, ip) {
            (IpAddr::V4(subnet_ip), IpAddr::V4(target_ip)) => {
                let mask_len = self.mask;
                if mask_len == 0 {
                    return true;
                }

                let mask = u32::MAX.checked_shl(32 - mask_len as u32).unwrap_or(0);
                (u32::from(subnet_ip) & mask) == (u32::from(*target_ip) & mask)
            }
            (IpAddr::V6(subnet_ip), IpAddr::V6(target_ip)) => {
                let mask_len = self.mask;
                if mask_len == 0 {
                    return true;
                }

                let mask = u128::MAX.checked_shl(128 - mask_len as u32).unwrap_or(0);
                (u128::from(subnet_ip) & mask) == (u128::from(*target_ip) & mask)
            }
            // Mismatched IP versions (IPv4 vs IPv6)
            _ => false,
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum ParseIPSubnetError {
    InvalidFormat,
    InvalidIp,
    InvalidMask,
}

impl fmt::Display for ParseIPSubnetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidFormat => "invalid subnet format, expected `<ip>` or `<ip>/<prefix>`",
            Self::InvalidIp => "invalid IP address",
            Self::InvalidMask => "invalid prefix length for address family",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for ParseIPSubnetError {}

impl FromStr for IPSubnet {
    type Err = ParseIPSubnetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<&str> for IPSubnet {
    type Error = ParseIPSubnetError;

    /// Try and parse given IP's like 192.168.0.0/24 or 192.168.0.10 or FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF/128 etc
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value.trim();
        if value.is_empty() {
            return Err(ParseIPSubnetError::InvalidFormat);
        }

        let (ip_str, mask_str) = match value.split_once('/') {
            Some((ip, mask)) => (ip, mask),
            None if value.contains('.') => (value, "32"),
            None => (value, "128"),
        };

        let ip_address: IpAddr = ip_str.parse().map_err(|_| ParseIPSubnetError::InvalidIp)?;

        let mask: u8 = mask_str
            .parse()
            .map_err(|_| ParseIPSubnetError::InvalidMask)?;

        // Validate mask limits based on IP version
        let max_mask = match ip_address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if mask > max_mask {
            return Err(ParseIPSubnetError::InvalidMask);
        }

        Ok(IPSubnet { ip_address, mask })
    }
}

#[cfg(test)]
mod test_ip_subnet {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_contains() {
        let subnet = IPSubnet::try_from("192.168.0.0/24").unwrap();
        assert!(subnet.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10))));
        assert!(!subnet.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        assert!(!subnet.contains(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));
        assert!(!subnet.contains(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2))));
    }

    #[test]
    fn test_contains_ipv6() {
        let subnet = IPSubnet::try_from("2001:db8::/32").unwrap();
        assert!(subnet.contains(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))));
        assert!(!subnet.contains(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0))));
    }

    #[test]
    fn test_contains_mask_boundaries() {
        // /0 matches every address of the same family
        let all_v4 = IPSubnet::try_from("0.0.0.0/0").unwrap();
        assert!(all_v4.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(all_v4.is_default_route());

        let all_v6 = IPSubnet::try_from("::/0").unwrap();
        assert!(all_v6.contains(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        assert!(all_v6.is_default_route());

        // /32 is an exact IPv4 match
        let single = IPSubnet::try_from("10.0.0.5/32").unwrap();
        assert!(single.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(!single.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6))));

        // /128 is an exact IPv6 match
        let single_v6 = IPSubnet::try_from("::1/128").unwrap();
        assert!(single_v6.contains(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));
        assert!(!single_v6.contains(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2))));

        // /31 matches both addresses in the pair
        let pair = IPSubnet::try_from("10.0.0.4/31").unwrap();
        assert!(pair.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4))));
        assert!(pair.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(!pair.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6))));
    }

    #[test]
    fn test_parse_defaults_and_trims() {
        // Bare IPv4 defaults to /32
        assert_eq!(IPSubnet::try_from("192.168.1.1").unwrap().prefix_len(), 32);
        // Bare IPv6 defaults to /128
        assert_eq!(IPSubnet::try_from("::1").unwrap().prefix_len(), 128);
        // Surrounding whitespace is tolerated
        assert_eq!(
            IPSubnet::try_from("  192.168.1.1/24  ").unwrap(),
            IPSubnet::try_from("192.168.1.1/24").unwrap()
        );
    }

    #[test]
    fn test_parse_errors() {
        assert_eq!(
            IPSubnet::try_from(""),
            Err(ParseIPSubnetError::InvalidFormat)
        );
        assert_eq!(
            IPSubnet::try_from("   "),
            Err(ParseIPSubnetError::InvalidFormat)
        );
        assert_eq!(
            IPSubnet::try_from("not-an-ip/24"),
            Err(ParseIPSubnetError::InvalidIp)
        );
        assert_eq!(
            IPSubnet::try_from("192.168.1.1/abc"),
            Err(ParseIPSubnetError::InvalidMask)
        );
        // Prefix longer than the address family allows
        assert_eq!(
            IPSubnet::try_from("192.168.1.1/33"),
            Err(ParseIPSubnetError::InvalidMask)
        );
        assert_eq!(
            IPSubnet::try_from("2001:db8::/129"),
            Err(ParseIPSubnetError::InvalidMask)
        );
    }

    #[test]
    fn test_display_round_trip() {
        // Host routes render without a redundant prefix
        assert_eq!(
            IPSubnet::try_from("127.0.0.1").unwrap().to_string(),
            "127.0.0.1"
        );
        assert_eq!(IPSubnet::try_from("::1").unwrap().to_string(), "::1");

        // Subnets keep their prefix and round-trip
        let subnet = IPSubnet::try_from("192.168.0.0/24").unwrap();
        assert_eq!(subnet.to_string(), "192.168.0.0/24");
        assert_eq!(subnet.to_string().parse::<IPSubnet>().unwrap(), subnet);

        assert_eq!(
            IPSubnet::try_from("2001:db8::/32").unwrap().to_string(),
            "2001:db8::/32"
        );
    }

    #[test]
    fn test_accessors() {
        let subnet = IPSubnet::try_from("10.1.2.0/24").unwrap();
        assert_eq!(subnet.ip_address(), IpAddr::V4(Ipv4Addr::new(10, 1, 2, 0)));
        assert_eq!(subnet.prefix_len(), 24);
        assert!(!subnet.is_default_route());
    }
}
