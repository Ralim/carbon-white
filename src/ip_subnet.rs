use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct IPSubnet {
    ip_address: IpAddr,
    mask: u8,
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

impl TryFrom<&str> for IPSubnet {
    type Error = ParseIPSubnetError;

    /// Try and parse given IP's like 192.168.0.0/24 or 192.168.0.10 or FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF/128 etc
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let (ip_str, mask_str) = value
            .split_once('/')
            .or_else(|| {
                if value.contains('.') {
                    Some((value, "32"))
                } else {
                    Some((value, "128"))
                }
            })
            .ok_or(ParseIPSubnetError::InvalidFormat)?;

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
}
