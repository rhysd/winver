use std::cmp::Ordering;
use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct WindowsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
}

impl WindowsVersion {
    pub fn new(major: u32, minor: u32, build: u32) -> Self {
        Self {
            major,
            minor,
            build,
        }
    }
}

impl Ord for WindowsVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.build.cmp(&other.build))
    }
}

impl PartialOrd for WindowsVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for WindowsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let v = WindowsVersion::new(1, 2, 3);
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.build, 3);
    }

    #[test]
    fn test_eq() {
        assert_ne!(WindowsVersion::new(1, 2, 3), WindowsVersion::new(1, 2, 4));
        assert_ne!(WindowsVersion::new(1, 2, 3), WindowsVersion::new(1, 3, 3));
        assert_ne!(WindowsVersion::new(1, 2, 3), WindowsVersion::new(2, 2, 3));
        assert_eq!(WindowsVersion::new(1, 2, 3), WindowsVersion::new(1, 2, 3));
    }

    #[test]
    fn test_ord() {
        assert!(WindowsVersion::new(1, 2, 3) < WindowsVersion::new(1, 2, 4));
        assert!(WindowsVersion::new(1, 2, 3) < WindowsVersion::new(1, 3, 0));
        assert!(WindowsVersion::new(0, 2, 3) < WindowsVersion::new(1, 0, 0));
    }

    #[test]
    fn test_display() {
        let v = WindowsVersion::new(1, 2, 3);
        assert_eq!(&format!("{}", v), "1.2.3");
    }
}
