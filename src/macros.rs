/// Declares a bitflag set together with its IMAP wire names, so flag parsing and
/// flag rendering cannot drift apart.
#[macro_export]
macro_rules! bitflags_like {
    ($name:ident { $($konst:ident = $value:expr, $wire:literal;)+ }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(pub u32);

        impl $name {
            pub const EMPTY: $name = $name(0);
            $(pub const $konst: $name = $name($value);)+

            pub const ALL: &'static [($name, &'static str)] = &[
                $(($name($value), $wire),)+
            ];

            #[inline]
            pub const fn bits(self) -> u32 {
                self.0
            }

            #[inline]
            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            #[inline]
            pub const fn intersects(self, other: Self) -> bool {
                self.0 & other.0 != 0
            }

            #[inline]
            pub const fn is_empty(self) -> bool {
                self.0 == 0
            }

            #[inline]
            pub fn insert(&mut self, other: Self) {
                self.0 |= other.0;
            }

            #[inline]
            pub fn remove(&mut self, other: Self) {
                self.0 &= !other.0;
            }

            #[inline]
            pub fn toggle(&mut self, other: Self) {
                self.0 ^= other.0;
            }

            #[inline]
            pub fn set(&mut self, other: Self, on: bool) {
                if on { self.insert(other) } else { self.remove(other) }
            }

            pub fn from_wire(s: &str) -> Option<Self> {
                Self::ALL
                    .iter()
                    .find(|(_, w)| w.eq_ignore_ascii_case(s))
                    .map(|(f, _)| *f)
            }

            pub fn parse_list<I, S>(items: I) -> (Self, std::collections::BTreeSet<String>)
            where
                I: IntoIterator<Item = S>,
                S: AsRef<str>,
            {
                let mut flags = Self::EMPTY;
                let mut extra = std::collections::BTreeSet::new();
                for it in items {
                    let s = it.as_ref();
                    match Self::from_wire(s) {
                        Some(f) => flags.insert(f),
                        None => {
                            extra.insert(s.to_string());
                        }
                    }
                }
                (flags, extra)
            }

            pub fn wire_names(self) -> Vec<&'static str> {
                Self::ALL
                    .iter()
                    .filter(|(f, _)| self.contains(*f))
                    .map(|(_, w)| *w)
                    .collect()
            }
        }

        impl std::ops::BitOr for $name {
            type Output = Self;
            #[inline]
            fn bitor(self, rhs: Self) -> Self {
                $name(self.0 | rhs.0)
            }
        }

        impl std::ops::BitOrAssign for $name {
            #[inline]
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }

        impl std::ops::BitAnd for $name {
            type Output = Self;
            #[inline]
            fn bitand(self, rhs: Self) -> Self {
                $name(self.0 & rhs.0)
            }
        }

        impl std::ops::Not for $name {
            type Output = Self;
            #[inline]
            fn not(self) -> Self {
                $name(!self.0)
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_u32(self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Ok($name(u32::deserialize(d)?))
            }
        }
    };
}
