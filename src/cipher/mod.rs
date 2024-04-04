macro_rules! create_boxtory {
    ($ex:expr) => {
        Box::new(|| Box::new($ex) as _)
    };
}

macro_rules! algo_list {
    (
        $all:ident,
        $new_all:ident,
        $new_by_name:ident,
        $t:ty,
        $($key:expr => $value:expr,)*
    ) => {
        pub fn $all() -> &'static [&'static str] {
            &[
                $($key,)*
            ]
        }

        pub fn $new_all() -> IndexMap<&'static str, Boxtory<$t>> {
            let mut res: IndexMap<&'static str, Boxtory<$t>> = IndexMap::new();
            $(
                res.insert($key,  Box::new(|| Box::new($value) as _));
            )*
            res
        }

        pub fn $new_by_name(name: &str) -> Option<Boxtory<$t>> {
            match name {
                $($key => Some(Box::new(|| Box::new($value) as _)),)*
                _ => None,
            }

        }
    }
}

pub mod compress;
pub mod crypt;
pub mod hash;
pub mod kex;
pub mod mac;
pub mod sign;

pub trait Factory<T> {
    fn create(&self) -> T;
}

impl<T, F> Factory<T> for F
where
    F: Fn() -> T,
{
    fn create(&self) -> T {
        self()
    }
}

pub type Boxtory<T> = Box<dyn Factory<Box<T>> + Send + Sync>;


trait Backend {
}
