use std::env;

pub fn debug<S>(message: S)
where
    S: AsRef<str>,
{
    if env::var("DEBUG_LOG").unwrap_or("0".to_string()) == "1".to_string() {
        log::debug!("{}", message.as_ref());
    }
}
