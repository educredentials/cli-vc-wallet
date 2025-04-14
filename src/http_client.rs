static APP_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
);

pub fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    return reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(APP_USER_AGENT)
            .connection_verbose(true)
            .build();
}

