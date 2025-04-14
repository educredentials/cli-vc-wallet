pub fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    return reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connection_verbose(true)
            .build();
}

