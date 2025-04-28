pub fn header(jwt: &str) -> Result<String, String> {
    let head = jsonwebtoken::decode_header(jwt)
        .map_err(|e| format!("Failed to decode JWT header: {}", e));

    dbg!(&head);
    
    return Ok("".to_string());
}
