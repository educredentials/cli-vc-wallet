pub fn verify(_credential: &String) -> Result<(), VerificationError> {
    todo!("Verification logic is not implemented yet");
}

#[derive(Debug)]
pub enum VerificationError {
    // InvalidSignature,
    // ExpiredToken,
    // InvalidIssuer,
    // InvalidAudience,
    // InvalidSubject,
    // MissingClaims,
}
