use std::path::Path;

pub fn to_strings<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<Result<String, failure::Error>>, image::ImageError> {
    let img = image::open(path)?;
    let decoder = bardecoder::default_decoder();
    Ok(decoder.decode(&img))
}
