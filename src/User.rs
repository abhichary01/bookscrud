use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: Option<i32>,
    firstname: String,
    lastname: String,
    email: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Book {
    id: Option<i32>,
    title: String,
    description: String,
    author: String,
    cover_image: String,
    price: f64,
}
