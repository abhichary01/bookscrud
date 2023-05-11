use actix_web;
use actix_web::{web, App, HttpResponse, HttpServer, Responder, Result};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::DateTime;
use jsonwebtoken::{encode, EncodingKey, Header};
use mysql::{Opts, Pool, Row};
use mysql::chrono::Duration;
use mysql::chrono::Utc;
use mysql::prelude::*;
use mysql::{ Error};
use serde::{Deserialize, Serialize};
use std::env;
use dotenv::dotenv;


#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: Option<i32>,
    first_name: String,
    last_name: String,
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


#[derive(Debug, Serialize, Deserialize)]
struct UserSignin {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Payload {
    sub: String, // Subject
    exp: i64,    // Expiration time
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i32,           // subject (user ID)
    exp: DateTime<Utc>, // expiration time
}

fn establish_connection() -> Result<mysql::Pool, Error> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let opts = Opts::from_url(&database_url)?;
    mysql::Pool::new(opts)
}

fn generate_jwt(user_id: i32) -> String {
    let encoding_key = env::var("JWT_SECRET_KEY").unwrap_or_else(|_| "secret".into());
    let payload = Payload {
        sub: user_id.to_string(),
        exp: (Utc::now() + Duration::days(7)).timestamp(),
    };
    encode(
        &Header::default(),
        &payload,
        &EncodingKey::from_secret(encoding_key.as_bytes()),
    )
    .unwrap()
}

async fn register_user(
    user: web::Json<User>,
    pool: web::Data<mysql::Pool>,
) -> impl Responder {
    println!("cheeeck 01");
    let user = user.into_inner();
    println!("cheeeck 02");
    let hashed_password = hash(&user.password, DEFAULT_COST).unwrap();
    println!("cheeeck 03");
    let query = format!(
        "INSERT INTO users (first_name, last_name, email, username, password) VALUES ('{}', '{}', '{}', '{}', '{}')",
        user.first_name, user.last_name, user.email, user.username, hashed_password
    );
    println!("cheeeck 04");
    let result = pool
        .get_conn()
        .and_then(|mut conn| conn.query_drop(query));
    match result {
        Ok(_) => HttpResponse::Ok().body("User registered successfully"),
        Err(_) => HttpResponse::InternalServerError().body("Error registering user"),
    }
}

async fn sign_in(
    user: web::Json<UserSignin>,
    pool: web::Data<mysql::Pool>,
) -> impl Responder {
    let user = user.into_inner();
    let query = format!(
        "SELECT id, password FROM users WHERE username = '{}'",
        user.username
    );
    let result = pool
        .get_conn()
        .and_then(|mut conn| conn.query_first::<(i32, String), _>(query));
    println!("cheeeck 04 {:?}",result);
    match result {
        Ok(Some((id, hashed_password))) => {
            if verify(&user.password, &hashed_password).unwrap_or(false) {
                let jwt = generate_jwt(id);
                HttpResponse::Ok().body(jwt)
            } else {
                HttpResponse::Unauthorized().body("Invalid username or password")
            }
        }
        Ok(None) => HttpResponse::Unauthorized().body("Invalid username or password"),
        Err(_) => HttpResponse::InternalServerError().body("Error signing in"),
    }
}

async fn create_book(
    book: web::Json<Book>,
    pool: web::Data<mysql::Pool>,
) -> impl Responder {
    let book = book.into_inner();
    let query = format!(
        "INSERT INTO books (title, description, author, cover_image, price) VALUES ('{}', '{}', '{}', '{}', '{}')",
        book.title, book.description, book.author, book.cover_image, book.price
    );
    println!("cheeeck 01 ");
    let result = pool
        .get_conn()
        .and_then(|mut conn| conn.query_drop(query));
    println!("cheeeck 02 {:?}",result);
    match result {
        Ok(_) => HttpResponse::Ok().body("Book created successfully"),
        Err(_) => HttpResponse::InternalServerError().body("Error creating book"),
    }
}

async fn get_all_books(pool: web::Data<Pool>) -> impl Responder {
    let query = "SELECT * FROM books";
    let mut conn = pool.get_conn().expect("couldn't get db connection from pool");
    let books: Vec<Book> = conn.query_map(query, |row: Row| {
        let (id, title, description, author, cover_image, price) =
            mysql::from_row(row);
        Book {
            id,
            title,
            description,
            author,
            cover_image,
            price,
        }
    }).expect("couldn't query database for books");
    HttpResponse::Ok().json(books)
}

async fn get_book_by_id(id: web::Path<i32>, pool: web::Data<Pool>) -> impl Responder {
    let query = "SELECT * FROM books WHERE id = ?";
    let mut conn = pool.get_conn().expect("couldn't get db connection from pool");
    let result = conn.exec_map(query, (id.into_inner(), ), |row: Row| {
        let (id, title, description, author, cover_image, price) =
            mysql::from_row(row);
        Book {
            id,
            title,
            description,
            author,
            cover_image,
            price,
        }
    });
    match result {
        Ok(book) => HttpResponse::Ok().json(book),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}

async fn update_book(
    id: web::Path<i32>,
    book: web::Json<Book>,
    pool: web::Data<mysql::Pool>,
) -> impl Responder {
    let book = book.into_inner();
    let query = format!(
        "UPDATE books SET title = '{}', description = '{}', author = '{}', cover_image = '{}', price = {} WHERE id = {}",
        book.title, book.description, book.author, book.cover_image, book.price, id
    );
    let result = pool
        .get_conn()
        .and_then(|mut conn| conn.query_drop(query));
    match result {
        Ok(_) => HttpResponse::Ok().body("Book updated successfully"),
        Err(_) => HttpResponse::InternalServerError().body("Error updating book"),
    }
}

async fn delete_book(
    id: web::Path<i32>,
    pool: web::Data<mysql::Pool>,
) -> impl Responder {
    let query = format!(
        "DELETE FROM books WHERE id = {}",
        id
    );
    let result = pool
        .get_conn()
        .and_then(|mut conn| conn.query_drop(query));
    match result {
        Ok(_) => HttpResponse::Ok().body("Book deleted successfully"),
        Err(_) => HttpResponse::InternalServerError().body("Error deleting book"),
    }
}

// async fn auth_middleware(req: HttpRequest) -> Result<HttpRequest, HttpResponse> {
//     // Get the token from the request header
//     let auth_header = req.headers().get(header::AUTHORIZATION);
//     let token = match auth_header {
//         Some(header_value) => {
//             let value = header_value.to_str().unwrap_or("").to_owned();
//             let parts: Vec<&str> = value.split(' ').collect();
//             if parts.len() != 2 || parts[0] != "Bearer" {
//                 return Err(HttpResponse::Unauthorized()
//                 .append_header(header::ContentType(mime::APPLICATION_JSON))
//                 .append_header((header::AUTHORIZATION, HeaderValue::from_static("Bearer my_token")))
//                 .finish())
//             }
//             parts[1].to_owned()
//         }
//         None => {
//             return Err(HttpResponse::Unauthorized()
//             .append_header(header::ContentType(mime::APPLICATION_JSON))
//             .append_header((header::AUTHORIZATION, HeaderValue::from_static("Bearer my_token")))
//             .finish())
//         }
//     };

//     // Decode and verify the token
//     let decoding_key = "secret"; // You should replace this with your own secret key
//     let validation = Validation::default();
//     match decode::<Payload>(&token, &DecodingKey::from_secret(decoding_key.as_ref()), &validation) {
//         Ok(_) => Ok(req),
//         Err(_) => Err(HttpResponse::Unauthorized()
//         .append_header(header::ContentType(mime::APPLICATION_JSON))
//         .append_header((header::AUTHORIZATION, HeaderValue::from_static("Bearer my_token")))
//         .finish()),
//     }
// }


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let pool = establish_connection().expect("Failed to create pool");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .route("/register", web::post().to(register_user))
            .route("/login", web::post().to(sign_in))
            .route("/books", web::post().to(create_book))
            .route("/books", web::get().to(get_all_books))
            .route("/books/{id}", web::get().to(get_book_by_id))
            .route("/books/{id}", web::put().to(update_book))
            .route("/books/{id}", web::delete().to(delete_book))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
