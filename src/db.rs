use mysql::prelude::*;
use mysql::{from_row, OptsBuilder, Pool};

fn establish_connection() -> Pool {
    let database_url = "mysql://root:aqj519@localhost/test";
    let builder = OptsBuilder::new()
        .ip_or_hostname(Some("localhost"))
        .db_name(Some("database_name"))
        .user(Some("username"))
        .pass(Some("password"));
    Pool::new(builder).unwrap()
}