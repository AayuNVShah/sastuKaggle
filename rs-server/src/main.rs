mod db;
mod execution;
mod newcode;

use crate::{db::init_db, execution::execute, newcode::new_code};
use actix_web::{App, HttpResponse, HttpServer, Responder, get, web};
use anyhow::Result;
use bollard::Docker;
use std::collections::HashMap;
use tracing::info;

#[get("/")]
async fn default() -> impl Responder {
    HttpResponse::Ok().body("Welcome to GoKaggle")
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let docker = web::Data::new(Docker::connect_with_local_defaults().unwrap());
    let db = web::Data::new(init_db().await?);
    let user_containers = web::Data::new(HashMap::<String, String>::new());
    let docker_timeouts = web::Data::new(HashMap::<String, u64>::new());

    info!("Starting server at http://127.0.0.1:8080/");

    HttpServer::new(move || {
        App::new()
            .app_data(docker.clone())
            .app_data(db.clone())
            .app_data(user_containers.clone())
            .app_data(docker_timeouts.clone())
            .service(default)
            .service(execute)
            .service(new_code)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;
    Ok(())
}
