mod db;
mod execute;
mod new;
mod run;
mod user;

use crate::{
    db::init_db,
    execute::execute_handler,
    new::new_handler,
    run::run_handler,
    user::{login_handler, logout_handler, register_handler},
};
use actix_web::{App, HttpResponse, HttpServer, Responder, get, web};
use anyhow::Result;
use bollard::Docker;
use std::{collections::HashMap, sync::Mutex};
use tracing::info;

#[get("/")]
async fn default_handler() -> impl Responder {
    HttpResponse::Ok().body("Welcome to GoKaggle")
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let docker = web::Data::new(Docker::connect_with_local_defaults().unwrap());
    let db = web::Data::new(init_db().await?);
    let user_containers = web::Data::new(Mutex::new(HashMap::<String, String>::new()));
    let docker_timeouts = web::Data::new(Mutex::new(HashMap::<String, u64>::new()));

    info!("Starting server at http://127.0.0.1:8080/");

    HttpServer::new(move || {
        App::new()
            .app_data(docker.clone())
            .app_data(db.clone())
            .app_data(user_containers.clone())
            .app_data(docker_timeouts.clone())
            .service(default_handler)
            .service(register_handler)
            .service(login_handler)
            .service(logout_handler)
            .service(execute_handler)
            .service(new_handler)
            .service(run_handler)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;
    Ok(())
}
