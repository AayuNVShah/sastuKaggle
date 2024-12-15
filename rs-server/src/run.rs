use crate::{
    execute::{CONTAINER_WORKDIR, IMAGE, run_command_in_container},
    new::NewCodePayload,
};
use actix_web::{HttpResponse, Responder, post, web};
use bollard::{Docker, image::CreateImageOptions};
use futures_util::TryStreamExt;
use mongodb::{Client, Collection, bson::doc};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{error, info};

#[derive(Deserialize)]
pub struct RunPayload {
    pub email: String,
    pub filename: String,
}

#[post("/run")]
pub async fn run_handler(
    db: web::Data<Client>,
    docker: web::Data<Docker>,
    user_containers: web::Data<Mutex<HashMap<String, String>>>,
    docker_timeouts: web::Data<Mutex<HashMap<String, u64>>>,
    payload: web::Json<RunPayload>,
) -> impl Responder {
    let email = &payload.email;
    let codes_collection: Collection<NewCodePayload> = db.database("gokaggle").collection("codes");

    if email.is_empty() {
        return HttpResponse::Unauthorized().body("User email missing in the request");
    }

    info!("New run request received from email: {}", email);

    if let Err(e) = docker
        .create_image(
            Some(CreateImageOptions {
                from_image: IMAGE,
                ..Default::default()
            }),
            None,
            None,
        )
        .try_collect::<Vec<_>>()
        .await
    {
        return HttpResponse::InternalServerError().body(format!("Failed to pull image: {e}"));
    }

    let filter = doc! {
        "email": &payload.email,
        "filename": &payload.filename,
    };

    match codes_collection.find_one(filter).await {
        Ok(Some(run_payload)) => {
            let container_id = {
                let user_containers = user_containers.lock().unwrap();
                match user_containers.get(email) {
                    Some(container_id) => container_id.clone(),
                    None => {
                        return HttpResponse::InternalServerError()
                            .body("No container initialized for user, try logging in first");
                    }
                }
            };

            let file_path = format!("{CONTAINER_WORKDIR}/main.go");

            let copy_code_command = format!("echo '{}' > {file_path}", run_payload.code);

            let copy_code_command = vec!["sh", "-c", &copy_code_command];

            if let Err(e) =
                run_command_in_container(&docker, &container_id, copy_code_command).await
            {
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to copy code to container: {e}"));
            }

            let run_code_command = vec!["go", "run", "main.go"];

            let output =
                match run_command_in_container(&docker, &container_id, run_code_command).await {
                    Ok(output) => output,
                    Err(e) => {
                        return HttpResponse::InternalServerError()
                            .body(format!("Failed to execute code: {e}"));
                    }
                };

            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Clock may have gone backwards")
                .as_secs();

            {
                let mut docker_timeouts = docker_timeouts.lock().unwrap();
                docker_timeouts.insert(email.clone(), timestamp);
            }

            info!("Container activity updated for user: {}", email);

            HttpResponse::Ok().body(output)
        }
        Ok(None) => {
            HttpResponse::Conflict().body("Code file not found for the given email and file name")
        }
        Err(err) => {
            error!("Error checking for existing file: {:?}", err);
            HttpResponse::InternalServerError().body("Error checking for existing file")
        }
    }
}
