use actix_web::{HttpResponse, Responder, post, web};
use anyhow::Result;
use bollard::{
    Docker,
    exec::{CreateExecOptions, StartExecResults},
    image::CreateImageOptions,
};
use futures_util::{TryStreamExt, stream::StreamExt};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::info;

pub const IMAGE: &str = "golang:latest";
pub const CONTAINER_WORKDIR: &str = "/usr/src/app";

#[derive(Deserialize)]
pub struct ExecutionPayload {
    pub email: String,
    pub code: String,
}

#[post("/execute")]
pub async fn execute_handler(
    docker: web::Data<Docker>,
    user_containers: web::Data<Mutex<HashMap<String, String>>>,
    docker_timeouts: web::Data<Mutex<HashMap<String, u64>>>,
    payload: web::Json<ExecutionPayload>,
) -> impl Responder {
    let email = &payload.email;
    let code = &payload.code;

    if email.is_empty() {
        return HttpResponse::Unauthorized().body("User email missing in the request");
    }

    info!("New execution request received from email: {}", email);

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

    let copy_code_command = format!("echo '{}' > {file_path}", code);

    let copy_code_command = vec!["sh", "-c", &copy_code_command];

    if let Err(e) = run_command_in_container(&docker, &container_id, copy_code_command).await {
        return HttpResponse::InternalServerError()
            .body(format!("Failed to copy code to container: {e}"));
    }

    let run_code_command = vec!["go", "run", "main.go"];

    let output = match run_command_in_container(&docker, &container_id, run_code_command).await {
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

pub async fn run_command_in_container(
    docker: &web::Data<Docker>,
    container_id: &str,
    cmd: Vec<&str>,
) -> Result<String, String> {
    let exec = docker
        .create_exec(container_id, CreateExecOptions {
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            cmd: Some(cmd),
            ..Default::default()
        })
        .await
        .map_err(|e| format!("Failed to create exec: {e}"))?;

    if let Ok(StartExecResults::Attached { mut output, .. }) = docker
        .start_exec(&exec.id, None)
        .await
        .map_err(|e| format!("Failed to start exec: {e}"))
    {
        let mut result = String::new();
        while let Some(Ok(msg)) = output.next().await {
            result.push_str(&msg.to_string());
        }
        Ok(result)
    } else {
        Err("Failed to attach output".into())
    }
}
