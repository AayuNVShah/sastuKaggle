use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};
use anyhow::Result;
use bollard::{
    Docker,
    container::{Config, CreateContainerOptions},
    exec::{CreateExecOptions, StartExecResults},
    image::CreateImageOptions,
};
use futures_util::{TryStreamExt, stream::StreamExt};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ExecutionPayload {
    username: String,
    timestamp: u64,
    code: String,
}

#[get("/")]
async fn default() -> impl Responder {
    HttpResponse::Ok().body("Welcome to GoKaggle.")
}

#[post("/execute")]
async fn execute(payload: web::Json<ExecutionPayload>) -> impl Responder {
    const IMAGE: &str = "golang:latest";
    const CONTAINER_WORKDIR: &str = "/usr/src/app";

    let docker = Docker::connect_with_local_defaults().unwrap();
    let container_name = format!("gokaggle_{}", payload.timestamp);

    println!(
        "New execution request received from {} on {} with code:\n{}",
        payload.username, payload.timestamp, payload.code
    );

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

    let container_config = Config {
        image: Some(IMAGE),
        working_dir: Some(CONTAINER_WORKDIR),
        host_config: Some(bollard::service::HostConfig {
            auto_remove: Some(true),
            ..Default::default()
        }),
        cmd: Some(vec!["sleep", "10"]),
        ..Default::default()
    };

    let create_container_options = CreateContainerOptions {
        name: container_name,
        platform: Some("linux/amd64".to_string()),
    };

    let container_id = match docker
        .create_container(Some(create_container_options), container_config)
        .await
    {
        Ok(container) => container.id,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to create container: {e}"));
        }
    };

    if let Err(e) = docker.start_container::<String>(&container_id, None).await {
        return HttpResponse::InternalServerError().body(format!("Failed to start container: {e}"));
    }

    let go_file_path = format!("{CONTAINER_WORKDIR}/main.go");

    let copy_command = format!("echo '{}' > {go_file_path}", payload.code);

    let write_command = vec!["sh", "-c", &copy_command];

    if let Err(e) = run_command_in_container(&docker, &container_id, write_command).await {
        return HttpResponse::InternalServerError()
            .body(format!("Failed to write code to container: {e}"));
    }

    let exec_command = vec!["go", "run", "main.go"];
    let output = match run_command_in_container(&docker, &container_id, exec_command).await {
        Ok(output) => output,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to execute code: {e}"));
        }
    };

    HttpResponse::Ok().body(output)
}

async fn run_command_in_container(
    docker: &Docker,
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
        Err("Failed to attach exec output".into())
    }
}

#[actix_web::main]
async fn main() -> Result<()> {
    println!("Starting server at http://127.0.0.1:8080/");
    HttpServer::new(|| App::new().service(default).service(execute))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await?;
    Ok(())
}
