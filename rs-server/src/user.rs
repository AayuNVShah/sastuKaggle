use crate::execute::{CONTAINER_WORKDIR, IMAGE};
use actix_web::{HttpResponse, Responder, post, web};
use bollard::{
    Docker,
    container::{Config, CreateContainerOptions, RemoveContainerOptions},
};
use mongodb::{Client, Collection, bson::doc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Mutex};
use tracing::{error, info};

#[derive(Deserialize, Serialize)]
pub struct UserPayload {
    pub email: String,
    pub password: String,
}

#[post("/register")]
pub async fn register_handler(
    db: web::Data<Client>,
    payload: web::Json<UserPayload>,
) -> impl Responder {
    let email = &payload.email;
    let password = &payload.password;

    if email.is_empty() {
        return HttpResponse::Unauthorized().body("User email missing in the request");
    }

    info!("New register request received from email: {}", email);

    let user_collection: Collection<UserPayload> = db.database("gokaggle").collection("users");

    let filter = doc! {
        "email": email
    };

    match user_collection.find_one(filter).await {
        Ok(Some(_)) => {
            return HttpResponse::Conflict().body("Email is already registered");
        }
        Ok(None) => {}
        Err(err) => {
            error!("Error checking for existing user: {:?}", err);
            return HttpResponse::InternalServerError().body("Error checking for existing user");
        }
    }

    let hashed_password = hash_password(password);

    let new_user = UserPayload {
        email: email.clone(),
        password: hashed_password,
    };

    match user_collection.insert_one(new_user).await {
        Ok(insert_result) => {
            info!(
                "User registered successfully, email: {}, ID: {:?}",
                email, insert_result.inserted_id
            );
            HttpResponse::Created().body(format!(
                "User saved successfully, ID: {:?}",
                insert_result.inserted_id
            ))
        }
        Err(err) => {
            error!("Failed to save user: {:?}", err);
            HttpResponse::InternalServerError().body("Failed to save user")
        }
    }
}

#[post("/login")]
pub async fn login_handler(
    db: web::Data<Client>,
    docker: web::Data<Docker>,
    user_containers: web::Data<Mutex<HashMap<String, String>>>,
    payload: web::Json<UserPayload>,
) -> impl Responder {
    let email = &payload.email;

    if email.is_empty() {
        return HttpResponse::Unauthorized().body("User email missing in the request");
    }

    info!("Login request received for email: {}", email);

    let user_collection: Collection<UserPayload> = db.database("gokaggle").collection("users");

    let filter = doc! { "email": email };

    let user = match user_collection.find_one(filter).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::Unauthorized().body("Invalid email or password");
        }
        Err(err) => {
            error!("Failed to fetch user: {:?}", err);
            return HttpResponse::InternalServerError().body("Failed to fetch user");
        }
    };

    if hash_password(&payload.password) != user.password {
        return HttpResponse::Unauthorized().body("Invalid email or password");
    }

    let mut user_containers_lock = user_containers.lock().unwrap();
    let container_id = if let Some(container_id) = user_containers_lock.get(email) {
        container_id.clone()
    } else {
        let container_name = format!("gokaggle_{}", email);

        let container_config = Config {
            image: Some(IMAGE),
            working_dir: Some(CONTAINER_WORKDIR),
            cmd: Some(vec!["sh", "-c", "while true; do sleep 1; done"]),
            ..Default::default()
        };

        let platform = "linux/amd64".to_string();

        let create_container_options = CreateContainerOptions {
            name: &container_name,
            platform: Some(&platform),
        };

        match docker
            .create_container(Some(create_container_options), container_config)
            .await
        {
            Ok(container) => {
                if let Err(e) = docker.start_container::<String>(&container.id, None).await {
                    error!("Failed to start container: {:?}", e);
                    return HttpResponse::InternalServerError().body("Failed to start container");
                }
                user_containers_lock.insert(email.clone(), container.id.clone());
                container.id
            }
            Err(e) => {
                error!("Failed to create container: {:?}", e);
                return HttpResponse::InternalServerError().body("Failed to create container");
            }
        }
    };

    info!("User logged in successfully: {}", email);

    HttpResponse::Ok().json({
        serde_json::json!({
            "status": "success",
            "message": "Login successful",
            "container_id": container_id
        })
    })
}

#[post("/logout")]
pub async fn logout_handler(
    db: web::Data<Client>,
    docker: web::Data<Docker>,
    user_containers: web::Data<Mutex<HashMap<String, String>>>,
    payload: web::Json<UserPayload>,
) -> impl Responder {
    let email = &payload.email;

    if email.is_empty() {
        return HttpResponse::Unauthorized().body("User email missing in the request");
    }

    info!("Logout request received for email: {}", email);

    let user_collection: Collection<UserPayload> = db.database("gokaggle").collection("users");

    let filter = doc! { "email": email };

    let user = match user_collection.find_one(filter).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::Unauthorized().body("Invalid email or password");
        }
        Err(err) => {
            error!("Failed to fetch user: {:?}", err);
            return HttpResponse::InternalServerError().body("Failed to fetch user");
        }
    };

    if hash_password(&payload.password) != user.password {
        return HttpResponse::Unauthorized().body("Invalid email or password");
    }

    let mut user_containers_lock = user_containers.lock().unwrap();

    if let Some(container_id) = user_containers_lock.remove(email) {
        if let Err(e) = docker
            .remove_container(
                &container_id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
        {
            error!("Failed to remove container: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed to remove container");
        }

        info!("Container removed for user: {}", email);
    } else {
        info!("No container found for user: {}", email);
    }

    HttpResponse::Ok().json({
        serde_json::json!({
            "status": "success",
            "message": "Logout successful"
        })
    })
}

pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}
