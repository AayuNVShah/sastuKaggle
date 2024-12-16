use crate::user::{UserPayload, hash_password};
use actix_web::{HttpResponse, Responder, post, web};
use futures_util::TryStreamExt;
use mongodb::{Client, Collection, bson::doc};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

#[derive(Deserialize, Serialize)]
pub struct NewCodePayload {
    pub email: String,
    pub filename: String,
    pub code: String,
}

#[post("/simple/new")]
pub async fn new_handler(
    db: web::Data<Client>,
    payload: web::Json<NewCodePayload>,
) -> impl Responder {
    let codes_collection: Collection<NewCodePayload> = db.database("gokaggle").collection("codes");

    let filter = doc! {
        "email": &payload.email,
        "filename": &payload.filename,
    };

    match codes_collection.find_one(filter).await {
        Ok(Some(_)) => {
            return HttpResponse::Conflict()
                .body("File with the same name already exists for this user");
        }
        Ok(None) => {}
        Err(err) => {
            error!("Error checking for existing file: {:?}", err);
            return HttpResponse::InternalServerError().body("Error checking for existing file");
        }
    }

    let doc = NewCodePayload {
        email: payload.email.clone(),
        filename: payload.filename.clone(),
        code: payload.code.clone(),
    };

    match codes_collection.insert_one(doc).await {
        Ok(insert_result) => {
            info!(
                "New code snippet saved, ID: {:?}",
                insert_result.inserted_id
            );
            HttpResponse::Created().body(format!(
                "Code saved successfully, ID: {:?}",
                insert_result.inserted_id
            ))
        }
        Err(err) => {
            error!("Failed to save code snippet: {:?}", err);
            HttpResponse::InternalServerError().body("Failed to save code snippet")
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct GetCodePayload {
    pub email: String,
    pub filename: String,
}

#[post("/simple/get_code")]
pub async fn get_code_handler(
    db: web::Data<Client>,
    payload: web::Json<GetCodePayload>,
) -> impl Responder {
    let codes_collection: Collection<NewCodePayload> = db.database("gokaggle").collection("codes");

    let filter = doc! {
        "email": &payload.email,
        "filename": &payload.filename,
    };

    match codes_collection.find_one(filter).await {
        Ok(Some(result)) => HttpResponse::Ok().json(result),
        Ok(None) => {
            HttpResponse::NotFound().body("No code found for the given email and file name")
        }
        Err(err) => {
            error!("Failed to fetch code: {:?}", err);
            HttpResponse::InternalServerError().body("Failed to fetch code")
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct GetFilesPayload {
    pub email: String,
}

#[post("/simple/get_files")]
pub async fn get_files_handler(
    db: web::Data<Client>,
    payload: web::Json<GetFilesPayload>,
) -> impl Responder {
    let codes_collection: Collection<NewCodePayload> = db.database("gokaggle").collection("codes");

    let filter = doc! {
        "email": &payload.email,
    };

    match codes_collection.find(filter).await {
        Ok(mut cursor) => {
            let mut files = Vec::new();
            while let Ok(Some(result)) = cursor.try_next().await {
                files.push(result);
            }
            HttpResponse::Ok().json(files)
        }
        Err(err) => {
            error!("Failed to fetch files: {:?}", err);
            HttpResponse::InternalServerError().body("Failed to fetch files")
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct UpdateCodePayload {
    pub email: String,
    pub filename: String,
    pub password: String,
    pub new_code: String,
}

#[post("/simple/update_code")]
pub async fn update_code_handler(
    db: web::Data<Client>,
    payload: web::Json<UpdateCodePayload>,
) -> impl Responder {
    let users_collection: Collection<UserPayload> = db.database("gokaggle").collection("users");

    let user_filter = doc! {
        "email": &payload.email,
    };

    match users_collection.find_one(user_filter).await {
        Ok(Some(user)) => {
            let hashed_input_password = hash_password(&payload.password);
            if hashed_input_password != user.password {
                return HttpResponse::Unauthorized().body("Invalid email or password");
            }
        }
        Ok(None) => return HttpResponse::Unauthorized().body("Invalid email or password"),
        Err(err) => {
            error!("Failed to fetch user: {:?}", err);
            return HttpResponse::InternalServerError().body("Failed to fetch user");
        }
    }

    let codes_collection: Collection<NewCodePayload> = db.database("gokaggle").collection("codes");
    let filter = doc! {
        "email": &payload.email,
        "filename": &payload.filename,
    };
    let update = doc! {
        "$set": doc! { "code": &payload.new_code },
    };

    match codes_collection.update_one(filter, update).await {
        Ok(result) if result.matched_count > 0 => HttpResponse::Ok().json(
            serde_json::json!({ "status": "success", "message": "Code updated successfully" }),
        ),
        Ok(_) => HttpResponse::NotFound().body("No code found for the given email and file name"),
        Err(err) => {
            error!("Failed to update code: {:?}", err);
            HttpResponse::InternalServerError().body("Failed to update code")
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct DeleteCodePayload {
    pub email: String,
    pub filename: String,
    pub password: String,
}

#[post("/simple/delete_code")]
pub async fn delete_code_handler(
    db: web::Data<Client>,
    payload: web::Json<DeleteCodePayload>,
) -> impl Responder {
    let database = db.database("gokaggle");
    let users_collection: Collection<UserPayload> = database.collection("users");

    let user_filter = doc! {
        "email": &payload.email,
    };

    match users_collection.find_one(user_filter).await {
        Ok(Some(user)) => {
            let hashed_input_password = hash_password(&payload.password);
            if hashed_input_password != user.password {
                return HttpResponse::Unauthorized().body("Invalid email or password");
            }
        }
        Ok(None) => return HttpResponse::Unauthorized().body("Invalid email or password"),
        Err(err) => {
            error!("Failed to fetch user: {:?}", err);
            return HttpResponse::InternalServerError().body("Failed to fetch user");
        }
    }

    let codes_collection: Collection<NewCodePayload> = database.collection("codes");
    let filter = doc! {
        "email": &payload.email,
        "filename": &payload.filename,
    };

    match codes_collection.delete_one(filter).await {
        Ok(result) if result.deleted_count > 0 => HttpResponse::Ok().json(
            serde_json::json!({ "status": "success", "message": "Code deleted successfully" }),
        ),
        Ok(_) => HttpResponse::NotFound().body("No code found for the given email and file name"),
        Err(err) => {
            error!("Failed to delete code: {:?}", err);
            HttpResponse::InternalServerError().body("Failed to delete code")
        }
    }
}
