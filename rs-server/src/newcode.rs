use actix_web::{HttpResponse, Responder, post, web};
use mongodb::{Client, bson::doc};
use serde::Deserialize;
use tracing::{error, info};

#[derive(Deserialize)]
pub struct NewCodePayload {
    email: String,
    filename: String,
    code: String,
}

#[post("/new")]
pub async fn new_code(db: web::Data<Client>, payload: web::Json<NewCodePayload>) -> impl Responder {
    let codes_collection = db.database("gokaggle").collection("codes");

    let doc = doc! {
        "email": &payload.email,
        "filename": &payload.filename,
        "code": &payload.code,
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
